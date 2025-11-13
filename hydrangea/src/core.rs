use crate::aggregator::Aggregator;
use crate::consensus::{ConsensusMessage, ProposalMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{
    Block, FallbackRecoveryProposal, NormalProposal, OptimisticProposal, ProposalType, Timeout,
    Vote, VoteType, QC, TC,
};
use crate::proposer::{ProposalTrigger, ProposerMessage};
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::{BlsSignatureService, Digest, Hash as _};
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::SimpleSender;
use primary::Certificate;
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

/// Implementation of Chained Moonshot per the latest whitepaper spec (22/09/2023).
/// If any of the terms used below are unclear, please refer to the paper. If you
/// are unsure of where to find the latest version of the paper, please contact
/// Isaac Doidge.

pub struct Core {
    aggregator: Aggregator,
    committee: Committee,
    committable_blocks: HashMap<Digest, Round>,
    consensus_only: bool,
    last_commit: Block,
    // a_f
    last_fallback_vote: Round,
    // a_n
    last_normal_vote: Round,
    // a_o
    last_optimistic_vote: Round,
    // d_o
    last_optimistic_vote_digest: Digest,
    // t_l
    last_timeout: Round,
    leader_elector: LeaderElector,
    // qc_l
    locked: QC,
    mempool_driver: MempoolDriver,
    name: PublicKey,
    // Index of uncommitted blocks by round, then by Proposal type.
    // Each round may have at most one Normal or one Fallback Proposal,
    // and up to two Optimistic Proposals.
    pending_proposals: HashMap<Round, HashMap<ProposalType, HashSet<Digest>>>,
    qc_sender: SimpleSender,
    qc_syncs: HashMap<PublicKey, Instant>,
    round: Round,
    rx_proposer: Receiver<ProposalMessage>,
    tx_message: Sender<ConsensusMessage>,
    rx_message: Receiver<ConsensusMessage>,
    rx_synchronizer: Receiver<Block>,
    signature_service: SignatureService,
    bls_signature_service: BlsSignatureService,
    store: Store,
    synchronizer: Synchronizer,
    sync_requests: HashSet<Digest>,
    timeout_delay: u64,
    // E
    timeout_syncs: HashSet<Round>,
    timer: Timer,
    tx_commit: Sender<Vec<Certificate>>,
    tx_output: Sender<Block>,
    tx_proposer: Sender<ProposerMessage>,
    // Index of uncommitted blocks by Digest.
    uncommitted_blocks: HashMap<Digest, Block>,
    uncommitted_qcs: HashMap<Round, QC>,
    vote_sender: SimpleSender,
}

// Identifier of the Genesis round.
const GENESIS: u64 = 0;

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        consensus_only: bool,
        signature_service: SignatureService,
        bls_signature_service: BlsSignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        tx_message: Sender<ConsensusMessage>,
        rx_message: Receiver<ConsensusMessage>,
        rx_proposer: Receiver<ProposalMessage>,
        rx_synchronizer: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Vec<Certificate>>,
        tx_output: Sender<Block>,
    ) {
        tokio::spawn(async move {
            let mut uncommitted_blocks = HashMap::new();
            let mut pending_proposals = HashMap::new();
            let mut uncommitted_qcs = HashMap::new();
            let genesis_block = Block::genesis();
            let genesis_qc = QC::genesis();
            let mut genesis_round_blocks = HashMap::new();
            let mut genesis_round_normal_blocks = HashSet::new();
            let digest = genesis_block.digest();
            genesis_round_normal_blocks.insert(digest.clone());
            genesis_round_blocks.insert(ProposalType::Normal, genesis_round_normal_blocks);
            uncommitted_blocks.insert(digest.clone(), genesis_block.clone());
            pending_proposals.insert(genesis_block.round, genesis_round_blocks);
            uncommitted_qcs.insert(genesis_block.round, genesis_qc.clone());

            Self {
                aggregator: Aggregator::new(committee.clone()),
                committee,
                committable_blocks: HashMap::new(),
                consensus_only,
                last_commit: genesis_block,
                last_fallback_vote: GENESIS,
                last_normal_vote: GENESIS,
                last_optimistic_vote: GENESIS,
                last_optimistic_vote_digest: digest,
                last_timeout: GENESIS,
                leader_elector,
                locked: QC::genesis(),
                mempool_driver,
                name,
                qc_sender: SimpleSender::new(),
                qc_syncs: HashMap::new(),
                round: 1,
                rx_proposer,
                tx_message,
                rx_message,
                rx_synchronizer,
                signature_service,
                bls_signature_service,
                store,
                synchronizer,
                sync_requests: HashSet::new(),
                timeout_delay,
                timeout_syncs: HashSet::new(),
                timer: Timer::new(timeout_delay),
                tx_commit,
                tx_output,
                tx_proposer,
                pending_proposals,
                uncommitted_blocks,
                uncommitted_qcs,
                vote_sender: SimpleSender::new(),
            }
            .run()
            .await
        });
    }

    // Sends the given ConsensusMessage to all but self.
    async fn broadcast(&mut self, m: ConsensusMessage) {
        debug!("Broadcasting {:?}", m);
        let addresses = self.committee.others_consensus_sockets(&self.name);
        let message =
            bincode::serialize(&m).expect(format!("Failed to serialize message {:?}", m).as_str());
        let m_bytes = Bytes::from(message);

        match m {
            ConsensusMessage::QC(_) => self.qc_sender.broadcast(addresses, m_bytes).await,
            ConsensusMessage::Vote(_) => self.vote_sender.broadcast(addresses, m_bytes).await,
            ConsensusMessage::Timeout(_) => self.vote_sender.broadcast(addresses, m_bytes).await,
            _ => (),
        }
    }

    // Unicasts the given ConsensusMessage to the given recipient if recipient is not self.
    async fn send_to(&mut self, m: ConsensusMessage, recipient: &PublicKey) {
        debug!("Unicasting {:?}", m);

        if *recipient != self.name {
            let address = self
                .committee
                .consensus(recipient)
                .expect("Target node is not in the committee")
                .consensus_to_consensus;
            let message = bincode::serialize(&m)
                .expect(format!("Failed to serialize message {:?}", m).as_str());
            let m_bytes = Bytes::from(message);

            match m {
                ConsensusMessage::QC(_) => self.qc_sender.send(address, m_bytes).await,
                ConsensusMessage::Vote(_) => self.vote_sender.send(address, m_bytes).await,
                ConsensusMessage::Timeout(_) => self.vote_sender.send(address, m_bytes).await,
                _ => (),
            }
        }
    }

    async fn get_block(&mut self, digest: Digest, round: Round) -> ConsensusResult<Option<Block>> {
        if round > self.last_commit.round {
            // This function should only ever be called with digests of certified blocks.
            assert!(self.uncommitted_qcs.contains_key(&round));

            let proposer = self.leader_elector.get_leader(round);

            // See if we have the corresponding block.
            if let Some(b) = self.uncommitted_blocks.get(&digest) {
                // Have the block.
                Ok(Some(b.clone()))
            } else {
                debug!("Syncing block for given digest");
                // Missing the block with the given digest.
                let maybe_b = self
                    .synchronizer
                    .get_block(&digest, &proposer, None)
                    .await?;
                // Should not have an uncommitted block on-disk but not in-memory.
                assert!(maybe_b.is_none());
                self.sync_requests.insert(digest);
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn have_all_ancestors(&mut self, block: Block) -> ConsensusResult<bool> {
        if block.round == GENESIS || block.parent == self.last_commit.digest() {
            // Genesis.
            return Ok(true);
        }

        // This function should only ever be called with uncommitted blocks.
        assert!(block.round > self.last_commit.round);
        // This function should only ever be called with blocks that directly
        // satisfy the commit rule (i.e. blocks that are LDC).
        assert!(self.committable_blocks.contains_key(&block.digest()));

        let mut b = block.clone();

        // Trace the chain of ancestors back to our most recently committed block.
        loop {
            let maybe_parent = 
                // Check the in-memory index to avoid IO.
                match self.uncommitted_blocks.get(&b.parent)
                {
                    Some(parent) => Some(parent.clone()),
                    // Ensure we resume processing the given LDC block once we have synchronised
                    // its missing ancestor. This ensures that we will be able to recursively
                    // sync all missing ancestors, even if we do not observe their QCs. It also
                    // ensures that we will commit the LDC block once we have all of its ancestors.
                    None => self.synchronizer.get_block(
                            &b.parent,
                            // We do not know the proposer of b.parent at this stage, so we ask
                            // the proposer of b instead. This node may not have b.parent upon
                            // receiving our request if it proposed b on the basis of a QC or TC,
                            // however, if this is the case then we will eventually contact the
                            // rest of our peers and obtain it from them instead.
                            &b.author,
                            Some(block.clone())
                        ).await?
                };

            if let Some(parent) = maybe_parent {
                if parent.round == self.last_commit.round {
                    // Reached the last committed block.
                    return Ok(true);
                }
                assert!(parent.round > self.last_commit.round);
                b = parent;
            } else {
                debug!("Syncing missing ancestor");
                // Missing an ancestor of the given block. Synchronizer will request it from our peers.
                // Make a note of the requested block so that we can authenticate it when it arrives.
                self.sync_requests.insert(b.parent.clone());
                return Ok(false);
            }
        }
    }

    async fn try_commit_or_sync_ancestor(&mut self, block: &Block) -> ConsensusResult<()> {
        // Should only ever call this function with recent blocks.
        assert!(block.round > self.last_commit.round);

        // Check if we have already marked this block for commit.
        if self.committable_blocks.contains_key(&block.digest()) {
            // Have the QC for this block and its immediate successor by round number.
            if self.have_all_ancestors(block.clone()).await? {
                // This block and all of its uncommitted ancestors are safe to commit.
                debug!("Late commit");
                self.commit(block.clone()).await?;
            }
        }
        // else: Have not yet observed QCs indicating that this block satisfies the
        // commit rule. If we eventually do, then we will commit it at that time.

        Ok(())
    }

    // Unicasts self.locked to the given peer to allow it to enter self.locked.round + 1.
    // Triggered when we see a Timeout from round lower than self.locked.round + 1.
    async fn sync_peer(&mut self, recipient: &PublicKey) {
        // Ensure our network bandwidth cannot be consumed by Byzantine nodes that spam us
        // with Timeouts for old rounds.
        let rate_limited = match self.qc_syncs.get(recipient) {
            // We expect to receive at most one Timeout message per timeout_delay per peer.
            Some(synced_at) => synced_at.elapsed().as_millis() < self.timeout_delay.into(),
            None => false,
        };

        if rate_limited {
            debug!("Rate-limited peer {:?} for QC Sync", recipient);
        } else {
            debug!(
                "Syncing peer {:?} with locked QC {:?}",
                recipient, self.locked
            );
            let address = self
                .committee
                .consensus(recipient)
                .expect("Recipient is not a member of the Validator Committee.")
                .consensus_to_consensus;
            let m = ConsensusMessage::QC(self.locked.clone());
            let message = bincode::serialize(&m)
                .expect(format!("Failed to serialize message {:?}", m).as_str());
            let m_bytes = Bytes::from(message);
            self.qc_sender.send(address, m_bytes).await;
            // Note the time that we served this peer so that we can rate-limit it.
            self.qc_syncs.insert(recipient.clone(), Instant::now());
        }
    }

    fn update_pending_proposals(&mut self, block: &Block, kind: ProposalType) {
        // Should only ever be called with blocks that have already passed can_accept_block.
        if let Some(accepted_for_round) = self.pending_proposals.get_mut(&block.round) {
            if let Some(accepted_for_kind) = accepted_for_round.get_mut(&kind) {
                // Proposal passed validation, so this must be the second and final valid Optimistic Proposal.
                assert!(kind == ProposalType::Optimistic);
                assert!(accepted_for_kind.len() == 1);
                accepted_for_kind.insert(block.digest());
            } else {
                // First proposal of this kind for this round.
                let mut accepted_for_kind = HashSet::new();
                accepted_for_kind.insert(block.digest());
                accepted_for_round.insert(kind, accepted_for_kind);
            }
        } else {
            // First proposal for this round.
            let mut accepted_for_round = HashMap::new();
            let mut accepted_for_kind = HashSet::new();
            accepted_for_kind.insert(block.digest());
            accepted_for_round.insert(kind, accepted_for_kind);
            self.pending_proposals
                .insert(block.round, accepted_for_round);
        }
    }

    async fn store_block(&mut self, block: &Block, kind: ProposalType) {
        // Should only ever call this function with recent blocks.
        assert!(block.round > self.last_commit.round);
        // Store in-memory.
        self.update_pending_proposals(block, kind);
        self.uncommitted_blocks
            .insert(block.digest(), block.clone());

        let _ = self.observe_payload(block).await;
        // Write to disk
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
        debug!("Stored block {:?}", block);
    }

    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        if block.round == GENESIS {
            // Ignore the Genesis block.
            return Ok(());
        }

        assert!(block.round > self.last_commit.round);

        let committing_round = block.round;
        // Stack of blocks to be committed, with the newest block (i.e. the one this function
        // was invoked with) at the base and the oldest ancestor (i.e. the child of the last
        // committed block) at the top.
        let mut to_commit = Vec::new();
        let mut ancestor = block.clone();

        // Identify all uncommitted blocks that can be committed now that
        // their descendent has satisfied the commit rule.
        loop {
            // We should always terminate this loop at our last committed block.
            // If we go back to a lower round then the chain has been compromised.
            let ancestor_parent = ancestor.parent.clone();
            to_commit.push(ancestor);

            if ancestor_parent == self.last_commit.digest() {
                break;
            }
            ancestor = self
                .uncommitted_blocks
                .remove(&ancestor_parent)
                .unwrap_or_else(|| {
                    panic!("Missing ancestor of {:?} detected during commit.", block)
                });

            // We should always terminate this loop at our last committed block.
            // If we encounter another block at the same height as our last commit or
            // skip this height entirely then the chain has been compromised.
            assert!(ancestor.round > self.last_commit.round);
        }

        // Send all the newly committed blocks to the node's application layer.
        while let Some(committing) = to_commit.pop() {
            // This log is required for generating benchmark outputs.
            info!("Committed {:?}", committing);

            if !self.consensus_only {
                let payload = committing.payload.clone();
                // Send the payload to the committer.
                self.tx_commit
                    .send(payload)
                    .await
                    .expect("Failed to send payload");
                //     let payload = committing.payload.clone();

                //     // Output the block to the top-level application.
                //     if let Err(e) = self.tx_output.send(committing).await {
                //         warn!("Failed to send block through the output channel: {}", e);
                //     }

                //     // Clean up the mempool.
                //     // TODO: Ensure that this also cleans up payloads for blocks from
                //     // previous rounds that can never be committed.
                //     self.mempool_driver.cleanup(payload).await;
            }
        }

        // Record the last commit to assist with validation of future blocks.
        self.last_commit = block;
        // Clean up in-memory storage.
        self.committable_blocks.retain(|_, r| *r > committing_round);
        self.pending_proposals.retain(|r, _| *r > committing_round);
        self.uncommitted_blocks
            .retain(|_, b| b.round > committing_round);
        self.uncommitted_qcs
            .retain(|_, qc| qc.round > committing_round);

        // TODO: Remove uncommittable blocks from disk.
        Ok(())
    }

    async fn schedule_commit(&mut self, d: &Digest, r: Round) -> ConsensusResult<()> {
        // Schedule the related block for commit once we have it and all of its ancestors.
        self.committable_blocks.insert(d.clone(), r);

        if let Some(block) = self.uncommitted_blocks.get(&d).cloned() {
            if self.have_all_ancestors(block.clone()).await? {
                debug!("Immediate commit");
                // Have all uncommitted ancestors of this block.
                self.commit(block).await?;
            } else {
                // Will have requested in call to have_all_ancestors.
                debug!(
                    "Missing ancestor for commit-scheduled {:?} for round {}",
                    d, r
                );
            }
        } else {
            // Will have requested in call to get_block.
            debug!("Missing block for commit-scheduled {:?} for round {}", d, r);
        }
        Ok(())
    }

    fn can_vote(&self, b: &Block, t: &ProposalType) -> bool {
        match t {
            ProposalType::Fallback => {
                self.last_fallback_vote < b.round
                    && self.last_normal_vote < b.round
                    && self.last_timeout < b.round
                // TC quorum and block parentage have already been checked.
            }
            ProposalType::Normal => {
                self.last_fallback_vote < b.round
                    && self.last_normal_vote < b.round
                    && (self.last_optimistic_vote < b.round
                        || self.last_optimistic_vote_digest == b.digest())
                    && self.last_timeout < b.round
                // QC quorum and block parentage have already been checked.
            }
            ProposalType::Optimistic => {
                self.last_fallback_vote < b.round
                    && self.last_normal_vote < b.round
                    && self.last_optimistic_vote < b.round
                    && self.locked.hash == b.parent
                    && self.locked.round == b.round - 1
                    && self.last_timeout < b.round - 1
            }
        }
    }

    async fn try_vote_and_optimistically_propose(&mut self) -> ConsensusResult<()> {
        if let Some(accepted) = self.pending_proposals.get(&(self.round)).cloned() {
            // Try to extend and vote for each block that we have accepted for this round.
            // Validation rules ensure that we will extend and vote for at most one Optimistic
            // Proposal and either one Normal Proposal or one Fallback Recovery Proposal per
            // round.
            //
            // If we extend and/or vote for:
            //   - Optimistic & Normal: then both proposals must contain the same block.
            //   - Optimistic & Fallback: then the Optimistic Proposal will fail.
            for (t, proposals) in accepted {
                for digest in proposals {
                    // Block to be extended.
                    let b = self
                        .uncommitted_blocks
                        .get(&digest)
                        .cloned()
                        .expect("Fatal: Block in pending_proposals not in uncommitted_blocks.");

                    if self.round == b.round && self.can_vote(&b, &t) {
                        // Try to propose first, in case our vote triggers a QC and
                        // causes us to advance round.
                        self.propose_optimistic(b.clone()).await;
                        self.send_prepare_vote(&b, &t).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn advance_to_round(&mut self, round: Round) -> ConsensusResult<()> {
        if round > self.round {
            self.cleanup_proposals(round - 1).await;
            // Enter the new round.
            self.round = round;
            // Reset round timer and timeout after \tau.
            self.timer.reset();
            debug!("Moved to round {}", self.round);
            // Try to vote and propose.
            // Covers the case where we receive the proposal for r before the QC for r-1.
            self.try_vote_and_optimistically_propose().await?;
        }
        Ok(())
    }

    async fn send_vote(&mut self, b: Digest, r: Round, t: VoteType) -> ConsensusResult<()> {
        // let start_time = Instant::now();
        let vote = Vote::new(self.name, b, t.clone(), r, &mut self.bls_signature_service).await;
        // let end_time = Instant::now();
        debug!("Created {:?}", vote);
        // let elapsed_time = end_time.duration_since(start_time);
        // info!(
        //     "time taken vote create : {:?} Round :{:?} Votetype: {:?}",
        //     elapsed_time.as_secs_f64() * 1000.0,
        //     r,
        //     t
        // );

        let _ = self.handle_vote(&vote).await;

        self.broadcast(ConsensusMessage::Vote(vote)).await;

        Ok(())
    }

    async fn send_prepare_vote(&mut self, block: &Block, t: &ProposalType) -> ConsensusResult<()> {
        let kind = match t {
            ProposalType::Fallback => {
                self.last_fallback_vote = block.round;
                VoteType::PrepareFallback
            }
            ProposalType::Normal => {
                self.last_normal_vote = block.round;
                VoteType::PrepareNormal
            }
            ProposalType::Optimistic => {
                self.last_optimistic_vote = block.round;
                self.last_optimistic_vote_digest = block.digest();
                VoteType::PrepareOptimistic
            }
        };
        self.send_vote(block.digest(), block.round, kind).await
    }

    async fn send_timeout(&mut self, round: Round) -> ConsensusResult<()> {
        // Avoid spamming Timeouts.
        if !self.timeout_syncs.contains(&round) {
            let timeout = Timeout::new(
                self.locked.clone(),
                round,
                self.name,
                self.signature_service.clone(),
            )
            .await;
            debug!("Created {:?}", timeout);
            self.last_timeout = max(round, self.last_timeout);
            // Ensure that we trigger Timeout Sync for r at most once every timeout_delay.
            self.timeout_syncs.insert(round);
            self.timer.reset();
            self.handle_timeout(&timeout).await?;
            self.broadcast(ConsensusMessage::Timeout(timeout)).await;
        }
        Ok(())
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        // Failed to form a QC this round.
        warn!("Timeout reached for round {}", self.round);
        // Allow Timeout Sync to be triggered (again) for rounds between
        // self.locked.round+1 and self.round.
        self.timeout_syncs.clear();
        self.send_timeout(self.round).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        debug!("Received {:?}", vote);
        if vote.round > self.last_commit.round {
            debug!("Processing {:?}", vote);
            let qc = match vote.kind {
                VoteType::Commit => self.aggregator.add_commit_vote(vote.clone())?,
                VoteType::PrepareNormal => self.aggregator.add_normal_vote(vote.clone())?,
                VoteType::PrepareOptimistic => self.aggregator.add_optimistic_vote(vote.clone())?,
                _ => self.aggregator.add_fallback_vote(vote.clone())?,
            };
            if let Some(qc) = qc {
                debug!("Assembled {:?}", qc);
                self.handle_qc(&qc).await?;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        // The sender claims to be stuck in timeout.round.
        debug!("Processing {:?}", timeout);
        let r = timeout.round;

        if r <= self.locked.round {
            // This helps to compensate for the lack of Eventual Delivery in real networks.
            if timeout.author_is_authorised(&self.committee)? {
                // Send our locked QC to our peer to allow it to enter a new round.
                self.sync_peer(&timeout.author).await;
            }
            // else: Spam message from a node outside the validator set.
        } else {
            // We cannot immediately sync our peer to a higher round.
            if r >= self.round {
                // Attempt to trigger Timeout Sync.
                self.handle_qc(&timeout.high_qc).await?;

                let (votes, maybe_tc) = self.aggregator.add_timeout(timeout.clone())?;
                if votes >= self.committee.validity_threshold() {
                    // Timeout Sync: We have observed at least f+1 (one honest) Timeouts for r.
                    // We also have not triggered this path since the last time our round timer expired.
                    debug!("Attempting Timeout Sync for round {}", r);
                    self.send_timeout(r).await?;

                    if let Some(tc) = maybe_tc {
                        debug!("Assembled {:?}", tc);
                        self.handle_tc(&tc).await?
                    }
                }
            } else {
                // This helps to compensate for the lack of Eventual Delivery in real networks.
                //
                // self.locked.round < r < self.round, so we must have entered self.round via a TC.
                // Therefore, there must be at least f+1 honest that have already sent Timeouts for
                // self.round - 1, so we can respond with this Timeout instead of a Timeout for r.
                //
                // This is Live because:
                //  1. If these f+1 will remain in self.round - 1 or self.round then they will
                //     continue to send these Timeout messages to any validators still in lower
                //     rounds due to timer expiry or this branch, so all will eventually observe
                //     a TC for self.round - 1.
                //  2. If any honest process advances to a higher round then either it must have
                //     locked a QC for a higher round, which all will soon see, or there must be
                //     some higher round for which f+1 honest processes are sending Timeout
                //     messages, which all will soon see and do the same via the branch above.
                //
                // Hence, we need only respond to our peer with a Timeout for self.round - 1.
                self.send_timeout(self.round - 1).await?;
            }
        }
        Ok(())
    }

    async fn propose_if_leader(&mut self, r: Round, trigger: ProposalTrigger) {
        if self.name == self.leader_elector.get_leader(r) {
            self.tx_proposer
                .send(ProposerMessage::Propose(trigger))
                .await
                .expect("Failed to send message to proposer");
        }
    }

    async fn cleanup_proposals(&mut self, r: Round) {
        // Stop trying to deliver proposals for all rounds up to and including this round.
        // Invocation of this function upon entering a new round (i.e. upon QC or TC
        // observation) prevents Byzantine nodes from draining our resources by never
        // ACKing proposals.
        self.tx_proposer
            .send(ProposerMessage::Cleanup(r))
            .await
            .expect("Failed to send message to proposer");
    }

    async fn propose_fallback(&mut self, tc: TC) {
        self.propose_if_leader(tc.round + 1, ProposalTrigger::TC(tc))
            .await
    }

    async fn propose_normal(&mut self, parent_qc: QC) {
        self.propose_if_leader(parent_qc.round + 1, ProposalTrigger::QC(parent_qc))
            .await
    }

    async fn observe_payload(&mut self, block: &Block) -> ConsensusResult<()> {
        self.tx_proposer
            .send(ProposerMessage::Observed(block.payload.clone()))
            .await
            .expect("Failed to send message to proposer");
        Ok(())
    }

    async fn propose_optimistic(&mut self, parent: Block) {
        if self.last_optimistic_vote_digest != parent.digest() {
            // Have not already extended this block. Prevents us from generating duplicate
            // proposals while still allowing us to create multiple Optimistic Proposals
            // if necessary. This improves the responsiveness of recovery to the Optimistic
            // Path after fallback as described below.
            //
            // Scenario:
            //   1. L_r creates O_r whilst in r-1 after voting for B_{r-1}.
            //   2. A quorum of validators vote for the same B_{r-1}, so QC_{r-1} exists.
            //   3. However, it so happens that at least f+1 honest send T_{r-1} before observing
            //     QC_{r-1}.
            //   4. L_r then enters r via TC_{r-1} and creates F_r.
            //   5. L_{r+1} enters r via QC_{r-1}, having not sent T_{r-1}, and votes for and
            //     extends O_r with O_{r+1}.
            //   However, since TC_{r-1} exists we know that the Optimistic Vote Rule will prevent
            //   O_r from becoming certified. Consequently, this O_{r+1} is also guaranteed to
            //   fail. Therefore, to ensure that we resume the Optimistic Path as soon as possible,
            //   L_{r+1} needs to be able to create O_{r+1}' when it subsequently receives and votes
            //   for F_r.
            self.propose_if_leader(parent.round + 1, ProposalTrigger::Block(parent))
                .await
        }
    }

    async fn handle_prepare_qc(&mut self, qc: &QC) -> ConsensusResult<()> {
        if !self.uncommitted_qcs.contains_key(&qc.round) {
            // Ensure QC is valid (has a quorum). This is a relatively expensive check.
            // qc.is_well_formed(&self.committee, &self.sorted_keys, &self.combined_pubkey)?;
            debug!("Processing new QC {:?}", qc);
            self.uncommitted_qcs.insert(qc.round, qc.clone());

            if self.round < qc.round + 1 {
                self.propose_normal(qc.clone()).await;
            }

            if self.locked.round < qc.round {
                debug!("Locked {:?}", qc);
                self.locked = qc.clone();
                // Can now sync peers in lower rounds using this QC, so no need to keep Timeouts.
                self.aggregator.cleanup_timeouts(&self.locked.round);

                if self.last_timeout < qc.round {
                    // Send a Commit Vote.
                    self.send_vote(qc.hash.clone(), qc.round, VoteType::Commit)
                        .await?
                }
            }

            // See if we have the related block and request it from our peers if we do not.
            self.get_block(qc.hash.clone(), qc.round).await?;
            self.broadcast(ConsensusMessage::QC(qc.clone())).await;
            self.advance_to_round(qc.round + 1).await?;
        }
        Ok(())
    }

    async fn handle_commit_qc(&mut self, qc: &QC) -> ConsensusResult<()> {
        if !self.committable_blocks.contains_key(&qc.hash) {
            // Ensure QC is valid (has a quorum). This is a relatively expensive check.
            // qc.is_well_formed(&self.committee, &self.sorted_keys, &self.combined_pubkey)?;
            debug!("Processing new QC {:?}", qc);
            self.schedule_commit(&qc.hash, qc.round).await?;
            self.broadcast(ConsensusMessage::QC(qc.clone())).await;
            self.aggregator.cleanup_prepares(&qc.round);
        }
        // else: Already observed this Commit QC but still syncing ancestors. Ignore.
        Ok(())
    }

    // TODO: Change to return a bool based on whether QC quorum is valid once panics have been removed.
    async fn handle_qc(&mut self, qc: &QC) -> ConsensusResult<()> {
        if qc.round > self.last_commit.round {
            if qc.kind == VoteType::Commit || qc.fast_quorum {
                self.handle_commit_qc(qc).await
            } else {
                self.handle_prepare_qc(qc).await
            }
        } else {
            // Old QC. Ignore.
            Ok(())
        }
    }

    async fn handle_tc(&mut self, tc: &TC) -> ConsensusResult<()> {
        debug!("Received TC {:?}", tc);
        if self.round < tc.round + 1 {
            // Process the high QC in case it is new.
            self.handle_qc(&tc.high_qc).await?;

            // Although the paper has only proposal under this condition, this is only to make
            // the proof reasoning simpler. We need not send Timeout messages for lower rounds
            // than our current round because if we entered this round via a QC then we will
            // use that to sync our peer, or if we entered via a TC instead then there must exist
            // at least f+1 honest Timeout messages for r_c - 1, so all honest will eventually
            // observe TC_{r_c-1} and will enter our current round.
            tc.is_well_formed(&self.committee)?;
            debug!("Processing new TC {:?}", tc);
            self.propose_fallback(tc.clone()).await;
            // Forward TC to next leader.
            let next_leader = self.leader_elector.get_leader(tc.round + 1);
            self.send_to(ConsensusMessage::TC(tc.clone()), &next_leader)
                .await;
            // Make sure we send the corresponding Timeout message so that the adversary
            // cannot prevent us from ever sending it by delivering us this TC before our
            // round timer expires.
            self.send_timeout(tc.round).await?;
            self.advance_to_round(tc.round + 1).await?;
        }
        Ok(())
    }

    fn is_non_equivocal_and_certifiable(&self, block: &Block, kind: ProposalType) -> bool {
        if let Some(accepted) = self.pending_proposals.get(&block.round) {
            let no_fallback = !accepted.contains_key(&ProposalType::Fallback);

            match kind {
                ProposalType::Fallback | ProposalType::Normal =>
                // Only accept one Normal Proposal or one Fallback Proposal per round.
                // Leader is equivocating otherwise.
                {
                    no_fallback && !accepted.contains_key(&ProposalType::Normal)
                }
                ProposalType::Optimistic => {
                    // Ignore if already accepted a Fallback Proposal, since its existence
                    // implies that this Optimistic Proposal cannot become certified.
                    if let Some(accepted_optimistic) = accepted.get(&ProposalType::Optimistic) {
                        // Honest leaders will only ever create at most two Optimistic Proposals per round.
                        no_fallback && accepted_optimistic.len() < 2
                    } else {
                        no_fallback
                    }
                }
            }
        } else {
            true
        }
    }

    async fn can_accept_block(
        &mut self,
        block: &Block,
        kind: ProposalType,
    ) -> ConsensusResult<bool> {
        let digest = block.digest();

        if block.round <= self.last_commit.round {
            // Old block.
            return Ok(false);
        }

        if self.sync_requests.remove(&digest) {
            // Was waiting to sync this block so have already received a QC for it.
            return Ok(true);
        }

        if let Some(qc) = self.uncommitted_qcs.get(&block.round) {
            // Have a QC for this round and are not trying to sync this block, so
            // either the QC if for this block and we already have it, or another
            // block was certified for this round instead. Either way, no need to
            // keep processing.
            assert!(
                qc.hash != block.digest() || self.uncommitted_blocks.contains_key(&block.digest())
            );
            return Ok(false);
        }

        // Ensure that the block proposer is the leader of block.round.
        // TODO: This should yield an error log, not panic.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // TODO: REVIEW THIS. Should actually return false if verify fails because it means
        // that we are missing a batch. However, don't actually need Narwhal at all for the PoC,
        // so could just remove all non-consensus-only features.
        if !self.consensus_only {
            // Check that the payload certificates are valid.
            // self.mempool_driver.verify(block).await?;
        }

        // Block has a valid payload.
        Ok(self.is_non_equivocal_and_certifiable(block, kind))
    }

    async fn process_block(&mut self, block: &Block, kind: ProposalType) -> ConsensusResult<()> {
        debug!("Received Block {:?}", block);

        if self.can_accept_block(block, kind.clone()).await? {
            self.store_block(block, kind).await;
            self.try_commit_or_sync_ancestor(block).await?;
            self.try_vote_and_optimistically_propose().await?;
        }
        Ok(())
    }

    async fn process_optimistic_proposal(&mut self, p: OptimisticProposal) -> ConsensusResult<()> {
        debug!("Received Optimistic Proposal {:?}", p);
        // Ensure:
        //   1. Proposer has voting rights.
        //   2. Block is signed by the proposer.
        p.is_well_formed(&self.committee)?;
        self.process_block(&p.block, ProposalType::Optimistic).await
    }

    async fn process_normal_proposal(&mut self, p: NormalProposal) -> ConsensusResult<()> {
        debug!("Received Normal Proposal {:?}", p);
        // Ensure embedded QC is valid. TODO: Remove panics.
        self.handle_qc(&p.qc).await?;
        // Ensure:
        //   1. Proposer has voting rights.
        //   2. Proposal includes a QC p.block.round - 1 and this QC certifies block.parent.
        //   3. Block is signed by the proposer.
        p.is_well_formed(&self.committee)?;
        self.process_block(&p.block, ProposalType::Normal).await
    }

    async fn process_fallback_recovery_proposal(
        &mut self,
        p: FallbackRecoveryProposal,
    ) -> ConsensusResult<()> {
        debug!("Received Fallback Recovery Proposal {:?}", p);
        // Ensure embedded TC is valid. TODO: Remove panics.
        self.handle_tc(&p.tc).await?;
        // Ensure:
        //   1. Proposer has voting rights.
        //   2. Block is signed by the proposer.
        //   3. Proposal includes a TC for p.block.round - 1.
        //   4. The parent of the included block is the block certified by
        //      the QC with the highest round included in the included TC.
        p.is_well_formed(&self.committee)?;
        self.process_block(&p.block, ProposalType::Fallback).await
    }

    async fn handle_proposal(&mut self, proposal: ProposalMessage) -> ConsensusResult<()> {
        match proposal {
            ProposalMessage::F(f) => self.process_fallback_recovery_proposal(f).await,
            ProposalMessage::N(n) => self.process_normal_proposal(n).await,
            ProposalMessage::O(o) => self.process_optimistic_proposal(o).await,
        }
    }

    async fn handle_sync_response(&mut self, block: Block) -> ConsensusResult<()> {
        debug!(
            "Received SyncResponse from peer containing block {:?}",
            block
        );
        let digest = block.digest();
        // Ensure that we were waiting for this block and have not already received
        // it via another channel (e.g. a late Proposal).
        if self.sync_requests.remove(&digest) && block.round > self.last_commit.round {
            // Store the block.
            //
            // If we requested this block via have_all_ancestors then this will trigger the
            // Synchronizer to send the latest LDC descendent of this block to us again via
            // the loopback channel so we can resume searching for missing ancestors.
            //
            // If we requested this block via get_block then we will start recursively syncing
            // ancestors if it is LDC. If this block (B) is LDC but we are already in the process
            // or syncing the ancestors of a higher LDC block (B'), then we will replace B with
            // B' as the block to yield upon receiving any subsequently-requested missing ancestor
            // (B_a) when the Synchronizer sends B' to us via loopback, which will trigger a
            // second SyncRequest for B_a (unless we get B_a before making this second request,
            // which should not happen when network latency is non-trivial).
            self.store_block(&block, ProposalType::Normal).await;
            self.try_commit_or_sync_ancestor(&block).await?;
        }
        Ok(())
    }

    async fn handle_synchronizer_loopback(&mut self, block: Block) -> ConsensusResult<()> {
        debug!(
            "Reprocessing of block {:?} triggered by Synchronizer",
            block
        );
        // The Synchronizer will only ever send us certified blocks that satisfy the commit
        // rule (i.e. blocks that are LDC) because we only ever request a loopback when we
        // are syncing blocks as a part of have_all_ancestors, which we only ever call with
        // LDC blocks. We will have already stored this block when we first received it.
        // We now re-process it to check if the chain of ancestors in now complete, as
        // long as we have not already committed it.
        if block.round > self.last_commit.round {
            self.try_commit_or_sync_ancestor(&block).await?;
        }
        Ok(())
    }

    fn sanitize_certificate(&mut self, qc: &QC) -> ConsensusResult<()> {
        if qc.round > self.last_commit.round {
            match qc.kind {
                VoteType::Commit => {
                    if !self.committable_blocks.contains_key(&qc.hash) {
                        qc.is_well_formed(&self.committee)?;
                    }
                }
                _ => {
                    if !self.uncommitted_qcs.contains_key(&qc.round) {
                        qc.is_well_formed(&self.committee)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        self.propose_normal(QC::genesis()).await;

        // This is the main loop: it processes incoming blocks, votes and QCs,
        // and receives timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() =>
                match message {
                    ConsensusMessage::Propose(proposal) => self.handle_proposal(proposal).await,
                    ConsensusMessage::QC(qc) => {
                        match self.sanitize_certificate(&qc){
                            Ok(()) => self.handle_qc(&qc).await,
                            error => error
                        }
                    },
                    ConsensusMessage::SyncResponse(block) => self.handle_sync_response(block).await,
                    ConsensusMessage::TC(timeout) => self.handle_tc(&timeout).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                    _ => panic!("Unexpected protocol message")
                },
                Some(proposal) = self.rx_proposer.recv() => self.handle_proposal(proposal).await,
                Some(block) = self.rx_synchronizer.recv() =>
                    self.handle_synchronizer_loopback(block).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
