use crate::consensus::{ConsensusMessage, ProposalMessage, Round};
use crate::messages::{Block, FallbackRecoveryProposal, NormalProposal, QC, TC};
use bytes::Bytes;
use config::Committee;
use crypto::{PublicKey, SignatureService};
use log::{debug, info};
use network::{CancelHandler, ReliableSender};
use primary::Certificate;
use std::collections::HashMap;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[derive(Debug, Clone)]
pub enum ProposalTrigger {
    QC(QC),
    TC(TC),
}

#[derive(Debug)]
pub enum ProposerMessage {
    Propose(ProposalTrigger),
    Cleanup(Round),
    Observed(Vec<Certificate>),
}

pub struct Proposer {
    name: PublicKey,
    consensus_only: bool,
    committee: Committee,
    in_progress: HashMap<Round, Vec<CancelHandler>>,
    last_proposed: Block,
    max_block_delay: u64,
    max_block_size: usize,
    rx_mempool: Receiver<Certificate>,
    rx_message: Receiver<ProposerMessage>,
    signature_service: SignatureService,
    tx_proposer_core: Sender<ProposalMessage>,
    network: ReliableSender,
    proposal_request: Option<ProposalTrigger>,
    buffer: Vec<Certificate>,
    last_proposal_time: Instant,
    client_rate: u32,
    first: bool,
}

impl Proposer {
    pub fn spawn(
        name: PublicKey,
        consensus_only: bool,
        committee: Committee,
        max_block_size: usize,
        signature_service: SignatureService,
        rx_mempool: Receiver<Certificate>,
        rx_message: Receiver<ProposerMessage>,
        tx_proposer_core: Sender<ProposalMessage>,
        client_rate: u32,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                consensus_only,
                committee,
                in_progress: HashMap::new(),
                last_proposed: Block::genesis(),
                signature_service,
                max_block_delay: 2_000,
                max_block_size,
                rx_mempool,
                rx_message,
                tx_proposer_core,
                network: ReliableSender::new(),
                proposal_request: None,
                buffer: Vec::new(),
                last_proposal_time: Instant::now(),
                client_rate,
                first: true,
            }
            .run()
            .await;
        });
    }

    // TODO: This function simulates payload creation. An actual payload manager will need to
    // have logic for identifying "pending" txs in order to prevent duplicates and/or lost txs.
    // Such pending txs should be those included in blocks that have been proposed/voted on
    // but have not yet satisfied the commit rule. Txs should only be removed from the Proposer
    // once they have been committed.
    fn get_payload(&mut self) -> Vec<u8> {
        // if self.consensus_only {
        let mut payload = Vec::new();
        let mut num_txns: usize;
        if self.first {
            num_txns = 1;
            self.first = false;
        } else {
            let duration = self.last_proposal_time.elapsed().as_millis();
            num_txns = (duration * self.client_rate as u128 / 1000) as usize;
            info!("NumTxns {:?} {:?}", num_txns, duration);
        }
        let payload_size = ((512 * num_txns * 3) as f32 / self.committee.size() as f32) as usize;
        payload = vec![0u8; payload_size];

        // for _ in 0..self.num_txns {
        //     // TODO: Payloads for all PoC blocks are the same, but when it is possible
        //     // for them to differ then it is necessary for the Proposer to ensure that
        //     // it reproposes the same block
        //     payload.push(Certificate::default());
        // }

        payload
        // } else {
        //     if self.buffer.len() < self.max_block_size {
        //         self.buffer.drain(..).collect()
        //     } else {
        //         self.buffer.drain(0..self.max_block_size).collect()
        //     }
        // }
    }

    async fn send_proposal(&mut self, proposal: ProposalMessage) {
        info!("Proposing {:?}", proposal);
        let (names, addresses): (Vec<_>, _) = self
            .committee
            .others_consensus(&self.name)
            .into_iter()
            .map(|(name, x)| (name, x.consensus_to_consensus))
            .unzip();

        debug!(
            "Sending to {:?} {:?}. Self is: {}",
            names, addresses, self.name
        );

        let message = bincode::serialize(&ConsensusMessage::Propose(proposal))
            .expect("Failed to serialize block");
        debug!("Size is {}B", message.len());

        // References to the connections that we are continuously trying to deliver
        // this proposal on. We keep them around to ensure that we keep sending until:
        //   1. we deliver it (indicated by an ACK from the recipient), or;
        //   2. we observe either a QC for it (indicating our job is done), or;
        //   3. we observe a TC for the round (indicating the network is asynchronous), or;
        //   4. we replace it with another proposal for this round (only occurs if Optimistic).
        let handles = self
            .network
            .broadcast(addresses, Bytes::from(message))
            .await;
        self.in_progress.insert(self.last_proposed.round, handles);
    }

    fn record_proposal(&mut self, b: Block) {
        info!("Created Round {:?}", b.round + 1);
        self.last_proposed = b;
    }

    async fn make_fallback_proposal(&mut self, tc: TC) -> ProposalMessage {
        let r = tc.round + 1;
        let b = Block::new(
            self.name,
            tc.high_qc.blk_hash.clone(),
            self.get_payload(),
            r,
            self.signature_service.clone(),
        )
        .await;
        self.record_proposal(b.clone());
        ProposalMessage::F(FallbackRecoveryProposal::new(b, tc))
    }

    async fn make_normal_proposal(&mut self, parent_qc: QC) -> ProposalMessage {
        let r = parent_qc.round + 1;
        let b = Block::new(
            self.name,
            parent_qc.blk_hash.clone(),
            self.get_payload(),
            r,
            self.signature_service.clone(),
        )
        .await;
        self.record_proposal(b.clone());
        ProposalMessage::N(NormalProposal::new(b, parent_qc))
    }

    async fn propose(&mut self, trigger: ProposalTrigger) {
        // Generate a new Proposal.
        let proposal = match trigger {
            ProposalTrigger::QC(parent_qc) => self.make_normal_proposal(parent_qc).await,
            ProposalTrigger::TC(tc) => self.make_fallback_proposal(tc).await,
        };

        self.last_proposal_time = Instant::now();

        // Send the Proposal to the Core for local processing.
        self.tx_proposer_core
            .send(proposal.clone())
            .await
            .expect("Failed to send block");
        // Broadcast the Proposal.
        self.send_proposal(proposal).await;
    }

    fn cleanup(&mut self, r: Round) {
        // Core sent a Cleanup request after we transitioned to a new round.
        // Stop trying to deliver proposals for previous rounds. Ensures
        // we are able to use the resend loop to reliably deliver our proposals
        // to honest validators while preventing Byzantine validators from arbitrarily
        // consuming our bandwidth by never ACKing.
        self.in_progress
            .retain(|proposal_round, _| *proposal_round > r);
    }

    fn observe(&mut self, certificates: Vec<Certificate>) {
        self.buffer.retain(|cert| !certificates.contains(cert));
    }

    async fn run(&mut self) {
        // Initialize connections with all peers to avoid the negotiation delay the first time we propose.
        // If we don't do this then the delay is repeated each time there is a new proposer, making it
        // non-trivial in shorter runs in larger networks.
        self.network
            .broadcast(
                self.committee.others_consensus_sockets(&self.name),
                Bytes::from("Ack"),
            )
            .await;

        if self.consensus_only {
            loop {
                tokio::select! {
                    Some(m) = self.rx_message.recv() => {
                        match m {
                            ProposerMessage::Propose(trigger) => self.propose(trigger).await,
                            ProposerMessage::Cleanup(r) => self.cleanup(r),
                            ProposerMessage::Observed(_) => (),
                        }
                    }
                }
            }
        } else {
            let timer = sleep(Duration::from_millis(self.max_block_delay));
            tokio::pin!(timer);

            loop {
                // Check if we can propose a new block.
                let timer_expired = timer.is_elapsed();
                let got_payload = !self.buffer.is_empty();

                if timer_expired || got_payload {
                    if let Some(trigger) = self.proposal_request.take() {
                        // Make a new block.
                        self.propose(trigger).await;

                        // Reschedule the timer.
                        let deadline = Instant::now() + Duration::from_millis(self.max_block_delay);
                        timer.as_mut().reset(deadline);
                    }
                }

                tokio::select! {
                    Some(certificate) = self.rx_mempool.recv() => {
                        self.buffer.push(certificate);
                    },
                    Some(m) = self.rx_message.recv() =>  {
                        match m {
                            ProposerMessage::Propose(trigger) => self.proposal_request = Some(trigger),
                            ProposerMessage::Cleanup(r) => self.cleanup(r),
                            ProposerMessage::Observed(certificates) => self.observe(certificates)
                        }
                    },
                    () = &mut timer => {
                        // Nothing to do.
                    },
                }
            }
        }
    }
}
