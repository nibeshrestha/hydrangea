use crate::consensus::{ConsensusMessage, CHANNEL_CAPACITY};
use crate::error::ConsensusResult;
use crate::messages::{Block, QC};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, Hash, PublicKey};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, error, info};
use network::SimpleSender;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

// #[cfg(test)]
// #[path = "tests/synchronizer_tests.rs"]
// pub mod synchronizer_tests;

const TIMER_ACCURACY: u64 = 5_000;

pub struct Synchronizer {
    store: Store,
    inner_channel: Sender<(Digest, PublicKey, Option<Block>)>,
}

impl Synchronizer {
    pub fn new(
        name: PublicKey,
        committee: Committee,
        store: Store,
        tx_sync_core: Sender<Block>,
        sync_retry_delay: u64,
    ) -> Self {
        let mut network = SimpleSender::new();
        let (tx_inner, mut rx_inner): (_, Receiver<(Digest, PublicKey, Option<Block>)>) =
            channel(CHANNEL_CAPACITY);

        let store_copy = store.clone();
        tokio::spawn(async move {
            let mut waiting = FuturesUnordered::new();
            let mut requests: HashMap<Digest, u128> = HashMap::new();
            let mut loopbacks: HashMap<Digest, Block> = HashMap::new();

            let timer = sleep(Duration::from_millis(TIMER_ACCURACY));
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    Some((to_sync, server, resume_from)) = rx_inner.recv() => {
                        if requests.contains_key(&to_sync) {
                            // Already made a SyncRequest for this block.
                            if let Some(to_yield_new) = resume_from {
                                // Loopback requested, which should be a GVC block.
                                if let Some(to_yield_old) = loopbacks.get(&to_sync) {
                                    // Also originally requested a loopback.
                                    if to_yield_new.round > to_yield_old.round {
                                        // Have now observed a higher GVC block, which we want to
                                        // commit upon completing the chain of uncommitted ancestors.
                                        loopbacks.insert(to_sync, to_yield_new);
                                    }
                                } else {
                                    // Did not initially request a loopback because the SyncRequest
                                    // was made on the basis of the QC for to_sync instead of that
                                    // for some GVC descendent thereof. We have since observed a
                                    // GVC descendent, which we want to ensure that we resume from
                                    // upon receiving to_sync.
                                    loopbacks.insert(to_sync, to_yield_new);
                                }
                            }
                        } else {
                            // New SyncRequest.
                            if let Some(to_yield) = resume_from {
                                // If this remove succeeds then we have received a GVC block that
                                // we had previously requested, but also happened to be missing an
                                // ancestor. We no longer need to keep requesting this block
                                // because we will persist it in-memory in loopbacks and yield it
                                // to the Core once it has written the block that we are now
                                // requesting to disk.
                                requests.remove(&to_yield.digest());
                                loopbacks.insert(to_sync.clone(), to_yield);
                            }

                            waiting.push(Self::waiter(store_copy.clone(), to_sync.clone()));

                            info!("Requesting sync for block {}", to_sync);
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            requests.insert(to_sync.clone(), now);

                            // Contact the specified peer before broadcasting the SyncRequest to
                            // reduce redundancy in the where case we failed to receive the block
                            // due to a local network failure. If it fails to respond (perhaps
                            // because it is the original proposer and it deliberately censored
                            // us in the first place) then we will contact the rest of the network
                            // on our next attempt.
                            let address = committee
                                .consensus(&server)
                                .expect("Peer specified as server is not in the committee")
                                .consensus_to_consensus;
                            let message = ConsensusMessage::SyncRequest(to_sync, name);
                            let message = bincode::serialize(&message)
                                .expect("Failed to serialize sync request");
                            network.send(address, Bytes::from(message)).await;
                        }
                    },
                    Some(result) = waiting.next() => match result {
                        Ok(requested) => {
                            // Ensure that we stop sending requests for this block.
                            requests.remove(&requested);

                            if let Some(resume_from) = loopbacks.remove(&requested) {
                                // Cause the Core to reprocess the given block. Usage ensures
                                // that resume_from is the GVC block with the greatest height
                                // known to the Core.
                                if let Err(e) = tx_sync_core.send(resume_from).await {
                                    panic!("Failed to send message through core channel: {}", e);
                                }
                            }
                            // else: The Core processed this block when it received the SyncResponse.
                        },
                        Err(e) => error!("{}", e)
                    },
                    () = &mut timer => {
                        // This implements the 'perfect point to point link' abstraction for blocks.
                        for (digest, timestamp) in &requests {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            if timestamp + (sync_retry_delay as u128) < now {
                                info!("Requesting sync for block {} (retry)", digest);
                                let addresses = committee
                                    .others_consensus(&name)
                                    .into_iter()
                                    .map(|(_, x)| x.consensus_to_consensus)
                                    .collect();
                                let message = ConsensusMessage::SyncRequest(digest.clone(), name);
                                let message = bincode::serialize(&message)
                                    .expect("Failed to serialize sync request");
                                network.broadcast(addresses, Bytes::from(message)).await;
                            }
                        }
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_ACCURACY));
                    }
                }
            }
        });
        Self {
            store,
            inner_channel: tx_inner,
        }
    }

    /**
     * Waits for the block with the given Digest wait_on to be written to storage.
     */
    async fn waiter(mut store: Store, wait_on: Digest) -> ConsensusResult<Digest> {
        store.notify_read(wait_on.to_vec()).await?;
        Ok(wait_on)
    }

    /**
     * Attempts to read the block (which should be certified) with the given digest from storage,
     * requesting it from the Committee if it cannot be found. Sends the given block (which should
     * be GVC), if any, back to the core consensus engine for processing once the requested block
     * is written to disk.
     */
    pub async fn get_block(
        &mut self,
        digest: &Digest,
        server: &PublicKey,
        resume_from: Option<Block>,
    ) -> ConsensusResult<Option<Block>> {
        if digest == &QC::genesis().hash {
            Ok(Some(Block::genesis()))
        } else {
            match self.store.read(digest.to_vec()).await? {
                Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
                None => {
                    debug!("Sending request to Synchronizer for {}", digest);
                    if let Err(e) = self
                        .inner_channel
                        .send((digest.clone(), server.clone(), resume_from))
                        .await
                    {
                        panic!("Failed to send request to synchronizer: {}", e);
                    }
                    Ok(None)
                }
            }
        }
    }
}
