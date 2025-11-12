use crate::consensus::ConsensusMessage;
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use log::{debug, warn};
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::Receiver;

// #[cfg(test)]
// #[path = "tests/helper_tests.rs"]
// pub mod helper_tests;

/// A task dedicated to help other authorities by replying to their sync requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive sync requests.
    rx_requests: Receiver<(Digest, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(committee: Committee, store: Store, rx_requests: Receiver<(Digest, PublicKey)>) {
        tokio::spawn(async move {
            Self {
                committee,
                store,
                rx_requests,
                network: SimpleSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some((digest, origin)) = self.rx_requests.recv().await {
            // TODO [issue #58]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.consensus(&origin) {
                Ok(x) => x.consensus_to_consensus,
                Err(e) => {
                    warn!("Received unexpected sync request: {}", e);
                    continue;
                }
            };

            debug!("Received request for {} from {}", digest, address);

            // If we prune the local blockchain every 24 hours (or similar) then should be able cache the
            // digests of all blocks in-memory to make the below read more efficient. Combined with
            // rate-limiting, this should be sufficient to prevent DoS.

            // Reply to the request (if we can).
            if let Some(bytes) = self
                .store
                .read(digest.to_vec())
                .await
                .expect("Failed to read from storage")
            {
                let block =
                    bincode::deserialize(&bytes).expect("Failed to deserialize our own block");
                let message = bincode::serialize(&ConsensusMessage::SyncResponse(block))
                    .expect("Failed to serialize block");
                debug!("Serving {} to {}", digest, address);
                self.network.send(address, Bytes::from(message)).await;
            }
        }
    }
}
