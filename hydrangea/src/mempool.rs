use crate::error::ConsensusResult;
use crate::messages::Block;
use blsttc::PublicKeyShareG2;
use config::Committee;
use primary::Certificate;
use tokio::sync::mpsc::Sender;

pub struct MempoolDriver {
    committee: Committee,
    tx_mempool: Sender<Certificate>,
}

impl MempoolDriver {
    pub fn new(committee: Committee, tx_mempool: Sender<Certificate>) -> Self {
        Self {
            committee,
            tx_mempool,
        }
    }

    /// Verify the payload certificates.
    pub async fn verify(&mut self, block: &Block) -> ConsensusResult<()> {
        Ok(())
    }

    /// Cleanup the mempool.
    pub async fn cleanup(&mut self, payload: Vec<Certificate>) {}
}
