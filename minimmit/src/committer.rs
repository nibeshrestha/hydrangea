#[cfg(feature = "benchmark")]
use log::info;
use primary::Certificate;

use tokio::sync::mpsc::Receiver;

pub struct Committer {
    rx_commit: Receiver<Vec<Certificate>>,
}

impl Committer {
    pub fn spawn(rx_commit: Receiver<Vec<Certificate>>) {
        tokio::spawn(async move {
            Self { rx_commit }.run().await;
        });
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(certificates) = self.rx_commit.recv() => {
                    // debug!("Processing {:?}", certificate);
                    #[cfg(feature = "benchmark")]
                    // NOTE: This log entry is used to compute performance.
                    for certificate in certificates {
                        info!("Committed Header {:?}", certificate.id);
                    }
                }
            }
        }
    }
}
