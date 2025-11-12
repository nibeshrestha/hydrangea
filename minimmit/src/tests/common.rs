use config::Committee;
use crate::consensus::Round;
use crate::messages::{Block, Timeout, Vote, QC, Proposal, Justification};
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{generate_keypair, Digest, PublicKey, SecretKey, Signature};
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::info;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

// Fixture.
pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture.
pub fn committee() -> Committee {
    Committee::new_for_test(
        keys()
            .into_iter()
            .enumerate()
            .map(|(i, (name, _))| {
                let address = format!("127.0.0.1:{}", i).parse().unwrap();
                let stake = 1;
                (name, stake, address)
            })
            .collect()
    )
}

// Fixture.
pub fn committee_with_base_port(base_port: u16) -> Committee {
    let mut committee = committee();
    for authority in committee.authorities.values_mut() {
        let port = authority.consensus.consensus_to_consensus.port();
        authority.consensus.consensus_to_consensus.set_port(base_port + port);
    }
    committee
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl Vote {
    pub fn new_from_key(hash: Digest, parent: Digest, round: Round, author: PublicKey, secret: &SecretKey) -> Self {
        let vote = Self {
            hash,
            parent,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = Signature::new(&vote.digest(), &secret);
        Self { signature, ..vote }
    }
}

// impl PartialEq for Vote {
//     fn eq(&self, other: &Self) -> bool {
//         self.digest() == other.digest()
//     }
// }

impl Timeout {
    pub fn new_from_key(high_qc: QC, round: Round, author: PublicKey, secret: &SecretKey) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = Signature::new(&timeout.digest(), &secret);
        Self {
            signature,
            ..timeout
        }
    }
}

// impl PartialEq for Timeout {
//     fn eq(&self, other: &Self) -> bool {
//         self.digest() == other.digest()
//     }
// }

// Fixture.
pub fn block() -> Block {
    let (public_key, secret_key) = keys().pop().unwrap();
    Block { 
        author: public_key, 
        parent: Block::genesis().digest(), 
        payload: Vec::new(), 
        round: 1 
    }
}

// Fixture.
pub fn block_from(author: PublicKey, parent: Digest, round: Round) -> Block {
    Block { 
        author, 
        parent, 
        payload: Vec::new(), 
        round
    }
}

// Fixture.
pub fn proposal() -> Proposal {
    let (public_key, secret_key) = keys().pop().unwrap();
    let block = Block { 
        author: public_key, 
        parent: Block::genesis().digest(), 
        payload: Vec::new(), 
        round: 1 
    };
    Proposal {
        signature: Signature::new(&block.digest(), &secret_key),
        block,
        justification: Justification::QC(QC::genesis())
    }
}

// Fixture.
pub fn proposal_from(
    author: PublicKey, 
    parent: Digest, 
    round: Round, 
    justification: Justification, 
    key: SecretKey
) -> Proposal {
    let block = block_from(author, parent, round);
    Proposal {
        signature: Signature::new(&block.digest(), &key),
        block,
        justification
    }
}

// Fixture.
pub fn proposal_from_block(
    block: Block,  
    justification: Justification, 
    key: SecretKey
) -> Proposal {
    Proposal {
        signature: Signature::new(&block.digest(), &key),
        block,
        justification
    }
}

// Fixture.
pub fn vote() -> Vote {
    let (public_key, secret_key) = keys().pop().unwrap();
    let vote = Vote { 
        author: public_key, 
        hash: block().digest(),
        parent: Block::genesis().digest(), 
        round: 1,
        signature: Signature::default()
    };
    Vote {
        signature: Signature::new(&vote.digest(), &secret_key),
        ..vote
    }
}

// Fixture.
pub fn qc() -> QC {
    let qc = QC {
        hash: Digest::default(),
        parent: Block::genesis().digest(),
        round: 1,
        votes: Vec::new(),
    };
    let digest = qc.digest();
    let mut keys = keys();
    let votes: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();
    QC { votes, ..qc }
}

// Fixture.
pub fn qc_from(hash: Digest, parent: Digest, round: Round) -> QC {
    let qc = QC {
        hash,
        parent,
        round,
        votes: Vec::new()
    };
    let digest = qc.digest();
    let mut keys = keys();
    let votes: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();
    QC { votes, ..qc }
}

// Fixture.
pub fn chain(keys: Vec<(PublicKey, SecretKey)>) -> Vec<(Block, QC)> {
    let mut parent = Block::genesis().digest();
    keys.iter()
        .enumerate()
        .map(|(i, key)| {
            // Make a block.
            let (public_key, _) = key;
            let block = block_from(
                *public_key,
                parent.clone(),
                1 + i as Round
            );

            // Make a qc for the block.
            let qc = QC {
                hash: block.digest(),
                parent: parent.clone(),
                round: block.round,
                votes: Vec::new(),
            };
            let digest = qc.digest();
            let votes: Vec<_> = keys
                .iter()
                .map(|(public_key, secret_key)| (*public_key, Signature::new(&digest, secret_key)))
                .collect();

            parent = block.digest();

            // Return the block.
            (block, qc)
        })
        .collect()
}

// Fixture
pub fn listener(address: SocketAddr, expected: Option<Bytes>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let transport = Framed::new(socket, LengthDelimitedCodec::new());
        let (mut writer, mut reader) = transport.split();
        match reader.next().await {
            Some(Ok(received)) => {
                writer.send(Bytes::from("Ack")).await.unwrap();
                if let Some(expected) = expected {
                    assert_eq!(received.freeze(), expected);
                }
            }
            _ => panic!("Failed to receive network message"),
        }
    })
}

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub timeout_delay: u64,
    pub sync_retry_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            timeout_delay: 5_000,
            sync_retry_delay: 10_000,
        }
    }
}

impl Parameters {
    pub fn log(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Timeout delay set to {} rounds", self.timeout_delay);
        info!("Sync retry delay set to {} ms", self.sync_retry_delay);
    }
}
