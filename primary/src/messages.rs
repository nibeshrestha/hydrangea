use crate::batch_maker::Transaction;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use blsttc::SignatureShareG1;
use config::Committee;
use crypto::{
    combine_key_from_ids, BlsSignatureService, Digest, Hash, PublicKey, Signature, SignatureService,
};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Transaction>,
    pub id: Digest,
    pub signature: Signature,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            id: Digest::default(),
            signature: Signature::default(),
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Check the signature.
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub signature: SignatureShareG1,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
        bls_signature_service: &mut BlsSignatureService,
    ) -> Self {
        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author,
            author: *author,
            signature: SignatureShareG1::default(),
        };
        let signature = bls_signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        // let author_bls_key_g1 = committee.get_bls_public_g1(&self.author);
        // Check the signature.
        // self.signature
        //     .verify_with_nizk(&self.digest().0, &author_bls_key_g1, &self.zkp)
        //     .map_err(DagError::from)
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub votes: (u128, SignatureShareG1),
}

impl Certificate {
    // pub fn genesis(committee: &Committee) -> Vec<Self> {
    //     committee
    //         .authorities
    //         .keys()
    //         .map(|name| Self {
    //             header: Header {
    //                 author: *name,
    //                 ..Header::default()
    //             },
    //             ..Self::default()
    //         })
    //         .collect()
    // }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // // Genesis certificates are always valid.
        // if Self::genesis(committee).contains(self) {
        //     return Ok(());
        // }

        // Check the embedded header.
        // self.header.verify(committee)?;

        // Ensure the certificate has a quorum.
        // let mut weight = 0;
        //let mut used = HashSet::new();
        // for (name, _) in self.votes.iter() {
        //     ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
        //     let voting_rights = committee.stake(name);
        //     ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
        //     used.insert(*name);
        //     weight += voting_rights;
        // }
        // ensure!(
        //     weight >= committee.validity_threshold(),
        //     DagError::CertificateRequiresQuorum
        // );
        let mut ids = Vec::new();

        for idx in 0..committee.size() {
            if self.votes.0 & (1 << idx) != 0 {
                ids.push(idx);
            }
        }

        // let pks: Vec<PublicKeyShareG2> = ids.iter().map(|i| sorted_keys[*i]).collect();
        let agg_pk = combine_key_from_ids(ids, &committee.sorted_keys);

        // Check the signatures.
        SignatureShareG1::verify_batch(&self.digest().0, &agg_pk, &self.votes.1)
            .map_err(DagError::from)
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round,
            self.origin,
            self.id,
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.id == other.id;
        ret &= self.round == other.round;
        ret &= self.origin == other.origin;
        ret
    }
}
