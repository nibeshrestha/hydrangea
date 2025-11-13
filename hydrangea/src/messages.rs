use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use blsttc::SignatureShareG1;
use config::Committee;
use crypto::{
    remove_pubkeys, BlsSignatureService, Digest, Hash, PublicKey, Signature, SignatureService,
};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use primary::Certificate;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;

// #[cfg(test)]
// #[path = "tests/messages_tests.rs"]
// pub mod messages_tests;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub author: PublicKey,
    pub parent: Digest,
    pub payload: Vec<Certificate>,
    pub round: Round,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        author: PublicKey,
        parent: Digest,
        payload: Vec<Certificate>,
        round: Round,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut b = Block {
            author,
            parent,
            payload,
            round,
            signature: Signature::default(),
        };
        b.signature = signature_service.request_signature(b.digest()).await;
        b
    }

    pub fn genesis() -> Self {
        Self {
            author: PublicKey::default(),
            parent: Digest::default(),
            payload: Vec::default(),
            round: 0,
            signature: Signature::default(),
        }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ignore Genesis block.
        if self.digest() != Block::genesis().digest() {
            // Ensure the proposer has voting rights.
            let voting_rights = committee.stake(&self.author);
            ensure!(
                voting_rights > 0,
                ConsensusError::UnknownAuthority(self.author)
            );
            // Ensure the included signature is that of the author.
            self.signature.verify(&self.digest(), &self.author)?;
        }
        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.parent.clone());
        hasher.update(self.round.to_le_bytes());

        for x in &self.payload {
            hasher.update(&x.id);
        }

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: CMB(author {}, parent {}, round {}, payload_len {})",
            self.digest(),
            self.author,
            self.parent,
            self.round,
            self.payload.len()
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "CMB{}", self.round)
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct OptimisticProposal {
    pub block: Block,
}

impl OptimisticProposal {
    pub fn new(block: Block) -> Self {
        Self { block }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        self.block.is_well_formed(committee)?;
        Ok(())
    }
}

impl Hash for OptimisticProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.block.digest());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for OptimisticProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "OptimisticProposal {}: Block {:?})",
            self.digest(),
            self.block
        )
    }
}

impl fmt::Display for OptimisticProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "OptimisticProposal B{}", self.block.round)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NormalProposal {
    pub block: Block,
    // QC for block.parent, which must have been proposed in block.round - 1.
    pub qc: QC,
}

impl NormalProposal {
    pub fn new(block: Block, qc: QC) -> Self {
        Self { block, qc }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        self.block.is_well_formed(committee)?;

        // QC must be for the parent of this block, which must have been proposed
        // for the round before this block.
        ensure!(
            // Check parent relationship and round numbers.
            // We check QC validity whilst processing the QC itself, which
            // happens before we invoke this function, so we don't check again here.
            self.qc.hash == self.block.parent && self.qc.round == self.block.round - 1,
            ConsensusError::MalformedNormalProposal(self.digest())
        );

        Ok(())
    }
}

impl Hash for NormalProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.block.digest());
        hasher.update(self.qc.digest());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for NormalProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "NormalProposal {}: Block {:?}, {:?})",
            self.digest(),
            self.block,
            self.qc
        )
    }
}

impl fmt::Display for NormalProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "NormalProposal B{}", self.block.round)
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FallbackRecoveryProposal {
    pub block: Block,
    // TC for block.round - 1, the highest QC of which must certify block.parent.
    pub tc: TC,
}

impl FallbackRecoveryProposal {
    pub fn new(block: Block, tc: TC) -> Self {
        Self { block, tc }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        self.block.is_well_formed(committee)?;

        // Ensure that the correct TC has been used to justify this proposal.
        ensure!(
            self.tc.round == self.block.round - 1,
            ConsensusError::BlockBadTC(self.digest(), self.block.round, self.tc.round)
        );

        // Parent of the block must be certified by qc_prime.
        ensure!(
            self.block.parent == self.tc.high_qc.hash,
            ConsensusError::FallbackRecoveryBadParent(self.block.digest())
        );

        // TC validity is checked when the TC is processed.
        Ok(())
    }
}

impl Hash for FallbackRecoveryProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.block.digest());
        hasher.update(self.tc.digest());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for FallbackRecoveryProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "FallbackRecoveryProposal {}: {:?}, {:?}",
            self.digest(),
            self.block,
            self.tc
        )
    }
}

impl fmt::Display for FallbackRecoveryProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "FallbackRecoveryProposal B{}", self.block.round)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum ProposalType {
    Fallback,
    Normal,
    Optimistic,
}

impl Hash for ProposalType {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        match self {
            Self::Fallback => hasher.update("Fallback"),
            Self::Normal => hasher.update("Normal"),
            Self::Optimistic => hasher.update("Optimistic"),
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Display for ProposalType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::Fallback => write!(f, "Fallback"),
            Self::Normal => write!(f, "Normal"),
            Self::Optimistic => write!(f, "Optimistic"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Default, Debug)]
pub enum VoteType {
    Commit,
    PrepareFallback,
    #[default]
    PrepareNormal,
    PrepareOptimistic,
}

impl Hash for VoteType {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        match self {
            Self::Commit => hasher.update("C"),
            Self::PrepareFallback => hasher.update("PF"),
            Self::PrepareNormal => hasher.update("PN"),
            Self::PrepareOptimistic => hasher.update("PO"),
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Display for VoteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::Commit => write!(f, "C"),
            Self::PrepareFallback => write!(f, "PF"),
            Self::PrepareNormal => write!(f, "PN"),
            Self::PrepareOptimistic => write!(f, "PO"),
        }
    }
}

// TODO: Timeouts and Prepares should come with justification to prevent
// Byzantine nodes spamming messages for higher rounds.
#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub author: PublicKey,
    pub hash: Digest,
    pub kind: VoteType,
    pub round: Round,
    pub signature: SignatureShareG1,
}

impl Vote {
    pub async fn new(
        author: PublicKey,
        hash: Digest,
        kind: VoteType,
        round: Round,
        bls_signature_service: &mut BlsSignatureService,
    ) -> Self {
        let vote = Self {
            author,
            hash: hash.clone(),
            kind,
            round,
            signature: SignatureShareG1::default(),
        };
        // Only sign the block. The network channels are already authenticated so
        // no need to sign the whole message.
        let signature = bls_signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // let author_bls_key_g1 = committee.get_bls_public_g1(&self.author);
        // // Check the signature.
        // self.signature
        //     .verify_batch(&self.digest().0, &author_bls_key_g1)
        //     .map_err(ConsensusError::from)
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.kind.digest());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "V({}, {}, {}, {})",
            self.kind, self.author, self.round, self.hash
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub kind: VoteType,
    pub round: Round,
    pub votes: (Vec<u128>, SignatureShareG1),
    pub fast_quorum: bool,
}

impl QC {
    pub fn genesis() -> Self {
        QC {
            hash: Block::genesis().digest(),
            kind: VoteType::Commit,
            round: 0,
            votes: (Vec::new(), SignatureShareG1::default()),
            fast_quorum: false,
        }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        if self.round == 0 {
            Ok(())
        } else {
            // // Ensure the QC has a quorum.
            // let mut weight = 0;
            // let mut used = HashSet::new();
            // for (name, _) in self.votes.iter() {
            //     ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            //     let voting_rights = committee.stake(name);
            //     ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            //     used.insert(*name);
            //     weight += voting_rights;
            // }
            // // TODO: Change to error log instead of panic.
            // ensure!(
            //     weight >= committee.quorum_threshold(),
            //     ConsensusError::QCRequiresQuorum(self.round)
            // );
            let mut ids = Vec::new();

            for idx in 0..committee.size() {
                let x = idx / 128;
                let chunk = self.votes.0[x];
                let ridx = idx - x * 128;
                if chunk & 1 << ridx != 0 {
                    ids.push(idx);
                }
            }

            let agg_pk = remove_pubkeys(&committee.combined_pubkey, ids, &committee.sorted_keys);

            // Check the signatures.
            SignatureShareG1::verify_batch(&self.digest().0, &agg_pk, &self.votes.1)
                .map_err(ConsensusError::from)
        }
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(&self.kind.digest());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Display for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.hash, self.round)
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.kind {
            VoteType::Commit => write!(f, "CommitQC({}, {})", self.hash, self.round),
            _ => write!(f, "PrepareQC({}, {}, {})", self.kind, self.hash, self.round),
        }
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.hash == other.hash && self.round == other.round
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub high_qc: QC,
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: Round,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn author_is_authorised(&self, committee: &Committee) -> ConsensusResult<bool> {
        // Ensure the author has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        Ok(true)
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        self.author_is_authorised(committee)?;
        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.is_well_formed(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.high_qc.round.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TC {
    // Justifies the correctness of `votes`. Without this, a Byzantine node
    // can forge a TC that includes erroneous votes with arbitrarily high
    // round numbers, which the adversary can use to force honest proposers
    // to create invalid Fallback Recovery Proposals (if, say, we create
    // such a proposal using our locked QC and the TC, as the old Jolteon
    // implementation did), since a leader will create an FRP from the first
    // TC that it receives. This allows the adversary to break liveness
    // permanently by always preventing honest leaders from generating valid
    // Fallback Recovery Proposals.
    pub high_qc: QC,
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature, Round)>,
}

impl TC {
    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the TC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, locked_qc_round) in self.votes.iter() {
            // Ensure that the creator of this TC reported the highest round
            // reported in `self.votes`.
            ensure!(
                *locked_qc_round <= self.high_qc.round,
                ConsensusError::TCInvalidHighQC(self.high_qc.clone())
            );
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        for (author, signature, locked_qc_round) in &self.votes {
            // Check the signature.
            let mut hasher = Sha512::new();
            hasher.update(locked_qc_round.to_le_bytes());
            hasher.update(self.round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, &author)?;
        }
        Ok(())
    }

    pub fn locked_rounds(&self) -> Vec<&Round> {
        self.votes
            .iter()
            .map(|(_, _, locked_round)| locked_round)
            .collect()
    }
}

impl Hash for TC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.digest());

        for (_node, _sig, locked_round) in &self.votes {
            hasher.update(locked_round.to_be_bytes());
        }

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "TC({}, {:?}, {:?})",
            self.round,
            self.high_qc,
            self.locked_rounds()
        )
    }
}
