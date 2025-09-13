use crate::config::{Committee, Stake};
use crate::core::{SeqNumber, OPT, PES, PRE_ONE, PRE_TWO, RBC_ECHO, RBC_READY};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{EchoVote, Prepare, RBCProof, RandomnessShare, ReadyVote};
use crypto::{PublicKey, Signature};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryInto;
use threshold_crypto::PublicKeySet;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

// In HotStuff, votes/timeouts aggregated by round
// In VABA and async fallback, votes aggregated by round, timeouts/coin_share aggregated by view
pub struct Aggregator {
    committee: Committee,
    share_coin_aggregators: HashMap<(SeqNumber, SeqNumber, SeqNumber), Box<RandomCoinMaker>>,
    echo_vote_aggregators: HashMap<(SeqNumber, SeqNumber), Box<RBCProofMaker>>,
    ready_vote_aggregators: HashMap<(SeqNumber, SeqNumber), Box<RBCProofMaker>>,
    prepare_vote_aggregators: HashMap<(SeqNumber, SeqNumber, u8), Box<PrepareMaker>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            share_coin_aggregators: HashMap::new(),
            echo_vote_aggregators: HashMap::new(),
            ready_vote_aggregators: HashMap::new(),
            prepare_vote_aggregators: HashMap::new(),
        }
    }

    pub fn add_rbc_echo_vote(&mut self, vote: EchoVote) -> ConsensusResult<Option<RBCProof>> {
        self.echo_vote_aggregators
            .entry((vote.epoch, vote.height))
            .or_insert_with(|| Box::new(RBCProofMaker::new()))
            .append(
                vote.epoch,
                vote.height,
                vote.author,
                RBC_ECHO,
                vote.signature,
                &self.committee,
            )
    }

    pub fn add_rbc_ready_vote(&mut self, vote: ReadyVote) -> ConsensusResult<Option<RBCProof>> {
        self.ready_vote_aggregators
            .entry((vote.epoch, vote.height))
            .or_insert_with(|| Box::new(RBCProofMaker::new()))
            .append(
                vote.epoch,
                vote.height,
                vote.author,
                RBC_READY,
                vote.signature,
                &self.committee,
            )
    }

    pub fn add_prepare_vote(&mut self, prepare: Prepare) -> ConsensusResult<Option<(u8, bool)>> {
        self.prepare_vote_aggregators
            .entry((prepare.epoch, prepare.height, prepare.phase))
            .or_insert_with(|| Box::new(PrepareMaker::new()))
            .append(prepare, &self.committee)
    }

    pub fn add_aba_share_coin(
        &mut self,
        share: RandomnessShare,
        pk_set: &PublicKeySet,
    ) -> ConsensusResult<Option<usize>> {
        self.share_coin_aggregators
            .entry((share.epoch, share.height, share.round))
            .or_insert_with(|| Box::new(RandomCoinMaker::new()))
            .append(share, &self.committee, pk_set)
    }

    pub fn cleanup(&mut self, epoch: SeqNumber, height: SeqNumber) {
        let size = self.committee.size() as u64;
        let rank = epoch * size + height;
        self.echo_vote_aggregators
            .retain(|(e, h, ..), _| e * size + h > rank);
        self.ready_vote_aggregators
            .retain(|(e, h, ..), _| e * size + h > rank);
        self.prepare_vote_aggregators
            .retain(|(e, h, ..), _| e * size + h > rank);
        self.share_coin_aggregators
            .retain(|(e, h, _), _| e * size + h > rank);
    }
}

struct RBCProofMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl RBCProofMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        author: PublicKey,
        tag: u8,
        siganture: Signature,
        committee: &Committee,
    ) -> ConsensusResult<Option<RBCProof>> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinRBCVote(author)
        );
        self.votes.push((author, siganture));
        self.weight += committee.stake(&author);

        if self.weight == committee.quorum_threshold()
            || (tag == RBC_READY && self.weight == committee.random_coin_threshold())
        {
            let proof = RBCProof::new(epoch, height, self.votes.clone(), tag);
            return Ok(Some(proof));
        }
        Ok(None)
    }
}

struct PrepareMaker {
    optnum: Stake,
    pesnum: Stake,
    used: HashSet<PublicKey>,
}

impl PrepareMaker {
    pub fn new() -> Self {
        Self {
            optnum: 0,
            pesnum: 0,
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        prepare: Prepare,
        committee: &Committee,
    ) -> ConsensusResult<Option<(u8, bool)>> {
        // Ensure it is the first time this authority votes.
        let author = prepare.author;
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinPrepare(author)
        );
        if prepare.val == OPT {
            self.optnum += committee.stake(&author)
        } else {
            self.pesnum += committee.stake(&author)
        }
        let total = self.optnum + self.pesnum;

        if total >= committee.quorum_threshold() {
            if prepare.phase == PRE_ONE {
                if self.optnum >= committee.quorum_threshold() {
                    return Ok(Some((OPT, true)));
                } else if self.optnum > 0 {
                    return Ok(Some((OPT, false)));
                }
                return Ok(Some((PES, false)));
            } else if prepare.phase == PRE_TWO {
                if self.pesnum >= committee.quorum_threshold() {
                    return Ok(Some((PES, true)));
                } else if self.pesnum > 0 {
                    return Ok(Some((PES, false)));
                }
                return Ok(Some((OPT, false)));
            }
        }
        Ok(None)
    }
}

struct RandomCoinMaker {
    weight: Stake,
    shares: Vec<RandomnessShare>,
    used: HashSet<PublicKey>,
}

impl RandomCoinMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            shares: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        share: RandomnessShare,
        committee: &Committee,
        pk_set: &PublicKeySet,
    ) -> ConsensusResult<Option<usize>> {
        let author = share.author;
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinCoin(author)
        );
        self.shares.push(share.clone());
        self.weight += committee.stake(&author);
        if self.weight == committee.random_coin_threshold() {
            // self.weight = 0; // Ensures QC is only made once.
            let mut sigs = BTreeMap::new();
            // Check the random shares.
            for share in self.shares.clone() {
                sigs.insert(
                    committee.id(share.author.clone()),
                    share.signature_share.clone(),
                );
            }
            if let Ok(sig) = pk_set.combine_signatures(sigs.iter()) {
                let id = usize::from_be_bytes((&sig.to_bytes()[0..8]).try_into().unwrap()) % 2;

                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}
