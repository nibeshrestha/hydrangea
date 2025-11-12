use crate::consensus::Round;
use config::{Committee, LeaderElectorKind};
use crypto::PublicKey;
use std::collections::{HashMap, VecDeque};

// Note: There is likely a better way to do the below. My Rust needs work.
/// Factory for the various leader electors to enable instantiation at runtime.
pub struct LeaderElector {
    // maybe_fair_succession: Option<DeterministicFairSuccessionLeaderElector>,
    // maybe_failure: Option<FailureSimulationLeaderElector>,
    simple: SimpleLeaderElector,
}

impl LeaderElector {
    pub fn new(kind: LeaderElectorKind, committee: Committee) -> Self {
        // let (maybe_failure, maybe_fair_succession) = match kind {
        //     LeaderElectorKind::FailureBestCase => (
        //         Some(FailureSimulationLeaderElector::new(
        //             committee,
        //             FailureScenario::BEST,
        //         )),
        //         None,
        //     ),
        //     LeaderElectorKind::FailureMidCase => (
        //         Some(FailureSimulationLeaderElector::new(
        //             committee,
        //             FailureScenario::MID,
        //         )),
        //         None,
        //     ),
        //     LeaderElectorKind::FailureWorstCase => (
        //         Some(FailureSimulationLeaderElector::new(
        //             committee,
        //             FailureScenario::WORST,
        //         )),
        //         None,
        //     ),
        //     LeaderElectorKind::FairSuccession => (
        //         None,
        //         Some(DeterministicFairSuccessionLeaderElector::new(committee)),
        //     ),
        //     LeaderElectorKind::Simple => (
        //         None,
        //         Some(SimpleLeaderElector::new(committee)),
        //     )
        // };

        // Self {
        //     maybe_fair_succession,
        //     maybe_failure,
        // }
        Self {
            simple: SimpleLeaderElector::new(committee),
        }
    }

    pub fn get_leader(&self, round: Round) -> PublicKey {
        // match (
        //     self.maybe_failure.clone(),
        //     self.maybe_fair_succession.clone(),
        // ) {
        //     (Some(l), None) => l.get_leader(round),
        //     (None, Some(l)) => l.get_leader(round),
        //     _ => panic!("Unreachable by construction."),
        // }
        self.simple.get_leader(round)
    }
}

#[derive(Clone)]
pub struct DeterministicFairSuccessionLeaderElector {
    nodes_ids: Vec<PublicKey>,
    schedule: Vec<usize>,
}

/// Leader elector that ensures:
///   1. Every node leads the same number of rounds during the schedule.
///   2. Every node is succeeded by every other node during the schedule.
///   3. Every unique pair of nodes appears exactly once in the schedule.
impl DeterministicFairSuccessionLeaderElector {
    pub fn new(committee: Committee) -> Self {
        let n = committee.size();
        // Currently only support a static validator set, so can set this during construction.
        let mut nodes_ids: Vec<PublicKey> = committee.authorities.keys().cloned().collect();
        let schedule = Self::generate_schedule(n);
        nodes_ids.sort();

        Self {
            nodes_ids,
            schedule,
        }
    }

    fn generate_schedule(n: usize) -> Vec<usize> {
        let mut successors: HashMap<usize, VecDeque<usize>> = HashMap::new();

        if n < 1 {
            return Vec::new();
        }

        // Generate the schedule of unique successors for each leader.
        // E.g, given n = 4:
        //   0: 1, 2, 3
        //   1: 2, 3, 0
        //   2: 3, 0, 1
        //   3: 0, 1, 2
        for i in 0..n {
            let mut index_schedule = VecDeque::new();

            for j in 0..n {
                let next_successor = (i + j) % n;

                if next_successor != i {
                    index_schedule.push_back(next_successor);
                }
            }

            successors.insert(i, index_schedule);
        }

        let mut schedule = Vec::new();
        let mut leader = 0;

        // Merge the schedules for each leader into a single schedule
        // that ensures that each leader is succeeded by every other
        // leader exactly once with no repetitions.
        //
        // E.g, given n = 4:
        // 0 1 2 3 0 2 0 3 1 3 2 1 0
        loop {
            schedule.push(leader);
            let leader_successors = successors.get_mut(&leader).unwrap();

            if let Some(successor) = leader_successors.pop_front() {
                leader = successor;
            } else {
                break;
            }
        }

        // Schedule should loop back around.
        assert!(schedule.first() == schedule.last());
        // Remove the duplicate, since we'll be looping over this array.
        schedule.pop();

        schedule
    }

    pub fn get_leader(&self, round: Round) -> PublicKey {
        let index = round as usize % self.schedule.len();
        let leader = self.schedule[index];
        self.nodes_ids[leader]
    }
}

pub struct SimpleLeaderElector {
    node_ids: Vec<PublicKey>,
    n: usize,
}

impl SimpleLeaderElector {
    pub fn new(committee: Committee) -> Self {
        let n = committee.size();
        // Currently only support a static validator set, so can set this during construction.
        let id_map: HashMap<u32, PublicKey> = committee
            .authorities
            .iter()
            .map(|(x, y)| (y.id, *x))
            .collect();
        let mut node_ids = Vec::new();
        for idx in 0..n as u32 {
            node_ids.push(id_map[&idx]);
        }
        Self { node_ids, n }
    }

    pub fn get_leader(&self, round: Round) -> PublicKey {
        let index = round as usize % self.n;
        self.node_ids[index]
    }
}

pub enum FailureScenario {
    BEST,
    MID,
    WORST,
}

#[derive(Clone)]
pub struct FailureSimulationLeaderElector {
    schedule: Vec<PublicKey>,
}

/// Leader elector that ensures:
///   1. Every node leads the same number of rounds during the schedule.
///   2. Every node is succeeded by every other node during the schedule.
///   3. Every unique pair of nodes appears exactly once in the schedule.
impl FailureSimulationLeaderElector {
    pub fn new(committee: Committee, scenario: FailureScenario) -> Self {
        // Currently only support a static validator set, so can set this during construction.
        let schedule = match scenario {
            FailureScenario::BEST => Self::generate_best_schedule(committee),
            FailureScenario::MID => Self::generate_mid_schedule(committee),
            FailureScenario::WORST => Self::generate_worst_schedule(committee),
        };

        Self { schedule }
    }

    /// Best case failure scenario for a fixed leader schedule:
    ///   2f+1 Honest followed by f Byzantine.
    ///   Produces 2f directly-committable blocks with 2-round (plus proposal) latency.
    ///   Produces 1 block with f+3-round (plus proposal) latency.
    fn generate_best_schedule(committee: Committee) -> Vec<PublicKey> {
        let mut byzantine = committee.get_byzantine_ids();
        let mut honest = committee.get_honest_ids();
        honest.append(&mut byzantine);
        honest
    }

    /// Mid case failure scenario for a fixed leader schedule:
    ///   Honest, then Byzantine, for 2f nodes, followed by f+1 Honest.
    ///   Produces f+1 directly-committable blocks with 2-round (plus proposal) latency.
    fn generate_mid_schedule(committee: Committee) -> Vec<PublicKey> {
        let mut schedule = Vec::new();
        let byzantine = committee.get_byzantine_ids();
        let honest = committee.get_honest_ids();

        assert!(honest.len() > byzantine.len());

        for i in 0..honest.len() {
            schedule.push(honest[i]);

            if i < byzantine.len() {
                schedule.push(byzantine[i]);
            }
        }

        schedule
    }

    /// Worst case:
    ///   Two Honest, then Byzantine, for 3f nodes, followed by 1 Honest.
    ///   Produces 1 directly-committable block with 2-round (plus proposal) latency.
    ///   Produces f blocks with average (3f+1)/2-round (?) (plus proposal) latency.
    fn generate_worst_schedule(committee: Committee) -> Vec<PublicKey> {
        let mut schedule = Vec::new();
        let byzantine = committee.get_byzantine_ids();
        let honest = committee.get_honest_ids();

        assert!(honest.len() > 2 * byzantine.len());

        for i in 0..honest.len() {
            schedule.push(honest[i]);

            if i < byzantine.len() * 2 && i % 2 == 1 {
                let j = i / 2; // Integer division automatically rounds down.
                schedule.push(byzantine[j]);
            }
        }

        schedule
    }

    pub fn get_leader(&self, round: Round) -> PublicKey {
        let index = round as usize % self.schedule.len();
        self.schedule[index]
    }
}

/// Test helper.
#[cfg(test)]
pub fn test_generate_schedule_fairness(n: usize) {
    let schedule = DeterministicFairSuccessionLeaderElector::generate_schedule(n);

    // Each leader should be paired with ever other exactly once.
    assert!(schedule.len() == n * (n - 1));

    // Each leader should appear the same number of times in the schedule.
    for i in 0..n {
        assert!(schedule.iter().filter(|x| **x == i).count() == n - 1)
    }

    for start in 0..schedule.len() {
        // Each node should wait no longer than this before becoming the leader again.
        // Haven't managed to work out why this formula holds, but the wait is at most
        // this for n between 1 and 200. Not sure if it holds for all n.
        let end = start + 3 * n - 2;

        if end > schedule.len() {
            // Ignore the last n for now.
            break;
        }

        let cycle = &schedule[start..end];
        assert!(cycle.iter().filter(|x| **x == cycle[0]).count() >= 2);
    }
}

#[tokio::test]
async fn repeatedly_test_generate_schedule_fairness() {
    // We're currently only testing networks of up to 200 nodes, so don't need to
    // check for larger n. This is useful because the current method for checking
    // the max wait between elections of the same node is very expensive.
    for i in 1..200 {
        test_generate_schedule_fairness(i);
    }
}
