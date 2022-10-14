use crate::error::Error;
use crate::helpers::mock::TestHelperGateway;
use crate::helpers::prss::{Participant, SpaceIndex};
use crate::protocol::{QueryId, Step};
use crate::test_fixture::make_participants;
use std::fmt::{Debug, Display, Formatter};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld<S: SpaceIndex> {
    pub query_id: QueryId,
    pub gateways: [TestHelperGateway<S>; 3],
    pub participants: [Participant<S>; 3],
}

#[must_use]
pub fn make<S: Step + SpaceIndex>(query_id: QueryId) -> TestWorld<S> {
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let gateways = TestHelperGateway::make_three();

    TestWorld {
        query_id,
        gateways,
        participants,
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TestStep {
    Mul1(u8),
    Mul2,
    Reshare(u8),
    Reveal(u8),
    Shuffle,
}

impl Display for TestStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mul1(u) => write!(f, "mul1/{}", u),
            Self::Mul2 => write!(f, "mul2"),
            Self::Reshare(u) => write!(f, "reshare/{}", u),
            Self::Reveal(u) => write!(f, "reveal/{}", u),
            Self::Shuffle => write!(f, "shuffle"),
        }
    }
}

impl TryFrom<String> for TestStep {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.strip_prefix('/').unwrap_or(&value).to_lowercase();
        if value == "mul2" {
            Ok(Self::Mul2)
        } else {
            value
                .split_once('/')
                .and_then(|(pre, suf)| (pre == "mul1").then_some(suf))
                .and_then(|suf| suf.parse::<u8>().ok())
                .map(Self::Mul1)
                .ok_or_else(|| Error::path_parse_error(&value))
        }
    }
}

impl Step for TestStep {}

impl SpaceIndex for TestStep {
    const MAX: usize = 5;

    fn as_usize(&self) -> usize {
        match self {
            TestStep::Mul1(_) => 0,
            TestStep::Mul2 => 1,
            TestStep::Reshare(_) => 2,
            TestStep::Reveal(_) => 3,
            TestStep::Shuffle => 4,
        }
    }
}
