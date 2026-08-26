use crate::coordinator::recovery::recover;
use crate::coordinator::{CoordinatorInitialState, CoordinatorState, CoordinatorStep1State};
use crate::errors::{ChillDkgError, Result};
use crate::msg::{
    CoordinatorDKGOutput, CoordinatorMsg1, CoordinatorMsg2, DKGOutput, ParticipantMsg1,
    ParticipantMsg2, RecoveryData,
};
use crate::party::{
    ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
};
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

pub mod coordinator;
pub mod crypto;
pub mod errors;
pub mod msg;
pub mod party;

pub struct Participant {
    state: ParticipantStateValue,
}

enum ParticipantStateValue {
    Initial(ParticipantInitialState),
    Step1(ParticipantStep1State),
    Step2(ParticipantStep2State),
    Failed,
    Succeed,
    Replaced, // An intermediate state between transitions
}

impl Participant {
    pub fn new(rng: &mut impl CryptoRngCore) -> (Scalar, Self) {
        let state = ParticipantInitialState::new(rng);

        (
            state.s,
            Self {
                state: ParticipantStateValue::Initial(state),
            },
        )
    }

    pub fn new_with_secret(scalar: &Scalar) -> Self {
        Self {
            state: ParticipantStateValue::Initial(ParticipantInitialState::new_with_secret(scalar)),
        }
    }

    pub fn recover(scalar: &Scalar, recovery_data: &RecoveryData) -> Result<DKGOutput> {
        party::recovery::recover(scalar, recovery_data)
    }

    pub fn step1(
        &mut self,
        msg: <ParticipantInitialState as ParticipantState>::Message,
    ) -> Result<ParticipantMsg1> {
        let (next, pmsg1) = Self::step1_inner(
            std::mem::replace(&mut self.state, ParticipantStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = ParticipantStateValue::Failed;
        })?;

        self.state = next;

        Ok(pmsg1)
    }

    fn step1_inner(
        state: ParticipantStateValue,
        msg: <ParticipantInitialState as ParticipantState>::Message,
    ) -> Result<(ParticipantStateValue, ParticipantMsg1)> {
        match state {
            ParticipantStateValue::Initial(state) => {
                let (next, pmsg1) = state.next(msg)?;

                let next_state = ParticipantStateValue::Step1(next.ok_or_else(|| {
                    ChillDkgError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, pmsg1))
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    pub fn step2(
        &mut self,
        msg: <ParticipantStep1State as ParticipantState>::Message,
    ) -> Result<ParticipantMsg2> {
        let (next, pmsg2) = Self::step2_inner(
            std::mem::replace(&mut self.state, ParticipantStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = ParticipantStateValue::Failed;
        })?;

        self.state = next;

        Ok(pmsg2)
    }

    fn step2_inner(
        state: ParticipantStateValue,
        msg: <ParticipantStep1State as ParticipantState>::Message,
    ) -> Result<(ParticipantStateValue, ParticipantMsg2)> {
        match state {
            ParticipantStateValue::Step1(state) => {
                let (next, pmsg1) = state.next(msg)?;

                let next_state = ParticipantStateValue::Step2(next.ok_or_else(|| {
                    ChillDkgError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, pmsg1))
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    pub fn finalize(
        &mut self,
        msg: <ParticipantStep2State as ParticipantState>::Message,
    ) -> Result<(DKGOutput, RecoveryData)> {
        let (out, recovery_data) = Self::finalize_inner(
            std::mem::replace(&mut self.state, ParticipantStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = ParticipantStateValue::Failed;
        })?;

        self.state = ParticipantStateValue::Succeed;

        Ok((out, recovery_data))
    }

    fn finalize_inner(
        state: ParticipantStateValue,
        msg: <ParticipantStep2State as ParticipantState>::Message,
    ) -> Result<(DKGOutput, RecoveryData)> {
        match state {
            ParticipantStateValue::Step2(state) => {
                let (_, res) = state.next(msg)?;
                Ok(res)
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, ParticipantStateValue::Failed)
    }

    pub fn is_succeed(&self) -> bool {
        matches!(self.state, ParticipantStateValue::Succeed)
    }

    pub fn is_active(&self) -> bool {
        !self.is_failed() && !self.is_succeed()
    }
}

pub struct Coordinator {
    state: CoordinatorStateValue,
}
enum CoordinatorStateValue {
    Initial(CoordinatorInitialState),
    Step1(CoordinatorStep1State),
    Failed,
    Succeed,
    Replaced, // An intermediate state between transitions
}

impl Coordinator {
    pub fn new(host_pubkeys: Vec<ProjectivePoint>, t: usize) -> Result<Self> {
        Ok(Self {
            state: CoordinatorStateValue::Initial(CoordinatorInitialState::new(host_pubkeys, t)?),
        })
    }

    pub fn recover(recovery_data: RecoveryData) -> Result<CoordinatorDKGOutput> {
        recover(&recovery_data)
    }

    pub fn step1(
        &mut self,
        msg: <CoordinatorInitialState as CoordinatorState>::Message,
    ) -> Result<CoordinatorMsg1> {
        let (next, cmsg1) = Self::step1_inner(
            std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = CoordinatorStateValue::Failed;
        })?;

        self.state = next;

        Ok(cmsg1)
    }

    fn step1_inner(
        state: CoordinatorStateValue,
        msg: <CoordinatorInitialState as CoordinatorState>::Message,
    ) -> Result<(CoordinatorStateValue, CoordinatorMsg1)> {
        match state {
            CoordinatorStateValue::Initial(state) => {
                let (next, cmsg1) = state.next(msg)?;

                let next_state = CoordinatorStateValue::Step1(next.ok_or_else(|| {
                    ChillDkgError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, cmsg1))
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }
    pub fn step2(
        &mut self,
        msg: <CoordinatorStep1State as CoordinatorState>::Message,
    ) -> Result<(CoordinatorMsg2, CoordinatorDKGOutput, RecoveryData)> {
        let (cmsg2, out, recovery_data) = Self::step2_inner(
            std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = CoordinatorStateValue::Failed;
        })?;

        self.state = CoordinatorStateValue::Succeed;

        Ok((cmsg2, out, recovery_data))
    }

    fn step2_inner(
        state: CoordinatorStateValue,
        msg: <CoordinatorStep1State as CoordinatorState>::Message,
    ) -> Result<(CoordinatorMsg2, CoordinatorDKGOutput, RecoveryData)> {
        match state {
            CoordinatorStateValue::Step1(state) => {
                let (_, res) = state.next(msg)?;
                Ok(res)
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Failed)
    }

    pub fn is_succeed(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Succeed)
    }

    pub fn is_active(&self) -> bool {
        !self.is_failed() && !self.is_succeed()
    }
}

#[cfg(test)]
mod tests {
    use crate::coordinator::{CoordinatorInitialState, CoordinatorState};
    use crate::msg::{ParticipantMsg1, ParticipantMsg2};
    use crate::party::{
        ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
    };
    use crate::{Coordinator, Participant};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    #[test]
    fn success_generate_key_hl() {
        const T: usize = 3;

        let mut rng = OsRng;

        // --------------- INIT PHASE ---------------
        let (s1, mut p1) = Participant::new(&mut rng);
        let (s2, mut p2) = Participant::new(&mut rng);
        let (s3, mut p3) = Participant::new(&mut rng);
        let (s4, mut p4) = Participant::new(&mut rng);
        let (s5, mut p5) = Participant::new(&mut rng);

        let host_seckeys = vec![s1, s2, s3, s4, s5];

        let host_keys = vec![
            ProjectivePoint::GENERATOR * s1,
            ProjectivePoint::GENERATOR * s2,
            ProjectivePoint::GENERATOR * s3,
            ProjectivePoint::GENERATOR * s4,
            ProjectivePoint::GENERATOR * s5,
        ];

        let mut c = Coordinator::new(host_keys.clone(), T).unwrap();

        // --------------- DKG PHASE ---------------

        // ---- STEP 1 ----

        let msg1 = vec![
            p1.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p2.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p3.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p4.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p5.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
        ];

        let msg1_resp = c.step1(msg1).unwrap();

        // ---- STEP 2 ----

        let msg2 = vec![
            p1.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p2.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p3.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p4.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p5.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
        ];

        let (msg2_resp, output, _) = c.step2(msg2).unwrap();

        println!("Coordinator DKG output:");
        println!(
            "\t\tGroup public key {:?}",
            output.threshold_pubkey.to_encoded_point(true).to_string()
        );
        println!("\n\n");

        // ---- CertEq ----

        let res1 = p1.finalize(msg2_resp.clone()).unwrap();
        let res2 = p2.finalize(msg2_resp.clone()).unwrap();
        let res3 = p3.finalize(msg2_resp.clone()).unwrap();
        let res4 = p4.finalize(msg2_resp.clone()).unwrap();
        let res5 = p5.finalize(msg2_resp.clone()).unwrap();

        for (i, res) in vec![res1, res2, res3, res4, res5].iter().enumerate() {
            let (p_output, recovery_data) = res;
            assert_eq!(
                p_output.threshold_pubkey, output.threshold_pubkey,
                "Invalid group key for party {}",
                p_output.idx
            );

            assert_eq!(p_output.pubshares, output.pubshares);

            println!("Participant {} DKG output:", p_output.idx);
            println!(
                "\t\tGroup public key {:?}",
                p_output.threshold_pubkey.to_encoded_point(true).to_string()
            );
            println!("\t\tSecret share {:x}", p_output.secshare.to_bytes());

            let p_output_recovered = ParticipantInitialState { s: host_seckeys[i] }
                .recover(&recovery_data)
                .unwrap();

            println!(
                "\t\tRecovered secret share {:x}",
                p_output_recovered.secshare.to_bytes()
            );
            println!("\n");
        }
    }

    #[test]
    fn success_generate_key() {
        const N: usize = 5;
        const T: usize = 3;

        let mut rng = OsRng;

        // --------------- INIT PHASE ---------------

        let parties: Vec<ParticipantInitialState> = (0..N)
            .map(|_| ParticipantInitialState::new(&mut rng))
            .collect();

        let host_seckeys: Vec<Scalar> = parties.iter().map(|p| p.s).collect();

        let host_keys: Vec<ProjectivePoint> = parties.iter().map(|p| p.get_host_key()).collect();

        let coordinator = CoordinatorInitialState::new(host_keys.clone(), T).unwrap();

        // --------------- DKG PHASE ---------------

        // ---- STEP 1 ----

        let mut msg1: Vec<ParticipantMsg1> = Vec::with_capacity(N);

        let parties: Vec<ParticipantStep1State> = parties
            .into_iter()
            .map(|p| {
                let (next, msg) = p.next((host_keys.clone(), T, [0u8; 32])).unwrap();
                msg1.push(msg);
                next.unwrap()
            })
            .collect();

        let (next_coordinator, msg1_resp) = coordinator.next(msg1).unwrap();
        let coordinator = next_coordinator.unwrap();

        // ---- STEP 2 ----

        let mut msg2: Vec<ParticipantMsg2> = Vec::with_capacity(N);

        let parties: Vec<ParticipantStep2State> = parties
            .into_iter()
            .map(|p| {
                let (next, msg) = p.next((msg1_resp.clone(), [0u8; 32])).unwrap();
                msg2.push(msg);
                next.unwrap()
            })
            .collect();

        let (_, (msg2_resp, output, _)) = coordinator.next(msg2).unwrap();

        println!("Coordinator DKG output:");
        println!(
            "\t\tGroup public key {:?}",
            output.threshold_pubkey.to_encoded_point(true).to_string()
        );
        println!("\n\n");

        // ---- CertEq ----

        for (i, p) in parties.into_iter().enumerate() {
            let (_, (p_output, recovery_data)) = p.next(msg2_resp.clone()).unwrap();
            assert_eq!(
                p_output.threshold_pubkey, output.threshold_pubkey,
                "Invalid group key for party {}",
                p_output.idx
            );

            assert_eq!(p_output.pubshares, output.pubshares);

            println!("Participant {} DKG output:", p_output.idx);
            println!(
                "\t\tGroup public key {:?}",
                p_output.threshold_pubkey.to_encoded_point(true).to_string()
            );
            println!("\t\tSecret share {:x}", p_output.secshare.to_bytes());

            let p_output_recovered =
                Participant::recover(&host_seckeys[i], &recovery_data).unwrap();

            println!(
                "\t\tRecovered secret share {:x}",
                p_output_recovered.secshare.to_bytes()
            );
            println!("\n");
        }
    }
}
