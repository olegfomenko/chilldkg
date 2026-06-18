use crate::msg::SessionParamsMsg;
use crate::{ParticipantInitialState, ParticipantParamsState, ParticipantState};
use k256::ProjectivePoint;

impl ParticipantState for ParticipantInitialState {
    type Message = SessionParamsMsg;
    type Next = ParticipantParamsState;
    type Output = ();

    fn next(self, msg: Self::Message) -> anyhow::Result<(Option<Self::Next>, Self::Output)> {
        let next_stage = ParticipantParamsState {
            idx: self.idx,
            s: self.s,
            host_pubkeys: msg.host_pubkeys,
            t: msg.t,
        };

        next_stage.validate_session_params()?;

        Ok((Some(next_stage), ()))
    }

    fn encryption_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.s
    }
}

impl ParticipantState for ParticipantParamsState {
    type Message = ();
    type Next = Self;
    type Output = ();

    fn next(self, _msg: Self::Message) -> anyhow::Result<(Option<Self::Next>, Self::Output)> {
        todo!("participant params state transition is not implemented yet")
    }

    fn encryption_key(&self) -> ProjectivePoint {
        self.host_pubkeys[self.idx]
    }
}
