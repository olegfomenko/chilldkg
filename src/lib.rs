use anyhow::Result;
use k256::ProjectivePoint;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub mod crypto;
pub mod math;
pub mod msg;

pub trait ParticipantsState {
    fn next(msg: impl DeserializeOwned)
    -> Result<(Option<impl ParticipantsState>, impl Serialize)>;
    fn encryption_key(&self) -> ProjectivePoint;
}
