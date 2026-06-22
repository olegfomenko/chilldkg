use crate::crypto::pop::SchnorrSignature;
use k256::{ProjectivePoint, Scalar};

/// Participant -> Coordinator, Step 1.
///
/// pmsg1_i = (C_i, pop_i, R_i, hat_u_{i,1}, ..., hat_u_{i,n})
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantMsg1 {
    /// Participant's VSS commitment.
    ///
    /// Math: `C_i = (C_{i,0}, ..., C_{i,t-1})`.
    pub commitment: Vec<ProjectivePoint>,

    /// Proof of possession for the free coefficient a_{i,0}.
    pub pop: SchnorrSignature,

    /// Public encryption nonce.
    ///
    /// Math: `R_i = r_i * G`.
    pub pubnonce: ProjectivePoint,

    /// Encrypted shares hat_u_{i,j}, one for each recipient j.
    pub enc_shares: Vec<Scalar>,
}

/// Coordinator -> Participants, Step 1.
///
/// cmsg1 = (
///   C_{1,0}, ..., C_{n,0},
///   Cbar_1, ..., Cbar_{t-1},
///   pop_1, ..., pop_n,
///   R_1, ..., R_n,
///   hat_u_1, ..., hat_u_n
/// )
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorMsg1 {
    /// Constant commitments to participant secrets.
    ///
    /// Math: this is `(C_{1,0}, ..., C_{n,0})`.
    pub coms_to_secrets: Vec<ProjectivePoint>,

    /// Aggregated non-constant commitments.
    ///
    /// Math: `Cbar_k = sum_i C_{i,k}` for `k = 1, ..., t - 1`.
    pub sum_coms_to_nonconst_terms: Vec<ProjectivePoint>,

    /// Proofs of possession pop_i.
    pub pops: Vec<SchnorrSignature>,

    /// Public encryption nonces.
    ///
    /// Math: this is `(R_1, ..., R_n)`.
    pub pubnonces: Vec<ProjectivePoint>,

    /// Aggregated encrypted shares:
    /// hat_u_j = sum_i hat_u_{i,j}.
    pub enc_secshares: Vec<Scalar>,
}

/// Participant -> Coordinator, Step 2.
///
/// pmsg2_i = sigma_eq_i
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantMsg2 {
    /// CertEq signature over the equality-check transcript.
    pub sig: SchnorrSignature,
}

/// Coordinator -> Participants, Finalize.
///
/// cmsg2 = (sigma_eq_1, ..., sigma_eq_n)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorMsg2 {
    /// CertEq certificate, one signature from each participant.
    pub cert: Vec<SchnorrSignature>,
}

/// Recovery data is not a coordinator message by itself, but ChillDKG returns it
/// after finalization:
///
/// recovery_data = transcript || cert
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryData {
    pub transcript: Vec<u8>,
    pub cert: Vec<SchnorrSignature>,
}
