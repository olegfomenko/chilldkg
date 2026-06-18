use crate::crypto::pop::SchnorrSignature;
use k256::{ProjectivePoint, Scalar};

/// Common participant inputs for starting a DKG session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionParamsMsg {
    /// Ordered participant host public keys P_i.
    pub host_pubkeys: Vec<ProjectivePoint>,

    /// Threshold t.
    pub t: u32,
}

/// Participant -> Coordinator, Step 1.
///
/// pmsg1_i = (C_i, pop_i, R_i, hat_u_{i,1}, ..., hat_u_{i,n})
#[derive(Clone, Debug)]
pub struct ParticipantMsg1 {
    /// Participant's VSS commitment C_i.
    /// C_i = (phi_{i,0}, ..., phi_{i,t-1})
    pub commitment: Vec<ProjectivePoint>,

    /// Proof of possession for the free coefficient a_{i,0}.
    pub pop: SchnorrSignature,

    /// Public encryption nonce R_i = r_i * G.
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
#[derive(Clone, Debug)]
pub struct CoordinatorMsg1 {
    /// Constant commitments C_{i,0}, one from each participant.
    pub coms_to_secrets: Vec<ProjectivePoint>,

    /// Aggregated non-constant commitments:
    /// Cbar_k = sum_i C_{i,k}, for k = 1,...,t-1.
    pub sum_coms_to_nonconst_terms: Vec<ProjectivePoint>,

    /// Proofs of possession pop_i.
    pub pops: Vec<SchnorrSignature>,

    /// Public encryption nonces R_i.
    pub pubnonces: Vec<ProjectivePoint>,

    /// Aggregated encrypted shares:
    /// hat_u_j = sum_i hat_u_{i,j}.
    pub enc_secshares: Vec<Scalar>,
}

/// Participant -> Coordinator, Step 2.
///
/// pmsg2_i = sigma_eq_i
#[derive(Clone, Debug)]
pub struct ParticipantMsg2 {
    /// CertEq signature over the equality-check transcript.
    pub sig: SchnorrSignature,
}

/// Coordinator -> Participants, Finalize.
///
/// cmsg2 = (sigma_eq_1, ..., sigma_eq_n)
#[derive(Clone, Debug)]
pub struct CoordinatorMsg2 {
    /// CertEq certificate, one signature from each participant.
    pub cert: Vec<SchnorrSignature>,
}

/// Optional Coordinator -> Participant investigation message.
///
/// Used only if participant step 2 fails and the participant needs blame data.
#[derive(Clone, Debug)]
pub struct CoordinatorInvestigationMsg {
    /// Encrypted partial secret shares from the first round.
    pub enc_partial_secshares: Vec<Scalar>,

    /// Partial public shares used for investigation.
    pub partial_pubshares: Vec<ProjectivePoint>,
}

/// Recovery data is not a coordinator message by itself, but ChillDKG returns it
/// after finalization:
///
/// recovery_data = eq_input || cert
#[derive(Clone, Debug)]
pub struct RecoveryData {
    pub threshold: u32,
    pub sum_commitment: Vec<ProjectivePoint>,
    pub host_pubkeys: Vec<ProjectivePoint>,
    pub pubnonces: Vec<ProjectivePoint>,
    pub enc_secshares: Vec<Scalar>,
    pub cert: Vec<SchnorrSignature>,
}
