//! # chilldkg-rs
//!
//! Rust implementation of ChillDKG (BIP-FROST-DKG) with optional FROST
//! signing (BIP-FROST-signing) over its output.
//!
//! - [`dkg`]: the distributed key generation protocol — the high-level
//!   [`Participant`](dkg::Participant) / [`Coordinator`](dkg::Coordinator)
//!   drivers, the underlying state machines, wire messages and recovery.
//! - [`sign`] (feature `signing`): threshold Schnorr signing with the DKG output.
//! - [`crypto`]: the shared primitives both are built on.

pub mod crypto;
pub mod dkg;
#[cfg(feature = "signing")]
pub mod sign;

#[cfg(test)]
mod tests {
    use crate::dkg::coordinator::{CoordinatorInitialState, CoordinatorState};
    use crate::dkg::msg::{ParticipantMsg1, ParticipantMsg2};
    use crate::dkg::party::{
        ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
    };
    use crate::dkg::{Coordinator, Participant};
    #[cfg(feature = "signing")]
    use crate::sign;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    #[test]
    fn success_generate_key_and_sign() {
        const T: usize = 3;

        let mut rng = OsRng;

        // --------------- INIT PHASE ---------------
        let (s1, mut p1) = Participant::new(&mut rng);
        let (s2, mut p2) = Participant::new(&mut rng);
        let (s3, mut p3) = Participant::new(&mut rng);
        let (s4, mut p4) = Participant::new(&mut rng);
        let (s5, mut p5) = Participant::new(&mut rng);

        let host_seckeys = [s1, s2, s3, s4, s5];

        let host_keys: Vec<ProjectivePoint> = host_seckeys
            .iter()
            .map(|k| ProjectivePoint::GENERATOR * k.as_ref())
            .collect();

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

        #[cfg(feature = "signing")]
        let mut signers = [
            sign::Signer::new(&res1.0),
            sign::Signer::new(&res2.0),
            sign::Signer::new(&res3.0),
        ];

        for (i, res) in [res1, res2, res3, res4, res5].iter().enumerate() {
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

            let p_output_recovered = Participant::recover(&host_seckeys[i], recovery_data).unwrap();

            println!(
                "\t\tRecovered secret share {:x}",
                p_output_recovered.secshare.to_bytes()
            );
            println!("\n");
        }

        // Create and verify a signature with 3 of 5.
        #[cfg(feature = "signing")]
        {
            use rand_core::RngCore;
            use sha2::{Digest, Sha256};

            let msg: Vec<u8> = Sha256::digest(b"hello world").to_vec();
            let tweaks = vec![sign::Tweak::xonly([0x42u8; 32])];

            // Signers generate their nonces before the message and the tweaks
            // are known; both reach every party only at the signing round.
            let mut coordinator = sign::Coordinator::new(&output);

            // Round 1: every signer publishes a nonce.
            let mut pubnonces = Vec::new();
            for signer in &mut signers {
                let mut random = [0u8; 32];
                rng.fill_bytes(&mut random);
                pubnonces.push(signer.step1((None, None, random)).unwrap());
            }
            let relayed = coordinator.step1(pubnonces).unwrap();

            // Round 2: every signer produces its partial signature.
            let psigs: Vec<_> = signers
                .iter_mut()
                .map(|signer| {
                    signer
                        .finalize((relayed.clone(), msg.clone(), tweaks.clone()))
                        .unwrap()
                })
                .collect();
            let sig = coordinator
                .step2((psigs, msg.clone(), tweaks.clone()))
                .unwrap();

            assert!(signers.iter().all(sign::Signer::is_successful));
            assert!(coordinator.is_successful());
            sign::verify(&output.threshold_pubkey, sig, &msg, &tweaks).unwrap();
            assert!(sign::verify(&output.threshold_pubkey, sig, &msg, &[]).is_err());
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
