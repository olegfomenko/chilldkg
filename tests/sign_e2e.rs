use crate::common::verify_bip340;
use chilldkg_rs::errors::ChillDkgError::{FaultyParticipant, Value};
use chilldkg_rs::sign::{Signer, Tweak, Verifier, sample_nonce};
use chilldkg_rs::{Coordinator, Participant};
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;

pub mod common;

#[test]
fn test_dkg_then_sign_passes() {
    const N: usize = 5;
    const T: usize = 3;
    let mut rng = OsRng;

    // DKG.
    let (host_seckeys, mut participants): (Vec<_>, Vec<_>) =
        (0..N).map(|_| Participant::new(&mut rng)).unzip();
    let host_pubkeys: Vec<ProjectivePoint> = host_seckeys
        .iter()
        .map(|k| ProjectivePoint::GENERATOR * k.as_ref())
        .collect();
    let mut coordinator = Coordinator::new(host_pubkeys.clone(), T).unwrap();
    let pmsgs1 = participants
        .iter_mut()
        .map(|p| p.step1((host_pubkeys.clone(), T, [0u8; 32])).unwrap())
        .collect();
    let cmsg1 = coordinator.step1(pmsgs1).unwrap();
    let pmsgs2 = participants
        .iter_mut()
        .map(|p| p.step2((cmsg1.clone(), [0u8; 32])).unwrap())
        .collect();
    let (cmsg2, coordinator_output, _) = coordinator.step2(pmsgs2).unwrap();
    let outputs: Vec<_> = participants
        .iter_mut()
        .map(|p| p.finalize(cmsg2.clone()).unwrap().0)
        .collect();

    // Participants 4, 1 and 2 sign `msg` under a BIP341 x-only tweak.
    let signer_ids = [4usize, 1, 2];
    let msg = b"chilldkg frost end-to-end";
    let tweaks = [Tweak::xonly([0x42u8; 32])];
    let verifier = Verifier::from(&coordinator_output);

    // Round 1: nonces.
    let (pubnonces, secnonces): (Vec<_>, Vec<_>) = signer_ids
        .iter()
        .map(|&id| {
            let out = &outputs[id];
            let (pubnonce, secnonce) = sample_nonce(
                &mut rng,
                Some(&out.secshare),
                Some(&out.pubshares[id]),
                Some(&out.threshold_pubkey),
                Some(msg),
                None,
            )
            .unwrap();
            ((id, pubnonce), secnonce)
        })
        .unzip();

    // Round 2: partial signatures.
    let psigs: Vec<_> = secnonces
        .into_iter()
        .zip(&signer_ids)
        .map(|(secnonce, &id)| {
            Signer::from(&outputs[id])
                .sign(msg, &tweaks, secnonce, &pubnonces)
                .unwrap()
        })
        .collect();
    let contributions: Vec<_> = pubnonces
        .iter()
        .zip(&psigs)
        .map(|((id, pubnonce), psig)| (*id, pubnonce.clone(), *psig))
        .collect();

    let sig = verifier
        .verify_and_aggregate(&contributions, msg, &tweaks)
        .unwrap();
    verify_bip340(sig, &verifier.signing_pubkey(&tweaks).unwrap(), msg).unwrap();
    assert!(verify_bip340(sig, &coordinator_output.threshold_pubkey, msg).is_err());

    // A tampered partial signature is attributed to its signer.
    let mut tampered = contributions.clone();
    tampered[1].2 += Scalar::ONE;
    assert_eq!(
        verifier
            .verify_and_aggregate(&tampered, msg, &tweaks)
            .err()
            .unwrap(),
        FaultyParticipant {
            participant: signer_ids[1],
            message: "invalid partial signature".into(),
        }
    );
    assert!(
        !verifier
            .partial_verify(&tampered[1].2, signer_ids[1], &pubnonces, msg, &tweaks)
            .unwrap()
    );

    // Fewer than t signers are rejected.
    assert_eq!(
        verifier
            .verify_and_aggregate(&contributions[..T - 1], msg, &tweaks)
            .err()
            .unwrap(),
        Value("The number of signers must be between t and n.".into())
    );
}
