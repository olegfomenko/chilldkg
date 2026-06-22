pub mod coordinator;
pub mod crypto;
pub mod math;
pub mod msg;
pub mod party;

#[cfg(test)]
mod tests {
    use crate::coordinator::{CoordinatorInitialState, CoordinatorState};
    use crate::msg::{ParticipantMsg1, ParticipantMsg2};
    use crate::party::{
        ParticipantInitialState, ParticipantParamsState, ParticipantState, ParticipantStep1State,
        ParticipantStep2State,
    };
    use k256::ProjectivePoint;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;

    #[test]
    fn success_generate_key() {
        const N: usize = 5;
        const T: usize = 3;

        let mut rng = OsRng;

        // ----- INIT PHASE -----

        let parties = vec![
            ParticipantInitialState::new(0, &mut rng),
            ParticipantInitialState::new(1, &mut rng),
            ParticipantInitialState::new(2, &mut rng),
            ParticipantInitialState::new(3, &mut rng),
            ParticipantInitialState::new(4, &mut rng),
        ];

        let host_keys: Vec<ProjectivePoint> = parties.iter().map(|p| p.get_host_key()).collect();

        let coordinator = CoordinatorInitialState::new(host_keys.clone(), T).unwrap();

        let parties: Vec<ParticipantParamsState> = parties
            .into_iter()
            .map(|p| p.next((host_keys.clone(), T)).unwrap().0.unwrap())
            .collect();

        // ----- DKG PHASE -----

        // STEP 1

        let mut msg1: Vec<ParticipantMsg1> = Vec::with_capacity(N);

        let parties: Vec<ParticipantStep1State> = parties
            .into_iter()
            .map(|p| {
                let (next, msg) = p.next([0u8; 32]).unwrap();
                msg1.push(msg);
                next.unwrap()
            })
            .collect();

        let (next_coordinator, msg1_resp) = coordinator.next(msg1).unwrap();
        let coordinator = next_coordinator.unwrap();

        // STEP 2

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

        // FINISH (CertEq)

        for p in parties {
            let (_, (p_output, _)) = p.next(msg2_resp.clone()).unwrap();
            assert_eq!(
                p_output.threshold_pubkey, output.threshold_pubkey,
                "Invalid group key for party {}",
                p_output.idx
            );

            println!("Participant {} DKG output:", p_output.idx);
            println!(
                "\t\tGroup public key {:?}",
                p_output.threshold_pubkey.to_encoded_point(true).to_string()
            );
            println!("\t\tSecret share {:x}", p_output.secshare.to_bytes());
            println!("\n");
        }
    }
}
