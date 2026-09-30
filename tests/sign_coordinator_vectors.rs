#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{parse_hex_array, parse_point_hex, parse_pubnonce_hex, parse_scalar_hex};
use chilldkg_rs::dkg::msg::CoordinatorDKGOutput;
use chilldkg_rs::sign::errors::SignError::{InvalidContribution, Value};
use chilldkg_rs::sign::{
    CoordinatorInitialState, CoordinatorState, CoordinatorStep1State, PubNonce, Tweak,
};
use k256::ProjectivePoint;

pub mod common;

fn key_material() -> CoordinatorDKGOutput {
    CoordinatorDKGOutput {
        t: 2,
        threshold_pubkey: parse_point_hex(
            "03B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237",
        )
        .unwrap(),
        pubshares: vec![
            parse_point_hex("022B02109FBCFB4DA3F53C7393B22E72A2A51C4AFBF0C01AAF44F73843CFB4B74B")
                .unwrap(),
            parse_point_hex("02EC6444271D791A1DA95300329DB2268611B9C60E193DABFDEE0AA816AE512583")
                .unwrap(),
            parse_point_hex("03113F810F612567D9552F46AF9BDA21A67D52060F95BD4A723F4B60B1820D3676")
                .unwrap(),
        ],
    }
}

/// The signers' public nonces from the `sign_verify` vectors, indexed by
/// participant id.
fn pubnonces() -> [PubNonce; 3] {
    [
        "03295054A682346C6A55DC184F463E48FEB38B23659E84A725604E570044487192021F8C6DC6DF28F187E52F796A4C189867797DB7D9E86796586F5A5FB6D4006597",
        "028D0DD00F4DD83ACE58ECA8197EC7CD0B94C9F53081E6394168EB37BE5DAAE5B7025224420D478FA5230C172FD625930B34A2343B335EAF2D3080D7B8DA71245CAE",
        "022A6084A7614CDBA50397DFFC922AFB40CB848AE3341D5EA2F6E8BEA5ECAC1B9D02298852FE90C793305C4B7E02F80DC04BD29CBEA7FD99972993172AE030384151",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap())
}

fn tweaks(tweaks: &[(&str, bool)]) -> Vec<Tweak> {
    tweaks
        .iter()
        .map(|(hex, is_xonly)| Tweak {
            value: parse_hex_array(hex).unwrap(),
            is_xonly: *is_xonly,
        })
        .collect()
}

#[test]
fn test_coordinator_step1_passes() {
    let key = key_material();
    let pubnonces = pubnonces();

    // Signer subsets from the `sign_verify` valid vectors.
    for ids in [vec![0, 1], vec![1, 0], vec![1, 2], vec![0, 1, 2]] {
        let input: Vec<_> = ids.iter().map(|&id| (id, pubnonces[id].clone())).collect();

        let initial = CoordinatorInitialState::new(&key);
        let (next, relayed) = initial.next(input.clone()).unwrap();

        // The list is relayed as received and remembered by id.
        assert_eq!(relayed, input);
        let next = next.unwrap();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort_unstable();
        assert!(next.pubnonces.keys().eq(sorted_ids.iter()));
        for (id, pubnonce) in &input {
            assert_eq!(&next.pubnonces[id], pubnonce);
        }
    }
}

#[test]
fn test_coordinator_step1_rejects_invalid_inputs() {
    let key = key_material();
    let pubnonces = pubnonces();
    let identity = PubNonce {
        R1: ProjectivePoint::IDENTITY,
        R2: ProjectivePoint::IDENTITY,
    };

    // (ids, coordinator pubshares as pool indices, nonce override as (id, nonce), error)
    for (ids, pubshares, nonce_override, expected_error) in [
        // Signer set contains a duplicate id
        (
            vec![0, 1, 1],
            [0, 1, 2],
            None,
            Value("The participant identifier list contains duplicate elements.".into()),
        ),
        // A signer id is outside the valid range [0, n-1]
        (
            vec![3, 1],
            [0, 1, 2],
            None,
            Value("The participant identifier at index 0 is out of range.".into()),
        ),
        // Signer set's public shares do not match the threshold public key
        (
            vec![0, 1],
            [0, 2, 2],
            None,
            Value("The provided key material is incorrect.".into()),
        ),
        // Fewer signers than the threshold t
        (
            vec![0],
            [0, 1, 2],
            None,
            Value("The number of signers must be between t and n.".into()),
        ),
        // A signer contributed the identity as its public nonce (not a
        // reference vector: the reference only rejects this at decoding)
        (
            vec![0, 1],
            [0, 1, 2],
            Some((1, identity)),
            InvalidContribution {
                participant: 1,
                message: "invalid pubnonce".into(),
            },
        ),
    ] {
        let mut input: Vec<_> = ids
            .iter()
            .map(|&id| (id, pubnonces[id % 3].clone()))
            .collect();
        if let Some((id, nonce)) = nonce_override {
            input.iter_mut().find(|(i, _)| *i == id).unwrap().1 = nonce;
        }

        let initial = CoordinatorInitialState {
            t: key.t,
            pubshares: pubshares.iter().map(|&i| key.pubshares[i]).collect(),
            threshold_pubkey: key.threshold_pubkey,
        };
        let err = initial.next(input).err().unwrap();
        assert_eq!(err, expected_error);
    }
}

#[test]
fn test_coordinator_finalize_passes() {
    let key = key_material();
    let pubnonces = pubnonces();
    // The `sig_agg` vectors: their aggregate nonces are the sums of the
    // `sign_verify` public nonces, so the partial signatures verify against
    // the individual nonces and the coordinator can run its full round 2.
    let msg =
        hex::decode("599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869").unwrap();

    // (signers as (id, psig), tweaks, expected signature)
    for (psigs, tweaks_hex, expected) in [
        // Minimum threshold subset of signers (t=2 of n=3), no tweaks
        (
            vec![
                (
                    0,
                    "911E1C3821D5C4314C32BF7B312C39B7D9A2C54FB3EF1E3349395299A781ED93",
                ),
                (
                    1,
                    "6F6E24B9ADD50F74B329F27A6EC30250A89938AD8C9CBE0235BD8EB8EAEA9EE2",
                ),
            ],
            vec![],
            "5527965735029EAD5BBF977E71E06B601589E22E241F11DD68F420E75FE4AC63008C40F1CFAAD3A5FF5CB1F59FEF3C09C78D211691433BF9BF2482C5C2364B34",
        ),
        // Signer order does not affect the aggregate signature: partial signatures are summed, so this matches the first valid case
        (
            vec![
                (
                    1,
                    "6F6E24B9ADD50F74B329F27A6EC30250A89938AD8C9CBE0235BD8EB8EAEA9EE2",
                ),
                (
                    0,
                    "911E1C3821D5C4314C32BF7B312C39B7D9A2C54FB3EF1E3349395299A781ED93",
                ),
            ],
            vec![],
            "5527965735029EAD5BBF977E71E06B601589E22E241F11DD68F420E75FE4AC63008C40F1CFAAD3A5FF5CB1F59FEF3C09C78D211691433BF9BF2482C5C2364B34",
        ),
        // Aggregation with three tweaks applied (one x-only, two plain)
        (
            vec![
                (
                    0,
                    "BFFDAC5F3CB017F2DEF06D1D7703A50875CF18D4F9CFCFE1FD0261D1250655A8",
                ),
                (
                    1,
                    "1792D36FD56EBA5A303C7F7E367B3EB48D6F631258FF396C36F4AA7D268039FA",
                ),
            ],
            vec![
                (
                    "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
                    true,
                ),
                (
                    "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
                    false,
                ),
                (
                    "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
                    false,
                ),
            ],
            "6D5558EB783A023F2A09BDE65D3E9DB79928702D4143BCFD69C2074C9A143F5108D818ADC9BD3AA2B9DC669B66AD9EF420FDBF97558DB65D9528C27FBEB3308E",
        ),
        // All n=3 signers participate, no tweaks
        (
            vec![
                (
                    0,
                    "96CCC80C315D5F61DA34B6FF7FB86CFB642FD1410089B7B6CE205C50C22891CF",
                ),
                (
                    1,
                    "33E5776846D493D422F995B676A73ACE7897345081DC569B2FE3BC0940F72DD6",
                ),
                (
                    2,
                    "B907873BD954272E5B3E97DAC1CC93D6DF1BF8161A69D2C548B3C1D405CF1C2C",
                ),
            ],
            vec![],
            "12FADDB3E8C8A8B95E6C36E5B33CB657A840A2EC1DDABCC19D05E99FD71F637583B9C6B051861A64586CE490B82C3BA2013420C0ED8740DB86E57BA138B89A90",
        ),
    ] {
        let input: Vec<_> = psigs
            .iter()
            .map(|&(id, _)| (id, pubnonces[id].clone()))
            .collect();
        let psigs: Vec<_> = psigs
            .iter()
            .map(|&(id, psig)| (id, parse_scalar_hex(psig).unwrap()))
            .collect();

        let initial = CoordinatorInitialState::new(&key);
        let (next, _) = initial.next(input).unwrap();
        let (next, sig) = next
            .unwrap()
            .next((psigs, msg.clone(), tweaks(&tweaks_hex)))
            .unwrap();
        assert!(next.is_none());
        assert_eq!(hex::encode_upper(sig), expected);
    }
}

#[test]
fn test_coordinator_finalize_rejects_invalid_inputs() {
    let key = key_material();
    let pubnonces = pubnonces();
    let msg =
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    // (signer ids fixed at round 1, partial signatures as (id, psig), error)
    for (ids, psigs, expected_error) in [
        // Partial signatures do not come from the signer set fixed at round 1
        (
            vec![0, 1],
            vec![
                (
                    0,
                    "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
                ),
                (
                    2,
                    "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
                ),
            ],
            Value("invalid list of signer ids".into()),
        ),
        // Negated partial signature fails the verification equation
        (
            vec![0, 1],
            vec![
                (
                    0,
                    "FB9C49E9C0A16F2F5F6BD25550EC8652431DAE39706F3C157D9F9E5F92BE911B",
                ),
                (
                    1,
                    "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
                ),
            ],
            InvalidContribution {
                participant: 0,
                message: "invalid partial signature".into(),
            },
        ),
        // A valid partial signature checked against the wrong signer fails the verification equation
        (
            vec![0, 1],
            vec![
                (
                    0,
                    "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
                ),
                (
                    1,
                    "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
                ),
            ],
            InvalidContribution {
                participant: 1,
                message: "invalid partial signature".into(),
            },
        ),
    ] {
        let psigs: Vec<_> = psigs
            .iter()
            .map(|&(id, psig)| (id, parse_scalar_hex(psig).unwrap()))
            .collect();

        // Coordinator after round 1 with the vector's nonces.
        let state = CoordinatorStep1State {
            t: key.t,
            pubshares: key.pubshares.clone(),
            threshold_pubkey: key.threshold_pubkey,
            pubnonces: ids.iter().map(|&id| (id, pubnonces[id].clone())).collect(),
        };
        let err = state.next((psigs, msg.clone(), vec![])).err().unwrap();
        assert_eq!(err, expected_error);
    }
}
