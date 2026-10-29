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
            "02D772A09F5F675783D275ED9F6AAEDB2ECCBC74171B37AC23AE3BBD9D7AE2CDAA",
        )
        .unwrap(),
        pubshares: vec![
            parse_point_hex("039EE3335AF48DFE23702AB353F4AF20D401F67A130DF783CC8457323A860A2FB4")
                .unwrap(),
            parse_point_hex("0284DC4AB2CB78A621EB87FA1F14BCE2B725AFEAAC981ADCBAFF5CC2D417D2A63A")
                .unwrap(),
            parse_point_hex("036441EC2D4C1266201CD89B69549A2F5B2188612A0D434153E625FB38173DD509")
                .unwrap(),
        ],
    }
}

/// The signers' public nonces from the `sign_verify` vectors, indexed by
/// participant id.
fn pubnonces() -> [PubNonce; 3] {
    [
        "028213A4194E3A70790607123B9A6D7A3363A62B8117C2DA1AFB40DE5B0EE4E06002EBAD9B1A145E503BCF05A4D05DB99E6B1A30098F26FA6305CDE8D59B32DBAC43",
        "02FB84325E2E570263DD8C1772FD17E810C0E938EEBFD0FA4AF39FB58507A5D48003FAD5DDF645F8197F9336480F34D928C2F69B1C44D88A8B1C57E93206CBDDF23D",
        "03B64B264AD117E20AD57BDC5A7EA33701CF1D6C7A7C19A946D082AA7746EFA1D102AD5BDCE55A642497B0932D584E26433722853F1D43387ACEDB4E9559D7CE0FB8",
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
    for ids in [vec![0, 1], vec![2, 1, 0], vec![1, 2], vec![0, 1, 2]] {
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
            Value("The ids list contains duplicate elements.".into()),
        ),
        // A signer id is outside the valid range [0, n-1]
        (
            vec![3, 1],
            [0, 1, 2],
            None,
            Value("The id at index 0 must satisfy 0 <= id <= n - 1.".into()),
        ),
        // Signer set's public shares do not match the threshold public key
        (
            vec![0, 1, 2],
            [0, 2, 1],
            None,
            Value(
                "The provided key material is incorrect: the public shares do not match the threshold public key."
                    .into(),
            ),
        ),
        // Fewer signers than the threshold t
        (
            vec![0],
            [0, 1, 2],
            None,
            Value("The number of signers must satisfy t <= u <= n.".into()),
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
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    // (signers as (id, psig), tweaks, expected signature)
    for (psigs, tweaks_hex, expected) in [
        // Minimum threshold subset of signers, no tweaks
        (
            vec![
                (
                    0,
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
                ),
                (
                    1,
                    "F6FC1814C8BDF89041FE10F91AD306CEF0E90CBD5003BE216D6C40B891469016",
                ),
            ],
            vec![],
            "B89B25226C5ED33AD67F5BD7C750516ED05DA326E36D9878A26C385B891E9A65B478634CE7387577AA8FD15DE92959169A77777F79A02141C2D0AA6BEC394FDD",
        ),
        // Signer set in descending order, so the identifiers must be sorted before hashing
        (
            vec![
                (
                    2,
                    "4636795DA140BB1DD14B7FA73FE3FD0CC24A9C08786ABE1CCBAAC776BC64F34C",
                ),
                (
                    1,
                    "2C1B45EB5E01613D4ACC325D2A3A5677F60750ADC9706BCCCDAFD144B45C72AF",
                ),
                (
                    0,
                    "763E4353210C86236AEA8E073FAFE564981ED70BCF096CFBECCE88B5F24F0EC9",
                ),
            ],
            vec![],
            "51A7FA5FFE4739217B46AE2D8570EF354AB19663AA27358F9460E6184048CB40E890029C204EA27E8702400BA9CE38E95070C3C210E496E586292171631074C4",
        ),
        // Aggregation with three tweaks applied (one plain, two x-only)
        (
            vec![
                (
                    0,
                    "AE2818DFC14FD4903FBA3778BDF27C0B3B5863AEEFDDA6540A73A22C4E734D10",
                ),
                (
                    1,
                    "21780564C5FF2FBC16724039E98740A7E33CECBFDF11EC52300BA12C278B4531",
                ),
            ],
            vec![
                (
                    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                    false,
                ),
                (
                    "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
                    true,
                ),
                (
                    "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
                    true,
                ),
            ],
            "95CB034D179622277EA691064988749ADDADFCFF36E0542B288F0D36CE5DACD173239D0A5A4B0BD8721E2286EBCB11B6D62174BAFF8D17E0191B9B9CDC8156AE",
        ),
        // All signers participate, no tweaks
        (
            vec![
                (
                    0,
                    "763E4353210C86236AEA8E073FAFE564981ED70BCF096CFBECCE88B5F24F0EC9",
                ),
                (
                    1,
                    "2C1B45EB5E01613D4ACC325D2A3A5677F60750ADC9706BCCCDAFD144B45C72AF",
                ),
                (
                    2,
                    "4636795DA140BB1DD14B7FA73FE3FD0CC24A9C08786ABE1CCBAAC776BC64F34C",
                ),
            ],
            vec![],
            "51A7FA5FFE4739217B46AE2D8570EF354AB19663AA27358F9460E6184048CB40E890029C204EA27E8702400BA9CE38E95070C3C210E496E586292171631074C4",
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
        // Number of partial signatures does not match the number of signers
        (
            vec![0, 1],
            vec![
                (
                    0,
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
                ),
                (
                    0,
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
                ),
                (
                    1,
                    "F6FC1814C8BDF89041FE10F91AD306CEF0E90CBD5003BE216D6C40B891469016",
                ),
            ],
            Value("The psigs and ids lists must have the same length.".into()),
        ),
        // Two partial signatures under the same id, one signer missing (not a
        // reference vector)
        (
            vec![0, 1],
            vec![
                (
                    0,
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
                ),
                (
                    0,
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
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
                    "4283B4C7E1858318976E3F9B31A9ADB85671953DD6639CDFAA9B964CA50D4039",
                ),
                (
                    1,
                    "F6FC1814C8BDF89041FE10F91AD306CEF0E90CBD5003BE216D6C40B891469016",
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
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
                ),
                (
                    1,
                    "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
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
