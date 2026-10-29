#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{parse_hex_array, parse_point_hex, parse_pubnonce_hex, parse_scalar_hex};
use chilldkg_rs::crypto::tweak::TweakContext;
use chilldkg_rs::dkg::msg::CoordinatorDKGOutput;
use chilldkg_rs::sign::coordinator::verify::{challenge, signing_nonce};
use chilldkg_rs::sign::errors::SignError::Value;
use chilldkg_rs::sign::{
    PartialSignature, PubNonce, SecNonce, SignerState, SignerStep1State, Tweak, aggr_pubnonces,
    partial_verify,
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

/// A secret nonce (`k_1 || k_2`) from the vectors.
fn secnonce(hex: &str) -> SecNonce {
    SecNonce {
        k1: parse_scalar_hex(&hex[..64]).unwrap(),
        k2: parse_scalar_hex(&hex[64..]).unwrap(),
    }
}

/// Verifies one partial signature the way the coordinator's round 2 does:
/// derive `(b, R, e)` for the session, then check the equation.
fn verify_one(
    key: &CoordinatorDKGOutput,
    psig: &PartialSignature,
    id: usize,
    pubnonces: &[(usize, PubNonce)],
    msg: &[u8],
) -> chilldkg_rs::sign::Result<()> {
    let ids: Vec<usize> = pubnonces.iter().map(|(id, _)| *id).collect();
    let tweak_ctx = TweakContext::new(key.threshold_pubkey)
        .apply_all(&[])
        .unwrap();
    let (b, R) = signing_nonce(
        &ids,
        aggr_pubnonces(pubnonces.iter().map(|(_, n)| n)),
        &tweak_ctx,
        msg,
    )
    .unwrap();
    let e = challenge(&R, &tweak_ctx, msg).unwrap();
    let (_, pubnonce) = pubnonces.iter().find(|(i, _)| *i == id).unwrap();
    partial_verify(
        psig,
        id,
        pubnonce,
        &key.pubshares[id],
        &ids,
        &tweak_ctx,
        b,
        &R,
        e,
    )
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
fn test_sign_passes() {
    let key = key_material();
    // Secret material of participants 0, 1 and 2.
    let secshares = [
        "53442FA9BD72EEA0A42DF6F2D2D76A2C0D3A3DFA2BE2F820F41ADE976B8259FB",
        "5A7F9BD41F4B544664C54D777D43303CB5302434F9903B9B552C4E552BF02201",
        "61BB07FE8123B9EC255CA3FC27AEF64D5D260A6FC73D7F15B63DBE12EC5DEA07",
    ]
    .map(|h| parse_scalar_hex(h).unwrap());
    let secnonces = [
        "874A212D2DF14B0E55D5E9B86B0B6530A83BA59785303E333AB9F6193289D4A3B5DE529495EC16F25C1452C2732363C38623725EAE7BBCA47BD1AB43B3E21792",
        "7B3932D72200FDDD616B2CB6DDD9B263D566DC290FD6F6965BB01A813F05BA971B5C79608E807BDA020227517B70DC848479BC9139803A489BC58C5E9E5F9F10",
        "3D85A0D7947B3445C60CBCB8CFDA98ECF10FCF45AF8DF3C7026EC127E9DA798D9C857374248DA423F9071D6A646128E6EA09A01363033C09E46ED079D6698DE0",
    ];
    // Public nonces of participants 0, 1 and 2, plus (index 3) one that
    // cancels the first two so the aggregate nonce is the point at infinity.
    let pubnonce_pool = [
        "028213A4194E3A70790607123B9A6D7A3363A62B8117C2DA1AFB40DE5B0EE4E06002EBAD9B1A145E503BCF05A4D05DB99E6B1A30098F26FA6305CDE8D59B32DBAC43",
        "02FB84325E2E570263DD8C1772FD17E810C0E938EEBFD0FA4AF39FB58507A5D48003FAD5DDF645F8197F9336480F34D928C2F69B1C44D88A8B1C57E93206CBDDF23D",
        "03B64B264AD117E20AD57BDC5A7EA33701CF1D6C7A7C19A946D082AA7746EFA1D102AD5BDCE55A642497B0932D584E26433722853F1D43387ACEDB4E9559D7CE0FB8",
        "0358D346E23685E092E143BD203EEC8597131390B1300E9466C9B741EC65FCCFC6039C9B5D46EF571F128C657306C86AC24E2E58CAC742788645A29E1CC0CEFFB316",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap());
    let msgs = [
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
        "",
        "2626262626262626262626262626262626262626262626262626262626262626262626262626",
    ]
    .map(|h| hex::decode(h).unwrap());

    // (signers as (id, pubnonce pool index), tweaks, msg index, signer id, expected psig)
    for (signers, tweaks_hex, msg_index, signer_id, expected) in [
        // Minimum threshold subset of signers
        (
            vec![(0, 0), (1, 1)],
            vec![],
            0,
            0,
            "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
        ),
        // Signer set in descending order, so the identifiers must be sorted before hashing
        (
            vec![(2, 2), (1, 1), (0, 0)],
            vec![],
            0,
            1,
            "2C1B45EB5E01613D4ACC325D2A3A5677F60750ADC9706BCCCDAFD144B45C72AF",
        ),
        // A different threshold subset gives a different partial signature, since the Lagrange coefficients depend on the signer set
        (
            vec![(1, 1), (2, 2)],
            vec![],
            0,
            1,
            "402438A10A54BC3B94AC3EBD8B95B540474E6AE5730B78A9FE11319C48654A9D",
        ),
        // Aggregate nonce is the point at infinity, so the final nonce point falls back to the generator G
        (
            vec![(0, 0), (1, 1), (2, 3)],
            vec![],
            0,
            0,
            "C874C21E5E2F850494E61433C9A5DBAEDA14588DBC0BE3EA564611FE859226B3",
        ),
        // Empty message
        (
            vec![(0, 0), (1, 1)],
            vec![],
            1,
            0,
            "CADAD81BC9AD421790DB199BAEE5FC7FBE37D7FD5294474D8732309F3A78B658",
        ),
        // Non-standard message length (38 bytes)
        (
            vec![(0, 0), (1, 1)],
            vec![],
            2,
            0,
            "ED73261B0C4F0CAA222B66C8E96C36B1F2374EEF808578E4580AAD7D2CCD800A",
        ),
        // Single x-only tweak (used for BIP341 Taproot)
        (
            vec![(0, 0), (1, 1)],
            vec![(
                "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                true,
            )],
            0,
            0,
            "F9D628F22F0CE83B04E888971472596F70754B5044473853F2464C6DD7A8091B",
        ),
        // Single plain tweak (used for BIP32 derivation)
        (
            vec![(0, 0), (1, 1)],
            vec![(
                "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                false,
            )],
            0,
            0,
            "F9D628F22F0CE83B04E888971472596F70754B5044473853F2464C6DD7A8091B",
        ),
        // A plain tweak followed by an x-only tweak
        (
            vec![(0, 0), (1, 1)],
            vec![
                (
                    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                    false,
                ),
                (
                    "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
                    true,
                ),
            ],
            0,
            0,
            "55E01D1976FF7A236BA2A0051CFAE6DDBF23D5B5B3159E8C717E380AB8C32CBB",
        ),
        // Four tweaks alternating x-only and plain
        (
            vec![(0, 0), (1, 1)],
            vec![
                (
                    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                    true,
                ),
                (
                    "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
                    false,
                ),
                (
                    "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
                    true,
                ),
                (
                    "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
                    false,
                ),
            ],
            0,
            0,
            "BBE0F7C4ED3027F0AC1C5E35731BE0A7EF6A78D15A1A9AAC8D0C01B2AA7FD4D8",
        ),
        // Four tweaks: two plain followed by two x-only
        (
            vec![(0, 0), (1, 1)],
            vec![
                (
                    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                    false,
                ),
                (
                    "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
                    false,
                ),
                (
                    "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
                    true,
                ),
                (
                    "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
                    true,
                ),
            ],
            0,
            1,
            "30CFDD50B5F08DFE30E30F1DEE0CE1BD0168D3E53F545D4DED4D411A17CD9ADE",
        ),
        // Plain tweak of zero, which is in range
        (
            vec![(0, 0), (1, 1)],
            vec![(
                "0000000000000000000000000000000000000000000000000000000000000000",
                false,
            )],
            0,
            0,
            "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
        ),
    ] {
        let pubnonces: Vec<_> = signers
            .iter()
            .map(|&(id, i)| (id, pubnonce_pool[i].clone()))
            .collect();
        let tweaks = tweaks(&tweaks_hex);
        let msg = &msgs[msg_index];

        // The signer after round 1, with the vector's nonce.
        let signer = SignerStep1State {
            idx: signer_id,
            t: key.t,
            secshare: secshares[signer_id],
            pubshares: key.pubshares.clone(),
            threshold_pubkey: key.threshold_pubkey,
            msg: Some(msg.clone()),
            tweaks: Some(tweaks.clone()),
            secnonce: secnonce(secnonces[signer_id]),
        };
        let (_, (id, psig)) = signer
            .next((pubnonces.clone(), msg.clone(), tweaks.clone()))
            .unwrap();
        assert_eq!(id, signer_id);
        assert_eq!(hex::encode_upper(psig.to_bytes()), expected);
    }
}

#[test]
fn test_sign_rejects_invalid_inputs() {
    let secnonces = [
        "874A212D2DF14B0E55D5E9B86B0B6530A83BA59785303E333AB9F6193289D4A3B5DE529495EC16F25C1452C2732363C38623725EAE7BBCA47BD1AB43B3E21792",
        "7B3932D72200FDDD616B2CB6DDD9B263D566DC290FD6F6965BB01A813F05BA971B5C79608E807BDA020227517B70DC848479BC9139803A489BC58C5E9E5F9F10",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "874A212D2DF14B0E55D5E9B86B0B6530A83BA59785303E333AB9F6193289D4A30000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000B5DE529495EC16F25C1452C2732363C38623725EAE7BBCA47BD1AB43B3E21792",
    ];
    let secshares = [
        "53442FA9BD72EEA0A42DF6F2D2D76A2C0D3A3DFA2BE2F820F41ADE976B8259FB",
        "5A7F9BD41F4B544664C54D777D43303CB5302434F9903B9B552C4E552BF02201",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ];
    // Public shares of participants 0, 1 and 2, then (index 3) the identity
    // in place of the vectors' undecodable point, (index 4) a point that makes
    // the shares of 0 and 1 interpolate to infinity, and (index 5) G.
    let pubshare_pool = [
        parse_point_hex("039EE3335AF48DFE23702AB353F4AF20D401F67A130DF783CC8457323A860A2FB4")
            .unwrap(),
        parse_point_hex("0284DC4AB2CB78A621EB87FA1F14BCE2B725AFEAAC981ADCBAFF5CC2D417D2A63A")
            .unwrap(),
        parse_point_hex("036441EC2D4C1266201CD89B69549A2F5B2188612A0D434153E625FB38173DD509")
            .unwrap(),
        ProjectivePoint::IDENTITY,
        parse_point_hex("02A5363A0993E3E2096EF80B7B4DA1EDF650DBF02CAE168BB4ACC0E90A24CED0FD")
            .unwrap(),
        parse_point_hex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
            .unwrap(),
    ];
    let pubnonce_pool = [
        "028213A4194E3A70790607123B9A6D7A3363A62B8117C2DA1AFB40DE5B0EE4E06002EBAD9B1A145E503BCF05A4D05DB99E6B1A30098F26FA6305CDE8D59B32DBAC43",
        "02FB84325E2E570263DD8C1772FD17E810C0E938EEBFD0FA4AF39FB58507A5D48003FAD5DDF645F8197F9336480F34D928C2F69B1C44D88A8B1C57E93206CBDDF23D",
        "03B64B264AD117E20AD57BDC5A7EA33701CF1D6C7A7C19A946D082AA7746EFA1D102AD5BDCE55A642497B0932D584E26433722853F1D43387ACEDB4E9559D7CE0FB8",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap());
    let msg =
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    // The signing step reproduces the reference's check order: the session
    // parameters and tweaks, then the secret nonce and share, then the
    // signer's own id and public share.
    // (ids, signer pubshares as pool indices by id, tweaks, signer id, secnonce index, secshare index, error)
    for (ids, pubshares, tweaks_hex, signer_id, secnonce_index, secshare_index, expected_error) in [
        // Tweak equals the group order, which is out of range
        (
            vec![0, 1],
            [0, 1, 2],
            vec![
                (
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                    false,
                ),
            ],
            0,
            0,
            0,
            Value("The tweak value is out of range.".into()),
        ),
        // Plain tweak drives the tweaked threshold public key to the point at infinity
        (
            vec![0, 1],
            [0, 1, 2],
            vec![
                (
                    "B3F73C80A46577051C695F91D7945BE3556A85275112EB952CC8EFB32521AF4C",
                    false,
                ),
            ],
            0,
            0,
            0,
            Value("The tweaked threshold public key must not be the point at infinity.".into()),
        ),
        // Signer's id is absent from the signer set
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            2,
            0,
            0,
            Value("The signer's id is missing from the ids list.".into()),
        ),
        // Signer set contains a duplicate id
        (
            vec![0, 1, 1],
            [0, 1, 2],
            vec![],
            0,
            0,
            0,
            Value("The ids list contains duplicate elements.".into()),
        ),
        // Signer's public share does not match the public share listed at its index
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            1,
            0,
            0,
            Value("The signer's pubshare does not match its entry in the pubshares list.".into()),
        ),
        // A public share is not a valid point
        (
            vec![0, 1],
            [0, 3, 2],
            vec![],
            0,
            0,
            0,
            Value("The pubshare at index 1 is not a valid point.".into()),
        ),
        // Public shares of the signer set interpolate to the point at infinity
        (
            vec![0, 1],
            [0, 4, 2],
            vec![],
            0,
            0,
            0,
            Value("The threshold public key must not be the point at infinity.".into()),
        ),
        // A signer id is outside the valid range [0, n-1]
        (
            vec![3, 1],
            [0, 1, 2],
            vec![],
            1,
            1,
            1,
            Value("The id at index 0 must satisfy 0 <= id <= n - 1.".into()),
        ),
        // Signer set's public shares do not match the threshold public key
        (
            vec![0, 1, 2],
            [0, 2, 1],
            vec![],
            0,
            0,
            0,
            Value("The provided key material is incorrect: the public shares do not match the threshold public key.".into()),
        ),
        // Public share beyond the first t signers is inconsistent with the threshold public key
        (
            vec![0, 1, 2],
            [0, 1, 5],
            vec![],
            0,
            0,
            0,
            Value("The provided key material is incorrect: the public shares do not match the threshold public key.".into()),
        ),
        // Secret nonce's first half is out of range (all-zero nonce, which may indicate nonce reuse)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            2,
            0,
            Value("The first half of secnonce is out of range.".into()),
        ),
        // Secret nonce's second half is out of range (zero)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            3,
            0,
            Value("The second half of secnonce is out of range.".into()),
        ),
        // Secret nonce's first half is out of range (zero)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            4,
            0,
            Value("The first half of secnonce is out of range.".into()),
        ),
        // Fewer signers than the threshold t
        (
            vec![0],
            [0, 1, 2],
            vec![],
            0,
            0,
            0,
            Value("The number of signers must satisfy t <= u <= n.".into()),
        ),
        // Secret share is out of range (zero)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            0,
            2,
            Value("The secshare is out of range.".into()),
        ),
    ] {
        let key = key_material();
        let signer = SignerStep1State {
            idx: signer_id,
            t: key.t,
            secshare: parse_scalar_hex(secshares[secshare_index]).unwrap(),
            pubshares: pubshares.iter().map(|&i| pubshare_pool[i]).collect(),
            threshold_pubkey: key.threshold_pubkey,
            msg: Some(msg.clone()),
            tweaks: Some(tweaks(&tweaks_hex)),
            secnonce: secnonce(secnonces[secnonce_index]),
        };
        let pubnonces: Vec<_> = ids
            .iter()
            .map(|&id| (id, pubnonce_pool[id % 3].clone()))
            .collect();

        let err = signer
            .next((pubnonces, msg.clone(), tweaks(&tweaks_hex)))
            .err()
            .unwrap();
        assert_eq!(err, expected_error);
    }
}

#[test]
fn test_verify_rejects_invalid_partial_signature() {
    let key = key_material();
    let pubnonce_pool = [
        "028213A4194E3A70790607123B9A6D7A3363A62B8117C2DA1AFB40DE5B0EE4E06002EBAD9B1A145E503BCF05A4D05DB99E6B1A30098F26FA6305CDE8D59B32DBAC43",
        "02FB84325E2E570263DD8C1772FD17E810C0E938EEBFD0FA4AF39FB58507A5D48003FAD5DDF645F8197F9336480F34D928C2F69B1C44D88A8B1C57E93206CBDDF23D",
        "03B64B264AD117E20AD57BDC5A7EA33701CF1D6C7A7C19A946D082AA7746EFA1D102AD5BDCE55A642497B0932D584E26433722853F1D43387ACEDB4E9559D7CE0FB8",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap());
    let msg =
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    for (psig, signers, signer_id) in [
        // Negated partial signature fails the verification equation
        (
            "4283B4C7E1858318976E3F9B31A9ADB85671953DD6639CDFAA9B964CA50D4039",
            vec![(0, 0), (1, 1)],
            0,
        ),
        // A valid partial signature checked against the wrong signer fails the verification equation
        (
            "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
            vec![(0, 0), (1, 1)],
            1,
        ),
    ] {
        let pubnonces: Vec<_> = signers
            .iter()
            .map(|&(id, i)| (id, pubnonce_pool[i].clone()))
            .collect();
        let psig = parse_scalar_hex(psig).unwrap();
        assert!(verify_one(&key, &psig, signer_id, &pubnonces, &msg).is_err());
    }
}
