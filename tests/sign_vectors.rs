#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{parse_hex_array, parse_point_hex, parse_pubnonce_hex, parse_scalar_hex};
use chilldkg_rs::errors::ChillDkgError::Value;
use chilldkg_rs::sign::{SecNonce, Signer, Tweak, Verifier};

pub mod common;

fn key_material() -> Verifier {
    Verifier {
        t: 2,
        thresh_pk: parse_point_hex(
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

/// Participant 0's secret nonce (`k_1 || k_2`) from the vectors.
fn secnonce(hex: &str) -> SecNonce {
    SecNonce {
        k1: parse_scalar_hex(&hex[..64]).unwrap(),
        k2: parse_scalar_hex(&hex[64..]).unwrap(),
    }
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
    let verifier = key_material();
    let signer = Signer::new(
        0,
        verifier.t,
        &parse_scalar_hex("CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1")
            .unwrap(),
        &verifier.pubshares,
        verifier.thresh_pk,
    );
    let pubnonce_pool = [
        "03295054A682346C6A55DC184F463E48FEB38B23659E84A725604E570044487192021F8C6DC6DF28F187E52F796A4C189867797DB7D9E86796586F5A5FB6D4006597",
        "028D0DD00F4DD83ACE58ECA8197EC7CD0B94C9F53081E6394168EB37BE5DAAE5B7025224420D478FA5230C172FD625930B34A2343B335EAF2D3080D7B8DA71245CAE",
        "022A6084A7614CDBA50397DFFC922AFB40CB848AE3341D5EA2F6E8BEA5ECAC1B9D02298852FE90C793305C4B7E02F80DC04BD29CBEA7FD99972993172AE030384151",
        "03ABA4374155062E973007AC12D2CB1BCB70A76ACF3CFCE6F9E2160CF5D7DD4CCB02EB324CCEF66810F01197F28E63B97B50D7F6503940709E8DDD0313144D039568",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap());
    let msgs = [
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
        "",
        "2626262626262626262626262626262626262626262626262626262626262626262626262626",
    ]
    .map(|h| hex::decode(h).unwrap());

    // (signers as (id, pubnonce pool index), tweaks, msg index, my_id, expected psig)
    for (signers, tweaks_hex, msg_index, my_id, expected) in [
        // No tweaks applied
        (
            vec![(0, 0), (1, 1)],
            vec![],
            0,
            0,
            "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
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
            "D9BA772C07C931FBAFC0DCD4BED4CACCEAFBB78C1C875BE8C2B7964B7E078452",
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
            "0250E76AE0FF75ADA6289CAAF4867C26EAB83C1B663A0810BEB21259C1676311",
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
            "B6684D187FC396F4E245ED9EC3A478DB938D0B9AE09370A14C52A8ACB01008AB",
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
            "F026C5B3BD2686448D4F0ABEE8F0B68E85B686BA974665D3C369C0481C82A1B9",
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
            0,
            "19831834CF227BE6B371C1D36A684DD1D30A8FC00D1418E11DF4A1A500006D72",
        ),
        // Same tweaks as the previous case but with all 3 signers; the partial signature differs because the Lagrange coefficient depends on the signer set
        (
            vec![(0, 0), (1, 1), (2, 2)],
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
            0,
            "FCDADA0021DC1C7C96A0097A596912382BD08757297E4024FAADF428368418EC",
        ),
        // Minimum threshold subset of signers (t=2 of n=3)
        (
            vec![(0, 0), (1, 1)],
            vec![],
            0,
            0,
            "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
        ),
        // Signer order does not affect the partial signature: the signer set is sorted internally, so this matches the first valid case
        (
            vec![(1, 1), (0, 0)],
            vec![],
            0,
            0,
            "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
        ),
        // A different threshold subset gives a different partial signature, since the Lagrange coefficients depend on the signer set
        (
            vec![(0, 0), (2, 2)],
            vec![],
            0,
            0,
            "5C8DF052E993D2157A3408E1D800D5D1812CD8D34703E68A46E9E1D1B2634C5E",
        ),
        // All n=3 signers participate (signer set equals the full group)
        (
            vec![(0, 0), (1, 1), (2, 2)],
            vec![],
            0,
            0,
            "006B9CB48E3EC79F0DB2D640CFA75DFA223C27C96728C615733C1EBFC8CB3B20",
        ),
        // Aggregate nonce is the point at infinity, so the final nonce point falls back to the generator G
        (
            vec![(0, 0), (1, 1), (2, 3)],
            vec![],
            0,
            0,
            "6FF6F55F78B4E5FE4860381D3845D4E1D609CDC8352150AB70C3D3814DD78D14",
        ),
        // Empty message
        (
            vec![(0, 0), (1, 1)],
            vec![],
            1,
            0,
            "301EF5B7AFEB52B217291F05898E3109D78DF39232FC93DA8F6D2FFC60F55668",
        ),
        // Non-standard message length (38 bytes)
        (
            vec![(0, 0), (1, 1)],
            vec![],
            2,
            0,
            "E636F1033039FF2757E6EFCFEFC8C742B01F003EBCA2E6AFBB741D8F0A2A0963",
        ),
    ] {
        let pubnonces: Vec<_> = signers
            .iter()
            .map(|&(id, i)| (id, pubnonce_pool[i].clone()))
            .collect();
        let tweaks = tweaks(&tweaks_hex);
        let msg = &msgs[msg_index];

        let psig = signer
            .sign(msg, &tweaks, secnonce("493A7862206B66B2D2E1B60583C8D3477D71EF66E5C628A30EF619665C86FE970057939BD14AB8EC43ACE8AA98CA359BBF0BF7432115DC52C173DD77104C1213"), &pubnonces)
            .unwrap();
        assert_eq!(hex::encode_upper(psig.to_bytes()), expected);
        assert!(
            verifier
                .partial_verify(&psig, my_id, &pubnonces, msg, &tweaks)
                .unwrap()
        );
    }
}

#[test]
fn test_sign_rejects_invalid_inputs() {
    let secnonces = [
        "493A7862206B66B2D2E1B60583C8D3477D71EF66E5C628A30EF619665C86FE970057939BD14AB8EC43ACE8AA98CA359BBF0BF7432115DC52C173DD77104C1213",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "493A7862206B66B2D2E1B60583C8D3477D71EF66E5C628A30EF619665C86FE970000000000000000000000000000000000000000000000000000000000000000",
    ];
    let secshares = [
        "CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ];
    let pubshare_pool = key_material().pubshares;
    let pubnonce_pool = [
        "03295054A682346C6A55DC184F463E48FEB38B23659E84A725604E570044487192021F8C6DC6DF28F187E52F796A4C189867797DB7D9E86796586F5A5FB6D4006597",
        "028D0DD00F4DD83ACE58ECA8197EC7CD0B94C9F53081E6394168EB37BE5DAAE5B7025224420D478FA5230C172FD625930B34A2343B335EAF2D3080D7B8DA71245CAE",
        "022A6084A7614CDBA50397DFFC922AFB40CB848AE3341D5EA2F6E8BEA5ECAC1B9D02298852FE90C793305C4B7E02F80DC04BD29CBEA7FD99972993172AE030384151",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap());
    let msg =
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    // The reference validates the signers context first, then the secret
    // nonce and share; the caller-side `validate_signers` reproduces that order.
    // (ids, verifier pubshares as pool indices, tweaks, my_id, secnonce index, secshare index, error)
    for (ids, pubshares, tweaks_hex, my_id, secnonce_index, secshare_index, expected_error) in [
        // Tweak exceeds the group order
        (
            vec![0, 1],
            [0, 1, 2],
            vec![(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                false,
            )],
            0,
            0,
            0,
            Value("The tweak value is out of range.".into()),
        ),
        // Tweak drives the tweaked public key to the point at infinity
        (
            vec![0, 1],
            [0, 1, 2],
            vec![(
                "C8FA70D93D4F99492E01B34792EF6CEE74F9C216E5FE3CC80D2065B3C4C8BD5A",
                false,
            )],
            0,
            0,
            0,
            Value("The result of tweaking cannot be infinity.".into()),
        ),
        // Signer's own id is not in the signer set
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            2,
            0,
            0,
            Value("The signer's id must be present in the participant identifier list.".into()),
        ),
        // Signer set contains a duplicate id
        (
            vec![0, 1, 1],
            [0, 1, 2],
            vec![],
            0,
            0,
            0,
            Value("The participant identifier list contains duplicate elements.".into()),
        ),
        // A signer id is outside the valid range [0, n-1]
        (
            vec![3, 1],
            [0, 1, 2],
            vec![],
            1,
            0,
            0,
            Value("The participant identifier at index 0 is out of range.".into()),
        ),
        // Signer set's public shares do not match the threshold public key
        (
            vec![0, 1],
            [0, 2, 2],
            vec![],
            0,
            0,
            0,
            Value("The provided key material is incorrect.".into()),
        ),
        // Secret nonce's first half is out of range (all-zero nonce, which may indicate nonce reuse)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            1,
            0,
            Value("first secnonce value is out of range.".into()),
        ),
        // Secret nonce's second half is out of range (zero)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            2,
            0,
            Value("second secnonce value is out of range.".into()),
        ),
        // Fewer signers than the threshold t
        (
            vec![0],
            [0, 1, 2],
            vec![],
            0,
            0,
            0,
            Value("The number of signers must be between t and n.".into()),
        ),
        // Secret share is out of range (zero)
        (
            vec![0, 1],
            [0, 1, 2],
            vec![],
            0,
            0,
            1,
            Value("The signer's secret share value is out of range.".into()),
        ),
    ] {
        let verifier = Verifier {
            pubshares: pubshares.iter().map(|&i| pubshare_pool[i]).collect(),
            ..key_material()
        };
        let signer = Signer::new(
            my_id,
            verifier.t,
            &parse_scalar_hex(secshares[secshare_index]).unwrap(),
            &verifier.pubshares,
            verifier.thresh_pk,
        );
        let pubnonces: Vec<_> = ids
            .iter()
            .map(|&id| (id, pubnonce_pool[id % 3].clone()))
            .collect();

        let err = signer
            .sign(
                &msg,
                &tweaks(&tweaks_hex),
                secnonce(secnonces[secnonce_index]),
                &pubnonces,
            )
            .err()
            .unwrap();
        assert_eq!(err, expected_error);
    }
}

#[test]
fn test_verify_rejects_invalid_partial_signature() {
    let verifier = key_material();
    let pubnonce_pool = [
        "03295054A682346C6A55DC184F463E48FEB38B23659E84A725604E570044487192021F8C6DC6DF28F187E52F796A4C189867797DB7D9E86796586F5A5FB6D4006597",
        "028D0DD00F4DD83ACE58ECA8197EC7CD0B94C9F53081E6394168EB37BE5DAAE5B7025224420D478FA5230C172FD625930B34A2343B335EAF2D3080D7B8DA71245CAE",
        "022A6084A7614CDBA50397DFFC922AFB40CB848AE3341D5EA2F6E8BEA5ECAC1B9D02298852FE90C793305C4B7E02F80DC04BD29CBEA7FD99972993172AE030384151",
    ]
    .map(|h| parse_pubnonce_hex(h).unwrap());
    let msg =
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    for (psig, signers, my_id) in [
        // Negated partial signature fails the verification equation
        (
            "FB9C49E9C0A16F2F5F6BD25550EC8652431DAE39706F3C157D9F9E5F92BE911B",
            vec![(0, 0), (1, 1)],
            0,
        ),
        // A valid partial signature checked against the wrong signer fails the verification equation
        (
            "0463B6163F5E90D0A0942DAAAF1379AC77912EAD3ED964264232C02D3D77B026",
            vec![(0, 0), (1, 1)],
            1,
        ),
    ] {
        let pubnonces: Vec<_> = signers
            .iter()
            .map(|&(id, i)| (id, pubnonce_pool[i].clone()))
            .collect();
        let psig = parse_scalar_hex(psig).unwrap();
        assert!(
            !verifier
                .partial_verify(&psig, my_id, &pubnonces, &msg, &[])
                .unwrap()
        );
    }
}
