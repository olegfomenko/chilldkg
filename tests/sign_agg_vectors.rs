#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{parse_aggnonce_hex, parse_hex_array, parse_point_hex, parse_scalar_hex};
use chilldkg_rs::crypto::tweak::TweakContext;
use chilldkg_rs::sign::coordinator::verify::{challenge, combine, signing_nonce};
use chilldkg_rs::sign::{PartialSignature, Tweak, verify};

pub mod common;

fn tweaks(tweaks: &[(&str, bool)]) -> Vec<Tweak> {
    tweaks
        .iter()
        .map(|(hex, is_xonly)| Tweak {
            value: parse_hex_array(hex).unwrap(),
            is_xonly: *is_xonly,
        })
        .collect()
}

/// The `sig_agg` reference vectors: combining partial signatures given only
/// the aggregate nonce (the reference `partial_sig_agg`).
#[test]
fn test_combine_passes() {
    let threshold_pubkey =
        parse_point_hex("02D772A09F5F675783D275ED9F6AAEDB2ECCBC74171B37AC23AE3BBD9D7AE2CDAA")
            .unwrap();
    let msg =
        hex::decode("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF").unwrap();

    // (ids, aggregate nonce as R1 || R2, tweaks, psigs, expected signature)
    for (ids, aggnonce, tweaks_hex, psigs, expected) in [
        // Minimum threshold subset of signers, no tweaks
        (
            vec![0, 1],
            "0258D346E23685E092E143BD203EEC8597131390B1300E9466C9B741EC65FCCFC6029C9B5D46EF571F128C657306C86AC24E2E58CAC742788645A29E1CC0CEFFB316",
            vec![],
            vec![
                "BD7C4B381E7A7CE76891C064CE565246643D47A8D8E5035C1536C8402B290108",
                "F6FC1814C8BDF89041FE10F91AD306CEF0E90CBD5003BE216D6C40B891469016",
            ],
            "B89B25226C5ED33AD67F5BD7C750516ED05DA326E36D9878A26C385B891E9A65B478634CE7387577AA8FD15DE92959169A77777F79A02141C2D0AA6BEC394FDD",
        ),
        // Signer set in descending order, so the identifiers must be sorted before hashing
        (
            vec![2, 1, 0],
            "022AB135CDC19EDF76340849130F0D8C0863071C70E2DA3C2FEDD20FF7DE1C739702156AD83CB8D523D67AA764CDC9B4AC913C76585C4B7BEEB7851CDBB33F0C832D",
            vec![],
            vec![
                "4636795DA140BB1DD14B7FA73FE3FD0CC24A9C08786ABE1CCBAAC776BC64F34C",
                "2C1B45EB5E01613D4ACC325D2A3A5677F60750ADC9706BCCCDAFD144B45C72AF",
                "763E4353210C86236AEA8E073FAFE564981ED70BCF096CFBECCE88B5F24F0EC9",
            ],
            "51A7FA5FFE4739217B46AE2D8570EF354AB19663AA27358F9460E6184048CB40E890029C204EA27E8702400BA9CE38E95070C3C210E496E586292171631074C4",
        ),
        // Aggregation with three tweaks applied (one plain, two x-only)
        (
            vec![0, 1],
            "0258D346E23685E092E143BD203EEC8597131390B1300E9466C9B741EC65FCCFC6029C9B5D46EF571F128C657306C86AC24E2E58CAC742788645A29E1CC0CEFFB316",
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
            vec![
                "AE2818DFC14FD4903FBA3778BDF27C0B3B5863AEEFDDA6540A73A22C4E734D10",
                "21780564C5FF2FBC16724039E98740A7E33CECBFDF11EC52300BA12C278B4531",
            ],
            "95CB034D179622277EA691064988749ADDADFCFF36E0542B288F0D36CE5DACD173239D0A5A4B0BD8721E2286EBCB11B6D62174BAFF8D17E0191B9B9CDC8156AE",
        ),
        // All signers participate, no tweaks
        (
            vec![0, 1, 2],
            "022AB135CDC19EDF76340849130F0D8C0863071C70E2DA3C2FEDD20FF7DE1C739702156AD83CB8D523D67AA764CDC9B4AC913C76585C4B7BEEB7851CDBB33F0C832D",
            vec![],
            vec![
                "763E4353210C86236AEA8E073FAFE564981ED70BCF096CFBECCE88B5F24F0EC9",
                "2C1B45EB5E01613D4ACC325D2A3A5677F60750ADC9706BCCCDAFD144B45C72AF",
                "4636795DA140BB1DD14B7FA73FE3FD0CC24A9C08786ABE1CCBAAC776BC64F34C",
            ],
            "51A7FA5FFE4739217B46AE2D8570EF354AB19663AA27358F9460E6184048CB40E890029C204EA27E8702400BA9CE38E95070C3C210E496E586292171631074C4",
        ),
    ] {
        let tweaks = tweaks(&tweaks_hex);
        let psigs: Vec<PartialSignature> = psigs
            .iter()
            .map(|hex| parse_scalar_hex(hex).unwrap())
            .collect();

        let tweak_ctx = TweakContext::new(threshold_pubkey)
            .apply_all(&tweaks)
            .unwrap();
        let (_, R) = signing_nonce(
            &ids,
            parse_aggnonce_hex(aggnonce).unwrap(),
            &tweak_ctx,
            &msg,
        )
        .unwrap();
        let e = challenge(&R, &tweak_ctx, &msg).unwrap();

        let sig = combine(psigs.iter(), &tweak_ctx, &R, e);
        assert_eq!(hex::encode_upper(sig), expected);
        verify(&threshold_pubkey, sig, &msg, &tweaks).unwrap();
    }
}
