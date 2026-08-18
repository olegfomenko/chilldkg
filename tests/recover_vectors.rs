#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{parse_point_hex, parse_scalar_hex};
use chilldkg_rs::coordinator::recovery::recover as recover_coordinator;
use chilldkg_rs::crypto::certeq::CertEQTranscript;
use chilldkg_rs::crypto::ec::{COMPRESSED_POINT_BYTES_SIZE, EC_SCALAR_BYTES_SIZE};
use chilldkg_rs::crypto::schnorr::{SCHNORR_SIG_BYTES_SIZE, SchnorrSignature};
use chilldkg_rs::errors::{ChillDkgError, Result};
use chilldkg_rs::msg::RecoveryData;
use chilldkg_rs::party::recovery::recover as recover_participant;

pub mod common;

#[test]
fn test_participant_recover_passes() {
    let threshold = 2;
    let n = 3;
    let hostseckey =
        parse_scalar_hex("ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207")
            .unwrap();
    let recovery_data = split_recovery_data("0000000203B74C6FD38288DDF94300E887B12DD40F655791144A07C32487FBD81CC228C07903B9C3F15E5C0E086EDE931D69BABD36167BE6CCA8705378F8849A4F00EDA2941303AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F303AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A30260537C74BC2B79676CDE217FFA7D48236D4A309954153DEB39A31AADF6B369CC022E7B7DD7A0B4A72097703E60648B615A4DDDF2D715A5E0992379537A44C13AD103D1FD5A186167E5DE84B11C0F56E1FC6808D2DB35E6E3587243CF59DE605CB806E242A37A2E03838EDCB4B064425FBA5F5F8331EDDF79B46AACC70EEB714995A27B5A879577BDAF956EC9F1C234BD3942E2B2F0E372902637993C54815B69F7EAFF288C16C20D3F8D26B64E23599E6996A833E286FEAD5A7490151202E859E484A6C2DE535556E47C8F3427B9716CFC4A66ADD0F2788AB793E2FBFF7D81DA06315C3F62CAA2B85E369922E68A94113EB839B5E3E424A4F4BF2E8D2908F517E8BE3B1B96C40D7F9A378F2A61FACF8469447344B5280F5E7B3C66B560709A6FA4D7E083E650F3C109995ACB96EEA2EE4EF252257E1BF92FFF121CE916DE2D7C4B5479195E7CBE22A8B53C41012ABEA37F0B59579E43EDC6477E8CC5C7EB9F3C8BF7AEC850C63A659FADD91C9063908054FC4D193594E132ADFBE1F24BE74C8BEA7A", threshold, n).unwrap();
    let secshare =
        parse_scalar_hex("CF1009015DDCBEB326BC5C7C556CECAC8BCA838ECAA0627DC6D9E1367589AB85")
            .unwrap();
    let threshold_pubkey =
        parse_point_hex("021979452A2E878B2A5BB662F293D23C5795991FB984A8DFDE6EAA885AB72B311A")
            .unwrap();
    let pubshares = vec![
        parse_point_hex("03D5DF677B4FD40950902A2D3D6469723FADCE0CDD939C8150937EF1D15801DDBC")
            .unwrap(),
        parse_point_hex("03B53DF94A01A578300EBB5095B36668E810FE030C200F887CD9BD7F3AD40F31CA")
            .unwrap(),
        parse_point_hex("0377FADE50E2F82A4FD697CF403F8C717E8614199AA87458BCB8A16E6289C26F8B")
            .unwrap(),
    ];

    let actual = recover_participant(&hostseckey, &recovery_data).unwrap();
    assert_eq!(actual.idx, 0);
    assert_eq!(actual.t, threshold);
    assert_eq!(actual.secshare, secshare);
    assert_eq!(actual.threshold_pubkey, threshold_pubkey);
    assert_eq!(actual.pubshares, pubshares);
}

#[test]
fn test_coordinator_recover_passes() {
    let threshold = 2;
    let n = 3;
    let recovery_data = split_recovery_data("0000000203B74C6FD38288DDF94300E887B12DD40F655791144A07C32487FBD81CC228C07903B9C3F15E5C0E086EDE931D69BABD36167BE6CCA8705378F8849A4F00EDA2941303AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F303AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A30260537C74BC2B79676CDE217FFA7D48236D4A309954153DEB39A31AADF6B369CC022E7B7DD7A0B4A72097703E60648B615A4DDDF2D715A5E0992379537A44C13AD103D1FD5A186167E5DE84B11C0F56E1FC6808D2DB35E6E3587243CF59DE605CB806E242A37A2E03838EDCB4B064425FBA5F5F8331EDDF79B46AACC70EEB714995A27B5A879577BDAF956EC9F1C234BD3942E2B2F0E372902637993C54815B69F7EAFF288C16C20D3F8D26B64E23599E6996A833E286FEAD5A7490151202E859E484A6C2DE535556E47C8F3427B9716CFC4A66ADD0F2788AB793E2FBFF7D81DA06315C3F62CAA2B85E369922E68A94113EB839B5E3E424A4F4BF2E8D2908F517E8BE3B1B96C40D7F9A378F2A61FACF8469447344B5280F5E7B3C66B560709A6FA4D7E083E650F3C109995ACB96EEA2EE4EF252257E1BF92FFF121CE916DE2D7C4B5479195E7CBE22A8B53C41012ABEA37F0B59579E43EDC6477E8CC5C7EB9F3C8BF7AEC850C63A659FADD91C9063908054FC4D193594E132ADFBE1F24BE74C8BEA7A", threshold, n).unwrap();
    let threshold_pubkey =
        parse_point_hex("021979452A2E878B2A5BB662F293D23C5795991FB984A8DFDE6EAA885AB72B311A")
            .unwrap();
    let pubshares = vec![
        parse_point_hex("03D5DF677B4FD40950902A2D3D6469723FADCE0CDD939C8150937EF1D15801DDBC")
            .unwrap(),
        parse_point_hex("03B53DF94A01A578300EBB5095B36668E810FE030C200F887CD9BD7F3AD40F31CA")
            .unwrap(),
        parse_point_hex("0377FADE50E2F82A4FD697CF403F8C717E8614199AA87458BCB8A16E6289C26F8B")
            .unwrap(),
    ];

    let actual = recover_coordinator(&recovery_data).unwrap();
    assert_eq!(actual.t, threshold);
    assert_eq!(actual.threshold_pubkey, threshold_pubkey);
    assert_eq!(actual.pubshares, pubshares);
}

#[test]
fn test_recover_rejects_malformed_data() {
    let recovery_data = "0000000203B74C6FD38288DDF94300E887B12DD40F655791144A07C32487FBD81CC228C07903B9C3F15E5C0E086EDE931D69BABD36167BE6CCA8705378F8849A4F00EDA2941303AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F303AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A30260537C74BC2B79676CDE217FFA7D48236D4A309954153DEB39A31AADF6B369CC022E7B7DD7A0B4A72097703E60648B615A4DDDF2D715A5E0992379537A44C13AD103D1FD5A186167E5DE84B11C0F56E1FC6808D2DB35E6E3587243CF59DE605CB806E242A37A2E03838EDCB4B064425FBA5F5F8331EDDF79B46AACC70EEB714995A27B5A879577BDAF956EC9F1C234BD3942E2B2F0E372902637993C54815B69F7EAFF288C16C20D3F8D26B64E23599E6996A833E286FEAD5A7490151202E859E484A6C2DE535556E47C8F3427B9716CFC4A66ADD0F2788AB793E2FBFF7D81DA06315C3F62CAA2B85E369922E68A94113EB839B5E3E424A4F4BF2E8D2908F517E8BE3B1B96C40D7F9A378F2A61FACF8469447344B5280F5E7B3C66B560709A6FA4D7E083E650F3C109995ACB96EEA2EE4EF252257E1BF92FFF121CE916DE2D7C4B5479195E7CBE22A8B53C41012ABEA37F0B59579E43EDC6477E8CC5C7EB9F3C8BF7AEC850C63A659FADD91C9063908054FC4D193594E132ADFBE1F24BE74C8BEA7A";
    let invalid_compressed_point =
        "030000000000000000000000000000000000000000000000000000000000000005";
    let tampered_pubnonce = "03421F5FC9A21065445C96FDB91C0C1E2F2431741C72713B4B99DDCB316F31E9FC";
    let invalid_scalar = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    let invalid_pmsg2 = "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9";
    let threshold = 2;
    let n = 3;

    for (recovery_data, threshold, expected_error) in [
        (
            recovery_data[2..].to_string(),
            threshold,
            ChillDkgError::RecoveryData("Failed to deserialize recovery data".to_owned()),
        ),
        (
            replace_bytes(recovery_data, 4, invalid_compressed_point),
            threshold,
            ChillDkgError::RecoveryData("Failed to deserialize recovery data".to_owned()),
        ),
        (
            replace_bytes(recovery_data, 332, invalid_scalar),
            threshold,
            ChillDkgError::RecoveryData("Failed to deserialize recovery data".to_owned()),
        ),
        (
            remove_bytes(&replace_bytes(recovery_data, 0, "00000000"), 4, 66),
            0,
            ChillDkgError::RecoveryData("Invalid session parameters in recovery data".to_owned()),
        ),
        (
            replace_bytes(recovery_data, 70, invalid_compressed_point),
            threshold,
            ChillDkgError::RecoveryData("Invalid session parameters in recovery data".to_owned()),
        ),
        (
            replace_bytes(recovery_data, 235, tampered_pubnonce),
            threshold,
            ChillDkgError::RecoveryData("Invalid certificate in recovery data".to_owned()),
        ),
        (
            format!(
                "{}{}",
                &recovery_data[..recovery_data.len() - 128],
                invalid_pmsg2
            ),
            threshold,
            ChillDkgError::RecoveryData("Invalid certificate in recovery data".to_owned()),
        ),
    ] {
        let err = split_recovery_data(&recovery_data, threshold, n)
            .and_then(|recovery_data| recover_coordinator(&recovery_data))
            .err()
            .unwrap();
        assert_eq!(err, expected_error);
    }
}

#[test]
fn test_participant_recover_rejects_host_seckey_mismatch() {
    let hostseckey =
        parse_scalar_hex("759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7")
            .unwrap();
    let recovery_data = split_recovery_data("0000000203B74C6FD38288DDF94300E887B12DD40F655791144A07C32487FBD81CC228C07903B9C3F15E5C0E086EDE931D69BABD36167BE6CCA8705378F8849A4F00EDA2941303AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F303AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A30260537C74BC2B79676CDE217FFA7D48236D4A309954153DEB39A31AADF6B369CC022E7B7DD7A0B4A72097703E60648B615A4DDDF2D715A5E0992379537A44C13AD103D1FD5A186167E5DE84B11C0F56E1FC6808D2DB35E6E3587243CF59DE605CB806E242A37A2E03838EDCB4B064425FBA5F5F8331EDDF79B46AACC70EEB714995A27B5A879577BDAF956EC9F1C234BD3942E2B2F0E372902637993C54815B69F7EAFF288C16C20D3F8D26B64E23599E6996A833E286FEAD5A7490151202E859E484A6C2DE535556E47C8F3427B9716CFC4A66ADD0F2788AB793E2FBFF7D81DA06315C3F62CAA2B85E369922E68A94113EB839B5E3E424A4F4BF2E8D2908F517E8BE3B1B96C40D7F9A378F2A61FACF8469447344B5280F5E7B3C66B560709A6FA4D7E083E650F3C109995ACB96EEA2EE4EF252257E1BF92FFF121CE916DE2D7C4B5479195E7CBE22A8B53C41012ABEA37F0B59579E43EDC6477E8CC5C7EB9F3C8BF7AEC850C63A659FADD91C9063908054FC4D193594E132ADFBE1F24BE74C8BEA7A", 2, 3).unwrap();
    let err = recover_participant(&hostseckey, &recovery_data)
        .err()
        .unwrap();
    assert_eq!(
        err,
        ChillDkgError::HostSeckey(
            "Host secret key does not match any host public key in the recovery data".to_owned()
        )
    );
}

fn split_recovery_data(hex: &str, threshold: usize, n: usize) -> Result<RecoveryData> {
    let bytes = hex::decode(hex).map_err(|err| ChillDkgError::Runtime(err.to_string()))?;
    let transcript_len = 4
        + COMPRESSED_POINT_BYTES_SIZE * threshold
        + (COMPRESSED_POINT_BYTES_SIZE + COMPRESSED_POINT_BYTES_SIZE + EC_SCALAR_BYTES_SIZE) * n;
    let cert_len = SCHNORR_SIG_BYTES_SIZE * n;

    if bytes.len() != transcript_len + cert_len {
        return Err(ChillDkgError::RecoveryData(
            "Failed to deserialize recovery data".to_owned(),
        ));
    }

    let transcript = CertEQTranscript::try_from((&bytes[..transcript_len], n)).map_err(|err| {
        ChillDkgError::RecoveryData(match err {
            ChillDkgError::InvalidHostPubkey { .. } => {
                "Invalid session parameters in recovery data".to_owned()
            }
            _ => "Failed to deserialize recovery data".to_owned(),
        })
    })?;

    Ok(RecoveryData {
        transcript,
        cert: bytes[transcript_len..]
            .chunks_exact(SCHNORR_SIG_BYTES_SIZE)
            .map(SchnorrSignature::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?,
    })
}

fn replace_bytes(hex: &str, offset: usize, replacement: &str) -> String {
    let mut hex = hex.to_owned();
    hex.replace_range(offset * 2..offset * 2 + replacement.len(), replacement);
    hex
}

fn remove_bytes(hex: &str, offset: usize, len: usize) -> String {
    let mut hex = hex.to_owned();
    hex.replace_range(offset * 2..(offset + len) * 2, "");
    hex
}
