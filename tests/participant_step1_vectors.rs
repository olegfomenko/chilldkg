#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{parse_hex_array, parse_participant_msg1, parse_point_hex, parse_scalar_hex};
use chilldkg_rs::crypto::secp256k1::Secp256k1;
use chilldkg_rs::errors::ChillDkgError::{
    DuplicateHostPubkeyError, HostSeckeyError, ThresholdOrCountError,
};
use chilldkg_rs::party::{ParticipantInitialState, ParticipantState};

pub mod common;

#[test]
fn test_participant_step1_passes() {
    let hostseckey =
        parse_scalar_hex("ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207")
            .unwrap();
    let random =
        parse_hex_array("42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC")
            .unwrap();
    let hostpubkeys = vec![
        parse_point_hex("03AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F3")
            .unwrap(),
        parse_point_hex("03AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7")
            .unwrap(),
        parse_point_hex("021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A3")
            .unwrap(),
    ];
    let t = 2;
    let n = hostpubkeys.len();
    let expected_pmsg1 = parse_participant_msg1("036BEE122EF60CBBB5DFC3572FE6D3A9AC0B35BB427E250F42C38F7C8229889CAB03E99E34AA2A0646563DF90F2407D0D0E345EAE2CF7F07F9F6561302F724EFA74708AE5A94BBDD3FC53924623E0D6764E089D679048F699118D7807884AD13CF484866D8210BCB76DAEB103AD6BA1CED0DBFE78F1E8A44F26FC69D5464BF23324D0260537C74BC2B79676CDE217FFA7D48236D4A309954153DEB39A31AADF6B369CCC6C144287B356EF70378A7F1054FF00354A01352587DC076554A82CD324B66A17006774A86C116C19F2C021793EAB87DF19EE3A978C60F757BA192DA23BAE5F56A3612D0720F35828FCFBA9DFEA790883B185A8B75A27449AF23169C919B47C7", t, n).unwrap();

    let initial = ParticipantInitialState::<Secp256k1> { s: hostseckey };
    let (_, actual) = initial.next((hostpubkeys, t, random)).unwrap();
    assert_eq!(actual, expected_pmsg1);
}

#[test]
fn test_participant_step1_invalid_threshold() {
    let hostseckey =
        parse_scalar_hex("ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207")
            .unwrap();
    let random =
        parse_hex_array("42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC")
            .unwrap();
    let hostpubkeys = vec![
        parse_point_hex("03AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F3")
            .unwrap(),
        parse_point_hex("03AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7")
            .unwrap(),
        parse_point_hex("021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A3")
            .unwrap(),
    ];
    let initial = ParticipantInitialState::<Secp256k1> { s: hostseckey };
    let err = initial.next((hostpubkeys, 0, random)).err().unwrap();
    assert_eq!(err, ThresholdOrCountError);
}

#[test]
fn test_participant_step1_duplicate_host_pubkey() {
    let hostseckey =
        parse_scalar_hex("ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207")
            .unwrap();
    let random =
        parse_hex_array("42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC")
            .unwrap();
    let hostpubkeys = vec![
        parse_point_hex("03AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F3")
            .unwrap(),
        parse_point_hex("03AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7")
            .unwrap(),
        parse_point_hex("021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A3")
            .unwrap(),
        parse_point_hex("03AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7")
            .unwrap(),
    ];
    let t = 2;
    let initial = ParticipantInitialState::<Secp256k1> { s: hostseckey };
    let err = initial.next((hostpubkeys, t, random)).err().unwrap();
    assert_eq!(
        err,
        DuplicateHostPubkeyError {
            participant1: 1,
            participant2: 3
        }
    );
}

#[test]
fn test_participant_step1_host_seckey_mismatch() {
    let hostseckey =
        parse_scalar_hex("759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7")
            .unwrap();
    let random =
        parse_hex_array("42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC")
            .unwrap();
    let hostpubkeys = vec![
        parse_point_hex("03AED316469060698D774150EFD7F8F406A2BAB516DD7D22CB258323C59C6417F3")
            .unwrap(),
        parse_point_hex("03AEB5AE20783D4858F6767747963F144C7DB8ABA328625CC8A87F7676D8CDEEE7")
            .unwrap(),
        parse_point_hex("021A48BBCCAC751AE9EC1EA7A7F8D421D5FD60AAB44E6D2F37B31873098A77B7A3")
            .unwrap(),
    ];
    let t = 2;
    let initial = ParticipantInitialState::<Secp256k1> { s: hostseckey };
    let err = initial.next((hostpubkeys, t, random)).err().unwrap();
    assert_eq!(
        err,
        HostSeckeyError("Host secret key does not match any host public key".to_owned())
    );
}
