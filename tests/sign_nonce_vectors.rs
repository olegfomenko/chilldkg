#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{
    parse_hex_array, parse_point_hex, parse_pubnonce_hex, parse_scalar_hex, serialize_nonce,
};
use chilldkg_rs::sign::{aggr_pubnonces, sample_nonce};
use rand_core::{CryptoRng, RngCore};

pub mod common;

/// Feeds the vector's `rand_` to `sample_nonce`, which draws it with a single `fill_bytes`.
struct FixedRng([u8; 32]);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

#[test]
fn test_sample_nonce_passes() {
    for (
        rand,
        secshare,
        pubshare,
        thresh_pk,
        msg,
        extra_in,
        expected_secnonce,
        expected_pubnonce,
    ) in [
        // All optional defense-in-depth arguments present
        (
            "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            Some("CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1"),
            Some("022B02109FBCFB4DA3F53C7393B22E72A2A51C4AFBF0C01AAF44F73843CFB4B74B"),
            Some("B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237"),
            Some("0101010101010101010101010101010101010101010101010101010101010101"),
            Some("0808080808080808080808080808080808080808080808080808080808080808"),
            "0C0ED687982527EDE4850D26CC9FDF258877A1082FAC554C768933C62D41098C2D47C635AFE853EDF5A918AAFD58A6DBE76EF7DA96B962F27F24AB9032CEC1E8",
            "03982518FE7FB9F7EA9C0D8872EB8A47E79D710ABCA90049ADD095246D205F9E3103773309BECBFC880A909E5718174F0A026F00DBDD7A41B073436B2965389CDD52",
        ),
        // Empty message
        (
            "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            Some("CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1"),
            Some("022B02109FBCFB4DA3F53C7393B22E72A2A51C4AFBF0C01AAF44F73843CFB4B74B"),
            Some("B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237"),
            Some(""),
            Some("0808080808080808080808080808080808080808080808080808080808080808"),
            "D4A3DB06AEDD363D479DBC64524AA9ADA0394C1889732B31FAD0D3786903153BFCCD13C3F7D6E37280AFF964882DEE2AE9F8A899FE08300CA47DD51862070F60",
            "02C412C64ED527F0A52387FA3137FDD78208B5855D6169E00B55FE30E2ECDE1E9802FA424EE04E9C35014ADA6A8684D90C0ED562D8BD706AB47E00D10C1FA7BFBF0F",
        ),
        // Non-standard message length (38 bytes)
        (
            "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            Some("CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1"),
            Some("022B02109FBCFB4DA3F53C7393B22E72A2A51C4AFBF0C01AAF44F73843CFB4B74B"),
            Some("B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237"),
            Some("2626262626262626262626262626262626262626262626262626262626262626262626262626"),
            Some("0808080808080808080808080808080808080808080808080808080808080808"),
            "C268086EE4BAA786A6E56A5B2D5A4B66C317AFE8FD51D2C5EC237B295EBAC6B0523DD1DEFF080854DBFFD90126CABD837A49F70B6B65217BE9E10816C48E8E0F",
            "033F49CDE3445DCC35457E0871876ADAFDFED2AA7E91FF9F129AB14D7512D04D0F0362D263542BCEC5EC060D513698A6A696EC37DEC674D59C33664AD93FC836B9FD",
        ),
        // All optional defense-in-depth arguments omitted
        (
            "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            None,
            None,
            None,
            None,
            None,
            "42B39CA56390449A85BCEC2EF9B102CE945E693570A0077E98F8E77476AC3063EC9CFC5CE249D19C7BE5C310A425FB5E1E9B3B4577F628D9854A4A3C6C64C653",
            "0375B28F1525614D3A57AE7B5D9109C24BDCB823065C4AD85D01A53EDCEBD22FEA03EBAC798BC7D8F6580F21792938CD7A8B4462BBBDB5AB171370F17951E55CE990",
        ),
        // Message omitted, other optional arguments present
        (
            "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            Some("CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1"),
            Some("022B02109FBCFB4DA3F53C7393B22E72A2A51C4AFBF0C01AAF44F73843CFB4B74B"),
            Some("B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237"),
            None,
            Some("0808080808080808080808080808080808080808080808080808080808080808"),
            "13FDD87FB367940C7F275ED69AD980B5827F87BDE76A423C2C3E8721865A922D4DC0BC032E32E742244955E9990E85BFAD737BFEB1C5989379D67AA74A61D63D",
            "0219EFF6E1946B512FB6B60FC3400AFFD4BE20A7073C497B377ABD44FB5E0009B202FFDA9D1589E20AF78035118BEF59536A7F9B4D1AF30307B8FD3477417D607B9F",
        ),
    ] {
        let secshare = secshare.map(|h| parse_scalar_hex(h).unwrap());
        let pubshare = pubshare.map(|h| parse_point_hex(h).unwrap());
        // The vector gives the x-only key; lift it to the even-y point.
        let thresh_pk = thresh_pk.map(|h| parse_point_hex(&format!("02{h}")).unwrap());
        let msg = msg.map(|h| hex::decode(h).unwrap());
        let extra_in = extra_in.map(|h| hex::decode(h).unwrap());

        let (pubnonce, secnonce) = sample_nonce(
            &mut FixedRng(parse_hex_array(rand).unwrap()),
            secshare.as_ref(),
            pubshare.as_ref(),
            thresh_pk.as_ref(),
            msg.as_deref(),
            extra_in.as_deref(),
        )
        .unwrap();

        assert_eq!(
            hex::encode_upper([secnonce.k1.to_bytes(), secnonce.k2.to_bytes()].concat()),
            expected_secnonce
        );
        assert_eq!(
            serialize_nonce(&pubnonce.R1, &pubnonce.R2),
            expected_pubnonce
        );
    }
}

#[test]
fn test_aggr_pubnonces_passes() {
    for (pubnonces, expected_aggnonce) in [
        // Two well-formed public nonces
        (
            vec![
                "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            ],
            "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8",
        ),
        // Second halves sum to the point at infinity, which is serialized as the all-zero encoding
        (
            vec![
                "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            ],
            "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let pubnonces: Vec<_> = pubnonces
            .iter()
            .map(|h| parse_pubnonce_hex(h).unwrap())
            .collect();
        let (R1, R2) = aggr_pubnonces(pubnonces.iter());
        assert_eq!(serialize_nonce(&R1, &R2), expected_aggnonce);
    }
}
