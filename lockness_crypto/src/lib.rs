use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidCiphertext,
    InvalidPoint,
}

pub fn encrypt<E: Curve>(public_key: &Point<E>, message: &[u8]) -> Vec<u8> {
    encrypt_with_rng(&mut OsRng, public_key, message)
}

pub fn encrypt_with_rng<E: Curve, R: RngCore + CryptoRng>(
    rng: &mut R,
    public_key: &Point<E>,
    message: &[u8],
) -> Vec<u8> {
    let eph = Scalar::<E>::random(rng);
    let r = Point::<E>::generator() * &eph;
    let shared = public_key * &eph;

    let shared_bytes = shared.to_bytes(true);
    let digest = Sha256::digest(shared_bytes.as_bytes());
    let key_stream = expand_to_len(&digest, message.len());
    let ciphertext = xor_bytes(message, &key_stream);

    let r_bytes = r.to_bytes(true);
    let mut out = Vec::with_capacity(r_bytes.as_bytes().len() + ciphertext.len());
    out.extend_from_slice(r_bytes.as_bytes());
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decrypt<E: Curve>(
    secret_key: &SecretScalar<E>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let r_len = Point::<E>::serialized_len(true);
    if ciphertext.len() < r_len {
        return Err(CryptoError::InvalidCiphertext);
    }

    let (r_bytes, c_bytes) = ciphertext.split_at(r_len);
    let r = Point::<E>::from_bytes(r_bytes).map_err(|_| CryptoError::InvalidPoint)?;
    let shared = r * secret_key.as_ref();

    let shared_bytes = shared.to_bytes(true);
    let digest = Sha256::digest(shared_bytes.as_bytes());
    let key_stream = expand_to_len(&digest, c_bytes.len());
    Ok(xor_bytes(c_bytes, &key_stream))
}

fn expand_to_len(seed: &[u8], len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    if seed.is_empty() {
        return vec![0u8; len];
    }

    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let remaining = len - out.len();
        if remaining >= seed.len() {
            out.extend_from_slice(seed);
        } else {
            out.extend_from_slice(&seed[..remaining]);
        }
    }
    out
}

fn xor_bytes(message: &[u8], key_stream: &[u8]) -> Vec<u8> {
    message
        .iter()
        .zip(key_stream.iter())
        .map(|(m, k)| m ^ k)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::curves::{Ed25519, Secp256k1, Secp384r1};
    use rand::{rngs::StdRng, SeedableRng};

    fn hex_bytes(input: &str) -> Vec<u8> {
        let compact: String = input.split_whitespace().collect();
        hex::decode(compact).expect("valid hex")
    }

    fn secret_65537<E: Curve>() -> SecretScalar<E> {
        SecretScalar::from_be_bytes(&[0x01, 0x00, 0x01]).expect("valid scalar")
    }

    fn roundtrip<E: Curve>() {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let sk = SecretScalar::<E>::random(&mut rng);
        let pk = Point::<E>::generator() * sk.as_ref();
        let message = b"lockness test";

        let ciphertext = encrypt_with_rng(&mut rng, &pk, message);
        let decrypted = decrypt(&sk, &ciphertext).expect("decrypt ok");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn decrypt_ed25519_vectors() {
        let sk = secret_65537::<Ed25519>();

        let ct1 = hex_bytes(
            "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b16\
             021c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
        );
        let msg1 = hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let out1 = decrypt(&sk, &ct1).expect("decrypt ok");
        assert_eq!(out1, msg1);

        let ct2 = hex_bytes(
            "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e575\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
        );
        let msg2 = hex_bytes(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let out2 = decrypt(&sk, &ct2).expect("decrypt ok");
        assert_eq!(out2, msg2);

        let ct3 = hex_bytes(
            "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c\
             6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde\
             433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98\
             067495fdb24b782dac9da5c0eb246c9fb15c00593e",
        );
        let msg3 = hex_bytes(
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
        let out3 = decrypt(&sk, &ct3).expect("decrypt ok");
        assert_eq!(out3, msg3);
    }

    #[test]
    fn decrypt_secp256k1_vectors() {
        let sk = secret_65537::<Secp256k1>();

        let ct4 = hex_bytes(
            "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad\
             4940c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395\
             f1",
        );
        let msg4 = hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let out4 = decrypt(&sk, &ct4).expect("decrypt ok");
        assert_eq!(out4, msg4);

        let ct5 = hex_bytes(
            "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d0\
             660ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
             f6",
        );
        let msg5 = hex_bytes(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let out5 = decrypt(&sk, &ct5).expect("decrypt ok");
        assert_eq!(out5, msg5);

        let ct6 = hex_bytes(
            "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd75879\
             5f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661\
             a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24\
             e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
        );
        let msg6 = hex_bytes(
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
        let out6 = decrypt(&sk, &ct6).expect("decrypt ok");
        assert_eq!(out6, msg6);
    }

    #[test]
    fn decrypt_secp384r1_vectors() {
        let sk = secret_65537::<Secp384r1>();

        let ct7 = hex_bytes(
            "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497a\
             fb8156b91c3f5baa12b4d81b5f44f2eb402399e501ed395e834c44d5c85008ef\
             0a8b281240c5d409e4d1b85a586e493332",
        );
        let msg7 = hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let out7 = decrypt(&sk, &ct7).expect("decrypt ok");
        assert_eq!(out7, msg7);

        let ct8 = hex_bytes(
            "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa\
             5abb536caf174cc3258bf387f3e72e496c018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
             d63e456eea56a0548bba4fe135f73faa9e",
        );
        let msg8 = hex_bytes(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let out8 = decrypt(&sk, &ct8).expect("decrypt ok");
        assert_eq!(out8, msg8);

        let ct9 = hex_bytes(
            "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a\
             3e79b4895fe83593a0cbe39b4010d96c63d39a10133ef7f68aabfc63253f4537\
             337539a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268\
             337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b\
             7f773eb58706",
        );
        let msg9 = hex_bytes(
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
        let out9 = decrypt(&sk, &ct9).expect("decrypt ok");
        assert_eq!(out9, msg9);
    }

    #[test]
    fn roundtrip_all_curves() {
        roundtrip::<Ed25519>();
        roundtrip::<Secp256k1>();
        roundtrip::<Secp384r1>();
    }
}
