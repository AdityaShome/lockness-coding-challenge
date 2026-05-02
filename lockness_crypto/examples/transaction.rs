use generic_ec::{curves::Secp256k1, Point, SecretScalar};
use lockness_crypto::{decrypt, encrypt_with_rng};
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let secret_key = SecretScalar::<Secp256k1>::random(&mut rng);
    let public_key = Point::<Secp256k1>::generator() * secret_key.as_ref();
    let message = b"maintainer demo message";

    let ciphertext = encrypt_with_rng(&mut rng, &public_key, message);
    let recovered = decrypt(&secret_key, &ciphertext).expect("decrypt failed");

    println!("curve: secp256k1");
    println!("secret key (hex): {}", hex::encode(secret_key.as_ref().to_be_bytes().as_bytes()));
    println!("public key (hex): {}", hex::encode(public_key.to_bytes(true).as_bytes()));
    println!("message (utf8): {}", String::from_utf8_lossy(message));
    println!("ciphertext (hex): {}", hex::encode(&ciphertext));
    println!("recovered (utf8): {}", String::from_utf8_lossy(&recovered));
    assert_eq!(recovered, message);
}