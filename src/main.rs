use base64::prelude::*;
use ed25519_dalek::{SigningKey, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand_core::OsRng; // Requires the `std` feature of `rand_core`

trait SigningKeyGetters {
    fn get_private_key(&self) -> [u8; SECRET_KEY_LENGTH];
    fn get_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH];
}

impl SigningKeyGetters for SigningKey {
    fn get_private_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        let mut a: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        a.copy_from_slice(&self.to_keypair_bytes()[0..SECRET_KEY_LENGTH]);
        return a;
    }

    fn get_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut a: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        a.copy_from_slice(
            &self.to_keypair_bytes()[SECRET_KEY_LENGTH..KEYPAIR_LENGTH],
        );
        return a;
    }
}

fn main() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

    println!(
        "{}",
        BASE64_STANDARD.encode(signing_key.get_private_key())
    );
    println!(
        "{}",
        BASE64_STANDARD.encode(signing_key.get_public_key())
    );
}