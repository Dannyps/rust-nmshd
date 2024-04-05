use base64::prelude::*;
use ed25519_dalek::{SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand_core::OsRng; // Requires the `std` feature of `rand_core`

trait SigningKeyGetters {
    fn get_private_key(&self) -> [u8; SECRET_KEY_LENGTH];
    fn get_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH];
}

impl SigningKeyGetters for SigningKey {
    fn get_private_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        return self.to_keypair_bytes()[..SECRET_KEY_LENGTH]
            .try_into()
            .expect("Could not load key.");
    }

    fn get_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        return self.to_keypair_bytes()[SECRET_KEY_LENGTH..]
            .try_into()
            .expect("Could not load key.");
    }
}

fn main() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

    println!("{}", BASE64_STANDARD.encode(signing_key.get_private_key()));
    println!("{}", BASE64_STANDARD.encode(signing_key.get_public_key()));
}
