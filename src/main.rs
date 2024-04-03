use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey, Verifier, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
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
            &self.to_keypair_bytes()[SECRET_KEY_LENGTH..SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH],
        );
        return a;
    }
}

fn main() {
    /// `HelloSigner` defined above instantiated with `ed25519-dalek` as
    /// the signing provider.
    pub type DalekHelloSigner = HelloSigner<ed25519_dalek::SigningKey>;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let signer = DalekHelloSigner { signing_key };
    let person = "Joe"; // Message to sign
    let signature = signer.sign(person);

    /// `HelloVerifier` defined above instantiated with `ed25519-dalek`
    /// as the signature verification provider.
    pub type DalekHelloVerifier = HelloVerifier<ed25519_dalek::VerifyingKey>;

    let verifying_key: ed25519_dalek::VerifyingKey = signer.signing_key.verifying_key();
    let verifier = DalekHelloVerifier { verifying_key };
    assert!(verifier.verify(person, &signature).is_ok());

    println!(
        "{}",
        BASE64_STANDARD.encode(signer.signing_key.get_private_key())
    );
    println!(
        "{}",
        BASE64_STANDARD.encode(signer.signing_key.get_public_key())
    );
}

pub struct HelloSigner<S>
where
    S: Signer<ed25519::Signature>,
{
    pub signing_key: S,
}

impl<S> HelloSigner<S>
where
    S: Signer<ed25519::Signature>,
{
    pub fn sign(&self, person: &str) -> ed25519::Signature {
        // NOTE: use `try_sign` if you'd like to be able to handle
        // errors from external signing services/devices (e.g. HSM/KMS)
        // <https://docs.rs/signature/latest/signature/trait.Signer.html#tymethod.try_sign>
        self.signing_key.sign(format_message(person).as_bytes())
    }
}

pub struct HelloVerifier<V> {
    pub verifying_key: V,
}

impl<V> HelloVerifier<V>
where
    V: Verifier<ed25519::Signature>,
{
    pub fn verify(
        &self,
        person: &str,
        signature: &ed25519::Signature,
    ) -> Result<(), ed25519::Error> {
        self.verifying_key
            .verify(format_message(person).as_bytes(), signature)
    }
}

fn format_message(person: &str) -> String {
    format!("Hello, {}!", person)
}
