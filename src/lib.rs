use core::convert::TryInto;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::hash::Hash;
use core::hash::Hasher;
use core::marker::PhantomData;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use libhash::Hash as LibHash;
use libsignature::PublicKey as LibPublicKey;
use libsignature::SecretKey as LibSecretKey;
use libsignature::Signature as LibSignature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

#[derive(Clone, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Signature<H>(
    #[serde(serialize_with = "serialize_array")]
    #[serde(deserialize_with = "deserialize_array")]
    [u8; SIGNATURE_LENGTH],
    PhantomData<H>,
);

const DEFAULT_PUBLIC_KEY: PublicKey = PublicKey {
    0: [0; PUBLIC_KEY_LENGTH],
};
const DEFAULT_SECRET_KEY: SecretKey = SecretKey {
    0: [0; SECRET_KEY_LENGTH],
};

impl LibSecretKey for SecretKey {}

impl LibPublicKey for PublicKey {}

impl<H: LibHash> LibSignature for Signature<H> {
    type Hash = H;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Error = ed25519_dalek::SignatureError;
    fn sign(hash: H, key: SecretKey) -> Result<Self, Self::Error> {
        let keypair = ed25519_dalek::Keypair {
            secret: key.try_into()?,
            public: DEFAULT_PUBLIC_KEY.try_into()?,
        };
        Ok(keypair.sign(hash.as_ref()).into())
    }
    fn verify(&self, hash: H, key: PublicKey) -> Result<bool, Self::Error> {
        let pubkey: ed25519_dalek::PublicKey = key.try_into()?;
        let sig: ed25519_dalek::Signature = (*self).try_into()?;
        Ok(pubkey.verify(hash.as_ref(), &sig).is_ok())
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(k: ed25519_dalek::PublicKey) -> Self {
        PublicKey { 0: k.to_bytes() }
    }
}

impl TryInto<ed25519_dalek::PublicKey> for PublicKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_into(self) -> Result<ed25519_dalek::PublicKey, Self::Error> {
        ed25519_dalek::PublicKey::from_bytes(&(self.0))
    }
}

impl From<ed25519_dalek::SecretKey> for SecretKey {
    fn from(k: ed25519_dalek::SecretKey) -> Self {
        SecretKey { 0: k.to_bytes() }
    }
}

impl TryInto<ed25519_dalek::SecretKey> for SecretKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_into(self) -> Result<ed25519_dalek::SecretKey, Self::Error> {
        ed25519_dalek::SecretKey::from_bytes(&(self.0))
    }
}

impl<H> From<ed25519_dalek::Signature> for Signature<H> {
    fn from(s: ed25519_dalek::Signature) -> Self {
        Signature {
            0: s.to_bytes(),
            1: PhantomData,
        }
    }
}

impl<H> TryInto<ed25519_dalek::Signature> for Signature<H> {
    type Error = ed25519_dalek::SignatureError;
    fn try_into(self) -> Result<ed25519_dalek::Signature, Self::Error> {
        ed25519_dalek::Signature::from_bytes(&(self.0))
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        DEFAULT_PUBLIC_KEY
    }
}
impl Default for SecretKey {
    fn default() -> Self {
        DEFAULT_SECRET_KEY
    }
}

impl Eq for PublicKey {}

impl Eq for SecretKey {}

impl PartialEq for PublicKey {
    #[inline]
    fn eq(&self, other: &PublicKey) -> bool {
        self.0[..] == other.0[..]
    }
}

impl PartialEq for SecretKey {
    #[inline]
    fn eq(&self, other: &SecretKey) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}
impl Hash for SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let mut formatted = String::new();
        formatted.push_str(&self.0[0].to_string());
        for num in &self.0[1..self.0.len()] {
            formatted.push_str(", ");
            formatted.push_str(&num.to_string());
        }
        write!(f, "{}", formatted)
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let mut formatted = String::new();
        formatted.push_str(&self.0[0].to_string());
        for num in &self.0[1..self.0.len()] {
            formatted.push_str(", ");
            formatted.push_str(&num.to_string());
        }
        write!(f, "{}", formatted)
    }
}

impl<H> Debug for Signature<H> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let mut formatted = String::new();
        formatted.push_str(&self.0[0].to_string());
        for num in &self.0[1..self.0.len()] {
            formatted.push_str(", ");
            formatted.push_str(&num.to_string());
        }
        write!(f, "{}", formatted)
    }
}

fn serialize_array<S, T>(array: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    array.serialize(serializer)
}

fn deserialize_array<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    let mut result: [u8; 64] = [0; 64];
    let slice: Vec<u8> = Deserialize::deserialize(deserializer)?;
    if slice.len() != 64 {
        return Err(::serde::de::Error::custom("input slice has wrong length"));
    }
    result.copy_from_slice(&slice);
    Ok(result)
}

impl<H> Hash for Signature<H> {
    fn hash<Hsh: Hasher>(&self, state: &mut Hsh) {
        Hash::hash(&self.0[..], state)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
