use orion::errors::UnknownCryptoError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::str::Utf8Error;

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> VaultError {
        VaultError {
            reason: e.to_string(),
        }
    }
}

impl From<Utf8Error> for VaultError {
    fn from(e: Utf8Error) -> VaultError {
        VaultError {
            reason: e.to_string(),
        }
    }
}
impl From<UnknownCryptoError> for VaultError {
    fn from(e: UnknownCryptoError) -> VaultError {
        VaultError {
            reason: e.to_string(),
        }
    }
}

impl Display for VaultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultKeyName;

impl VaultKeyName {
    pub fn key_from_name(name: &str) -> String {
        format!("{}{}", name, ".vlt.key")
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vault {
    pub name: String,
    pub entries: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct VaultError {
    pub reason: String,
}

impl Vault {
    pub fn add_entry(&mut self, e: Entry) {
        self.entries.insert(e.key, e.value);
    }
}
