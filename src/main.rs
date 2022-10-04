mod args;
use crate::args::Commands::{Add, Dump, Key, List, New};
use crate::args::{AddEntryCmd, DumpCmd, NewVaultCmd, ValueForKeyCmd, VaultArgs};
use clap::Parser;
use orion::aead;
use orion::errors::UnknownCryptoError;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::str::Utf8Error;
use std::string::ToString;
use std::{fs, io};

pub const FILE_NAME: &str = "vault.key";
//
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
struct Entry {
    key: String,
    value: String,
}
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Vault {
    name: String,
    entries: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct VaultError {
    reason: String,
}

impl Vault {
    pub fn add_entry(&mut self, e: Entry) {
        self.entries.insert(e.key, e.value);
    }
}
fn load_keygen() -> Result<aead::SecretKey, VaultError> {
    let path = Path::new(FILE_NAME);
    let mut file = File::open(&path)?;
    let mut buffer = [0u8; 32];
    let _ = file.read(&mut buffer)?;
    let secret_key = aead::SecretKey::from_slice(&buffer)?;
    Ok(secret_key)
}
fn make_new_key() -> Result<aead::SecretKey, VaultError> {
    let secret_key = aead::SecretKey::default();
    let path = Path::new(FILE_NAME);
    let mut file = File::create(&path)?;
    file.write_all(secret_key.unprotected_as_bytes()).unwrap();
    Ok(secret_key)
}
fn handle_new_vault_cmd(cmd: NewVaultCmd) -> Result<(), VaultError> {
    let secret_key = make_new_key()?;

    let new_vault = Vault {
        name: cmd.name.clone(),
        entries: HashMap::new(),
    };

    let json_vault = serde_json::to_string(&new_vault).unwrap();
    let encrypted = aead::seal(&secret_key, json_vault.as_ref())?;
    let vault_file_name = cmd.name + ".vlt";

    let path = Path::new(&vault_file_name);
    let mut file = File::create(&path)?;
    file.write_all(&encrypted)?;
    Ok(())
}
fn handle_dump_cmd(cmd: DumpCmd) -> Result<(), VaultError> {
    let secret_key = load_keygen()?;
    let vault_file_name = cmd.name + ".vlt";
    let path = Path::new(&vault_file_name);

    let content_encrypted = fs::read(path)?;
    let json_vec = aead::open(&secret_key, &*content_encrypted)?;

    let json = std::str::from_utf8(&json_vec)?;
    let v = serde_json::from_str::<Vault>(json).unwrap();
    println!("{:?}", v);
    Ok(())
}
fn open_vault(vault_name: String) -> Result<Vault, VaultError> {
    let secret_key = load_keygen()?;
    let vault_file_name = vault_name + ".vlt";
    let path = Path::new(&vault_file_name);

    let content_encrypted = fs::read(path)?;
    let json_vec = aead::open(&secret_key, &*content_encrypted)?;

    let json = std::str::from_utf8(&json_vec)?;

    let v = serde_json::from_str::<Vault>(json).unwrap();
    Ok(v)
}
fn close_vault(v: Vault) -> Result<(), VaultError> {
    let secret_key = load_keygen()?;
    let vault_file_name = v.name.clone() + ".vlt";
    let path = Path::new(&vault_file_name);
    let json_vault = serde_json::to_string(&v).unwrap();
    let encrypted = aead::seal(&secret_key, json_vault.as_ref())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(&encrypted)?;
    f.flush()?;
    Ok(())
}
fn handle_add_cmd(cmd: AddEntryCmd) -> Result<(), VaultError> {
    let mut vault = open_vault(cmd.vault_name)?;
    let entry = Entry {
        key: cmd.key,
        value: cmd.val,
    };
    vault.add_entry(entry);

    close_vault(vault)?;
    Ok(())
}

fn handle_val_for_key_cmd(cmd: ValueForKeyCmd) -> Result<String, VaultError> {
    let v = open_vault(cmd.vault_name)?;
    match v.entries.get(&cmd.key) {
        None => Err(VaultError {
            reason: "No such key in this vault".to_string(),
        }),
        Some(val) => Ok(val.to_string()),
    }
}
fn main() -> Result<(), VaultError> {
    let args = VaultArgs::parse();

    match args.cmd_option {
        List(_) => {
            println!("list entries");
            Ok(())
        }
        New(cmd) => handle_new_vault_cmd(cmd),
        Dump(cmd) => handle_dump_cmd(cmd),
        Add(cmd) => handle_add_cmd(cmd),
        Key(cmd) => {
            let key = cmd.key.clone();
            match handle_val_for_key_cmd(cmd) {
                Ok(val) => {
                    println!("Key {} has value: {}", key, val);
                    println!("The value is now in the clipboard.");
                    cli_clipboard::set_contents(val).unwrap();
                }
                Err(e) => {
                    println!("{}", e)
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_eq;
    #[test]
    fn read_secret_key() {
        let k = make_new_key().unwrap();
        let x = load_keygen().unwrap();
        assert_eq!(k, x);
    }
}
