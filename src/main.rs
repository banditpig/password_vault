mod args;
mod vault;
use crate::args::Commands::{Add, DeleteVault, Dump, Key, List, New};
use crate::args::{AddEntryCmd, DeleteVaultCmd, DumpCmd, NewVaultCmd, ValueForKeyCmd, VaultArgs};
use crate::vault::*;

use clap::Parser;
use orion::aead;

use crate::vault::VaultError;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::string::ToString;

fn load_keygen(file_name: &str) -> Result<aead::SecretKey, VaultError> {
    let path = Path::new(file_name);
    let mut file = File::open(&path)?;
    let mut buffer = [0u8; 32];
    let _ = file.read(&mut buffer)?;
    let secret_key = aead::SecretKey::from_slice(&buffer)?;
    Ok(secret_key)
}
fn make_new_key(name: &str) -> Result<aead::SecretKey, VaultError> {
    let secret_key = aead::SecretKey::default();
    let path = Path::new(name);
    let mut file = File::create(&path)?;
    file.write_all(secret_key.unprotected_as_bytes()).unwrap();
    Ok(secret_key)
}
fn handle_new_vault_cmd(cmd: &NewVaultCmd) -> Result<(), VaultError> {
    let vault_file_name = format!("{}{}", cmd.vault_name, ".vlt");
    let key_file_name = format!("{}{}", vault_file_name, ".key");
    let secret_key = make_new_key(&key_file_name)?;
    let new_vault = Vault {
        name: cmd.vault_name.to_owned(),
        entries: HashMap::new(),
    };

    let json_vault = serde_json::to_string(&new_vault).unwrap();
    let encrypted = aead::seal(&secret_key, json_vault.as_ref())?;

    let path = Path::new(&vault_file_name);
    let mut file = File::create(&path)?;
    file.write_all(&encrypted)?;
    Ok(())
}

fn key_secret_file(name: &str) -> Result<(String, aead::SecretKey, String), VaultError> {
    let vault_key_name = VaultKeyName::key_from_name(name);
    let secret_key = load_keygen(&vault_key_name)?;
    let vault_file_name = format!("{}{}", name, ".vlt");
    Ok((vault_key_name, secret_key, vault_file_name))
}
fn handle_dump_cmd(cmd: &DumpCmd) -> Result<(), VaultError> {
    let (_, secret_key, vault_file_name) = key_secret_file(&cmd.vault_name)?;
    let path = Path::new(&vault_file_name);

    let content_encrypted = fs::read(path)?;
    let json_vec = aead::open(&secret_key, &*content_encrypted)?;

    let json = std::str::from_utf8(&json_vec)?;
    let v = serde_json::from_str::<Vault>(json).unwrap();
    println!("{:?}", v);
    Ok(())
}
fn open_vault(vault_name: &str) -> Result<Vault, VaultError> {
    let (_, secret_key, vault_file_name) = key_secret_file(vault_name)?;
    let path = Path::new(&vault_file_name);
    let content_encrypted = fs::read(path)?;
    let json_vec = aead::open(&secret_key, &*content_encrypted)?;

    let json = std::str::from_utf8(&json_vec)?;
    let v = serde_json::from_str::<Vault>(json).unwrap();
    Ok(v)
}
fn close_vault(v: Vault) -> Result<(), VaultError> {
    let (_, secret_key, vault_file_name) = key_secret_file(&v.name)?;

    let path = Path::new(&vault_file_name);
    let json_vault = serde_json::to_string(&v).unwrap();
    let encrypted = aead::seal(&secret_key, json_vault.as_ref())?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(&encrypted)?;
    f.flush()?;
    Ok(())
}
fn handle_add_cmd(cmd: &AddEntryCmd) -> Result<(), VaultError> {
    let mut vault = open_vault(&cmd.vault_name)?;
    let entry = Entry {
        key: cmd.key.clone(),
        value: cmd.val.clone(),
    };
    vault.add_entry(entry);

    close_vault(vault)?;
    Ok(())
}

fn handle_val_for_key_cmd(cmd: &ValueForKeyCmd) -> Result<String, VaultError> {
    let v = open_vault(&cmd.vault_name)?;
    match v.entries.get(&cmd.key) {
        None => Err(VaultError {
            reason: "No such key in this vault".to_string(),
        }),
        Some(val) => Ok(val.to_string()),
    }
}
fn handle_delete_vault_cmd(cmd: &DeleteVaultCmd) -> Result<(), VaultError> {
    let (vault_key_name, _, vault_file_name) = key_secret_file(&cmd.vault_name)?;

    fs::remove_file(Path::new(&vault_key_name))?;
    fs::remove_file(Path::new(&vault_file_name))?;

    Ok(())
}

fn main() -> Result<(), VaultError> {
    let args = VaultArgs::parse();

    match args.cmd_option {
        List(_) => {
            println!("list entries");
            Ok(())
        }
        New(cmd) => handle_new_vault_cmd(&cmd),
        Dump(cmd) => handle_dump_cmd(&cmd),
        Add(cmd) => handle_add_cmd(&cmd),

        Key(cmd) => {
            let key = cmd.key.clone();
            match handle_val_for_key_cmd(&cmd) {
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
        DeleteVault(cmd) => handle_delete_vault_cmd(&cmd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_eq;
    #[test]
    fn read_secret_key() {
        let name = "xxx";
        let k = make_new_key(name).unwrap();
        let x = load_keygen(name).unwrap();
        assert_eq!(k, x);
    }
}
