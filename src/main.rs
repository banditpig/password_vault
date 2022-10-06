extern crate core;

mod args;
mod vault;
use crate::args::Commands::{Add, DeleteKey, DeleteVault, Dump, Key, List, New};
use crate::args::{
    AddEntryCmd, DeleteKeyCmd, DeleteVaultCmd, DumpCmd, NewVaultCmd, ValueForKeyCmd, VaultArgs,
};
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
    let mut file = File::open(&file_name)?;
    let mut buffer = [0u8; 32];
    let _ = file.read(&mut buffer)?;
    let secret_key = aead::SecretKey::from_slice(&buffer)?;
    Ok(secret_key)
}
fn make_new_key(name: &str) -> Result<aead::SecretKey, VaultError> {
    let secret_key = aead::SecretKey::default();

    let mut file = File::create(&name)?;
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

    let mut file = File::create(&vault_file_name)?;
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

    let content_encrypted = fs::read(&vault_file_name)?;
    let json_vec = aead::open(&secret_key, &*content_encrypted)?;

    let json = std::str::from_utf8(&json_vec)?;
    let v = serde_json::from_str::<Vault>(json).unwrap();
    println!("{:?}", v);
    Ok(())
}
fn open_vault(vault_name: &str) -> Result<Vault, VaultError> {
    let (_, secret_key, vault_file_name) = key_secret_file(vault_name)?;

    let content_encrypted = fs::read(&vault_file_name)?;
    let json_vec = aead::open(&secret_key, &*content_encrypted)?;

    let json = std::str::from_utf8(&json_vec)?;
    let v = serde_json::from_str::<Vault>(json).unwrap();
    Ok(v)
}
fn close_vault(v: Vault) -> Result<(), VaultError> {
    let (_, secret_key, vault_file_name) = key_secret_file(&v.name)?;

    let json_vault = serde_json::to_string(&v).unwrap();
    let encrypted = aead::seal(&secret_key, json_vault.as_ref())?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&vault_file_name)?;
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
fn handle_delete_key(cmd: &DeleteKeyCmd) -> Result<(), VaultError> {
    let mut vault = open_vault(&cmd.vault_name)?;

    match vault.entries.remove(&cmd.key) {
        None => {
            close_vault(vault)?;
            Err(VaultError {
                reason: "Unknown key".to_string(),
            })
        }
        Some(_) => {
            close_vault(vault)?;
            Ok(())
        }
    }
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

    fs::remove_file(&vault_key_name)?;
    fs::remove_file(&vault_file_name)?;

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
        DeleteKey(cmd) => handle_delete_key(&cmd),
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
    use claim::*;
    use std::assert_eq;
    #[test]
    fn read_secret_key() {
        let name = "xxx";
        let k = make_new_key(name).unwrap();
        let x = load_keygen(name).unwrap();
        assert_eq!(k, x);
    }

    #[test]
    fn new_vault_created() {
        let cmd = NewVaultCmd {
            vault_name: "test1".to_string(),
        };
        assert_ok!(handle_new_vault_cmd(&cmd));

        assert!(Path::new("test1.vlt.key").exists());
        assert!(Path::new("test1.vlt").exists());
    }
    #[test]
    fn add_entry_read_back() {
        let cmd = NewVaultCmd {
            vault_name: "test2".to_string(),
        };
        assert_ok!(handle_new_vault_cmd(&cmd));

        let add_cmd = AddEntryCmd {
            vault_name: "test2".to_string(),
            key: "name".to_string(),
            val: "fred".to_string(),
        };
        assert_ok!(handle_add_cmd(&add_cmd));
        //read back
        let cmd = ValueForKeyCmd {
            vault_name: "test2".to_string(),
            key: "name".to_string(),
        };
        let r = handle_val_for_key_cmd(&cmd);
        assert_ok!(&r);
        let val = r.unwrap();
        assert_eq!(val, "fred".to_string());
    }

    #[test]
    fn add_entry_delete_it_try_read_back() {
        let cmd = NewVaultCmd {
            vault_name: "test3".to_string(),
        };
        assert_ok!(handle_new_vault_cmd(&cmd));

        let add_cmd = AddEntryCmd {
            vault_name: "test3".to_string(),
            key: "name".to_string(),
            val: "fred".to_string(),
        };
        assert_ok!(handle_add_cmd(&add_cmd));
        //read back
        let cmd = ValueForKeyCmd {
            vault_name: "test3".to_string(),
            key: "name".to_string(),
        };
        let r = handle_val_for_key_cmd(&cmd);
        assert_ok!(&r);
        let val = r.unwrap();
        assert_eq!(val, "fred".to_string());

        let cmd = DeleteKeyCmd {
            vault_name: "test3".to_string(),
            key: "name".to_string(),
        };
        let r = handle_delete_key(&cmd);
        assert_ok!(&r);
        //now try retrieve "fred"
        let cmd = ValueForKeyCmd {
            vault_name: "test3".to_string(),
            key: "name".to_string(),
        };
        let r = handle_val_for_key_cmd(&cmd);
        match r {
            Ok(_) => {
                assert!(false)
            }
            Err(s) => {
                assert_eq!(s.reason, "No such key in this vault".to_string())
            }
        }
    }
}
