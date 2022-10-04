//https://docs.rs/orion/latest/orion/aead/index.html

use clap::*;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct VaultArgs {
    #[clap(subcommand)]
    pub cmd_option: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    // ///Create and save to file a new key.
    // Key(KeyGenCmd),
    New(NewVaultCmd),
    ///Lists name of all entries in the vault.
    List(ListCmd),
    Dump(DumpCmd),
    Add(AddEntryCmd),

    Key(ValueForKeyCmd),
}
#[derive(Debug, Args)]
pub struct KeyGenCmd {
    pub file: String,
}
#[derive(Debug, Args)]
pub struct ListCmd {}

#[derive(Debug, Args)]
pub struct DumpCmd {
    pub name: String,
}

#[derive(Debug, Args)]
pub struct NewVaultCmd {
    pub name: String,
}
#[derive(Debug, Args)]
pub struct AddEntryCmd {
    pub vault_name: String,
    pub key: String,
    pub val: String,
}
#[derive(Debug, Args)]
pub struct ValueForKeyCmd {
    pub vault_name: String,
    pub key: String,
}
