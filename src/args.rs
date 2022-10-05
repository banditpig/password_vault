use clap::*;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
#[command(about = "Secure vault for key/value pairs. Use symmetric key crypto.", long_about = None)]
pub struct VaultArgs {
    #[clap(subcommand)]
    pub cmd_option: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create a new vault.
    New(NewVaultCmd),
    ///Lists name of all entries in the vault.
    List(ListCmd),
    ///Dump entire contents of the vault
    Dump(DumpCmd),
    ///Add an entry to a vault.
    Add(AddEntryCmd),
    ///Get the value associated with a key.
    Key(ValueForKeyCmd),
    ///Deletes the vault and the associated key.
    #[clap(name = "delete")]
    DeleteVault(DeleteVaultCmd),
}

#[derive(Debug, Args)]
pub struct ListCmd {}

#[derive(Debug, Args)]
pub struct DumpCmd {
    pub vault_name: String,
}

#[derive(Debug, Args)]
pub struct NewVaultCmd {
    pub vault_name: String,
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
#[derive(Debug, Args)]
pub struct DeleteVaultCmd {
    pub vault_name: String,
}
