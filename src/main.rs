//! YourSB Code, an encrypted files manager
//!
//! This is an executable able to encrypt files using the ChaCha20Poly1305 algorithm,
//! secured by a password.
//!
//! Note: the password is not directly used to encrypt everything, a random key is used
//! instead, itself encrypted with the password.

pub mod crypto;
pub mod errors;
pub mod key;
pub mod passwords;
pub mod project;

use clap::Subcommand;
use project::{find_project, ProjectPath};
use std::{fs, io::Read, path::PathBuf};

use clap::Parser;

use crate::errors::YoursbError;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
/// YourSB Code, an encrypted files manager.
///
/// This is an executable able to encrypt files using the ChaCha20Poly1305
/// algorithm, secured by a random secret key. The key is itself encrypted
/// using a passphrase chosen by the user.
pub struct Cli {
    /// The location of the project.
    ///
    /// Either "global", "local" or "local:<PATH>":
    ///
    /// * "global" will indicate to use a global instance of YourSBCode
    ///
    /// * "local" will indicate to look in the current directory and its parents
    /// searching for a local directory. For the command "init", local will indicate
    /// to initialize the project in the current directory
    ///
    /// * "local:<PATH>" will indicate to look at the project located at PATH
    ///
    /// Defaults to "global" if there's a global instance, or "local" otherwise.
    #[arg(short, long)]
    project: Option<ProjectPath>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create an encryption key. Prompts for the password to use while
    /// creating the key.
    Init {},

    /// Executes an encryption. Prompts for the password to unlock the key.
    #[clap(aliases = &["e", "en"])]
    Encrypt {
        /// File to encrypt.
        file: PathBuf,

        /// Output path of the encrypted file.
        #[arg(short, long, default_value = "output.yoursbcoded")]
        output: PathBuf,
    },

    /// Executes a decryption. Prompts for the password to unlock the key.
    #[clap(aliases = &["d", "de"])]
    Decrypt {
        /// File to decrypt.
        file: PathBuf,

        /// Output path of the decrypted file.
        #[arg(short, long, default_value = "output.txt")]
        output: PathBuf,
    },

    /// Executes a decryption. Prompts for the password to unlock the key.
    #[clap(aliases = &["p", "pass"])]
    Password {
        /// The action to do.
        #[command(subcommand)]
        action: Action,
    },
}

#[derive(Subcommand)]
pub enum Action {
    /// Creates and encrypts a password
    #[clap(aliases = &["c"])]
    Create {
        /// How to name/identify the password
        identifier: String,

        /// Additionnal data about the password. These will be printed when
        /// the password gets decrypted (could be a comment for isntance)
        data: Option<String>,

        /// When set, propts for the password instead of generating it randomly
        #[arg(short, long)]
        prompt: bool,

        /// Without --prompt, indicates the length of the generated password
        #[arg(short, long, default_value = "15")]
        len: u16,
    },
    /// Queries for a password
    #[clap(aliases = &["g"])]
    Get {
        /// The password to find
        identifier: String,
    },
    /// List all password ids
    List,
    /// Delete a password
    Delete {
        /// The password to delete
        identifier: String,
    },
}

fn main() -> Result<(), errors::Error> {
    let args = Cli::parse();

    match &args.command {
        Commands::Init {} => key::new_key(&args.project.unwrap_or(ProjectPath::Global).get_path()?),
        Commands::Encrypt { file, output } => {
            let input = _try!(fs::File::open(file), [file.to_owned()]);
            let bytes = input.bytes().map(|e| e.unwrap()); // TODO

            let keypath = args
                .project
                .map(|p| p.find())
                .unwrap_or_else(find_project)?;
            let key = key::unlock_key(&keypath)?;
            crypto::encrypt(bytes, output, (&key).into())
        }
        Commands::Decrypt { file, output } => {
            let keypath = args
                .project
                .map(|p| p.find())
                .unwrap_or_else(find_project)?;
            let key = key::unlock_key(&keypath)?;

            let decrypted = crypto::decrypt(file, (&key).into())?;
            _try!(fs::write(output, decrypted), [output.to_owned()]);
            Ok(())
        }
        Commands::Password { action } => passwords::run(action, &args),
    }
}
