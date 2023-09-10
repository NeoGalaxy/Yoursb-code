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

use clap::Subcommand;
use std::path::{Path, PathBuf};

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
/// YourSB Code, an encrypted files manager.
///
/// This is an executable able to encrypt files using the ChaCha20Poly1305
/// algorithm, secured by a random secret key. The key is itself encrypted
/// using a passphrase chosen by the user.
struct Cli {
    /// The location of the secret key.
    ///
    /// In command "init", if no value is given then it defaults to "./.yoursbcode.key".
    ///
    /// Otherwise, defaults to the first file named ".yoursbcode.key"
    /// when searching in current directory and recursively in its parent.
    #[arg(short, long)]
    keypath: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an encryption key. Prompts for the password to use while
    /// creating the key.
    Init,
    /// Executes an encryption. Prompts for the password to unlock the key.
    Encrypt {
        /// File to encrypt.
        file: PathBuf,

        /// Output path of the encrypted file.
        #[arg(short, long, default_value = "output.yoursbcoded")]
        output: PathBuf,
    },
    /// Executes a decryption. Prompts for the password to unlock the key.
    Decrypt {
        /// File to decrypt.
        file: PathBuf,

        /// Output path of the decrypted file.
        #[arg(short, long, default_value = "output.txt")]
        output: PathBuf,
    },
}

fn main() -> Result<(), errors::Error> {
    let args = Cli::parse();

    match args.command {
        Commands::Init => key::new_key(
            args.keypath
                .as_deref()
                .unwrap_or(Path::new(".yoursbcode.key")),
        ),
        Commands::Encrypt { file, output } => {
            let keypath = &args.keypath.ok_or(()).or_else(|()| key::find_key())?;
            let key = key::unlock_key(keypath)?;
            crypto::encrypt(&file, &output, (&key).into())
        }
        Commands::Decrypt { file, output } => {
            let keypath = &args.keypath.ok_or(()).or_else(|()| key::find_key())?;
            let key = key::unlock_key(keypath)?;
            crypto::decrypt(&file, &output, (&key).into())
        }
    }
}
