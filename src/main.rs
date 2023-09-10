pub mod crypto;
pub mod errors;
pub mod key;

use clap::Subcommand;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[arg(short, long, default_value = ".yoursbcode.key")]
    keypath: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create encryption key
    Init,
    /// An encryption
    Encrypt {
        /// File to encrypt
        file: PathBuf,

        /// Output path of the encrypted file.
        #[arg(short, long, default_value = "output.yoursbcoded")]
        output: PathBuf,
    },
    /// A decryption
    Decrypt {
        /// File to decrypt
        file: PathBuf,

        /// Output path of the decrypted file.
        #[arg(short, long, default_value = "output.txt")]
        output: PathBuf,
    },
}

fn main() -> Result<(), errors::Error> {
    let args = Cli::parse();

    match args.command {
        Commands::Init => key::new_key(&args.keypath),
        Commands::Encrypt { file, output } => {
            let key = key::unlock_key(&args.keypath)?;
            crypto::encrypt(&file, &output, (&key).into())
        }
        Commands::Decrypt { file, output } => {
            let key = key::unlock_key(&args.keypath)?;
            crypto::decrypt(&file, &output, (&key).into())
        }
    }
}
