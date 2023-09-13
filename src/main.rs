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

use clap::{Args, Subcommand};
use project::{find_project, FilePos, ProjectPath, KEY_NAME};
use std::{
    fs::{self, create_dir_all},
    io::Read,
    path::PathBuf,
};

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
    /// Defaults to "local" if there's a local instance, or "global" otherwise.
    #[arg(short, long)]
    project: Option<ProjectPath>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a YourSBCode instance. Prompts for the passphrase to use for this instance.
    Init {},

    /// Executes an encryption. Prompts for the passphrase to unlock the key.
    #[clap(aliases = &["e", "en"])]
    Encrypt {
        /// File to encrypt.
        file: PathBuf,

        /// output file.
        #[clap(flatten)]
        output: FilePosArg,
    },

    /// Executes a decryption. Prompts for the passphrase to unlock the key.
    #[clap(aliases = &["d", "de"])]
    Decrypt {
        /// input file.
        #[clap(flatten)]
        input: FilePosArg,

        /// Output path of the decrypted file.
        #[arg(short, long, default_value = "output.txt")]
        output: PathBuf,
    },

    /// Displays the elements in the global YourSBCode instance. The displayed element ids
    /// stops at the first encountered `/` after the prefix. This does NOT require the
    /// passphrase.
    Ls {
        /// The prefix of the elements to display
        #[clap(default_value = ".")]
        prefix: String,
    },

    /// Executes a decryption. Prompts for the passphrase to unlock the key.
    #[clap(aliases = &["p", "pass"])]
    Password {
        /// The action to do.
        #[command(subcommand)]
        action: Action,
    },
}

#[derive(Debug, Args, Clone)]
#[group(required = true, multiple = false)]
pub struct FilePosArg {
    /// Identifier of the internal file to the YourSBCode instance
    #[arg(id = "identifier", short, long)]
    internal: Option<PathBuf>,

    /// Path to the encrypted file
    #[arg(id = "path", short, long)]
    external: Option<PathBuf>,
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
        Commands::Init {} => {
            let project = args.project.unwrap_or(ProjectPath::Global);
            match &project {
                ProjectPath::Local(path) => {
                    println!("Creating YourSBCode instance in dir {path:?}")
                }
                ProjectPath::Global => println!("Creating global YourSBCode instance"),
            }
            let project_dir = project.get_path()?;

            let keypath = project_dir.join(KEY_NAME);
            if keypath.exists() {
                return Err(errors::Error::ProjectAlreadyExists);
            }

            if let Some(p) = keypath.parent() {
                let _ = create_dir_all(p);
            }

            key::new_key(&keypath)
        }

        Commands::Encrypt { file, output } => {
            let output: FilePos = output.clone().into();
            let input = _try!(fs::File::open(file), [file.to_owned()]);
            let bytes = input.bytes().map(|e| e.unwrap()); // TODO

            let project_path = args
                .project
                .map(|p| p.find())
                .unwrap_or_else(find_project)?;

            let key = key::unlock_key(&project_path.join(KEY_NAME))?;

            let output = output.to_path(&project_path);

            crypto::encrypt(bytes, &output, (&key).into())
        }

        Commands::Decrypt { input, output } => {
            let input: FilePos = (*input).clone().into();

            let project_path = args
                .project
                .map(|p| p.find())
                .unwrap_or_else(find_project)?;

            let key = key::unlock_key(&project_path.join(KEY_NAME))?;

            let input = input.to_path(&project_path);

            let decrypted = crypto::decrypt(&input, (&key).into())?;
            _try!(fs::write(output, decrypted), [output.to_owned()]);
            Ok(())
        }

        Commands::Ls { prefix } => {
            let project_path = args
                .project
                .map(|p| p.find())
                .unwrap_or_else(find_project)?;

            project::find_files(project_path, prefix)?.for_each(|e| {
                if let Ok(p) = e {
                    println!("{p:?}");
                }
            });
            Ok(())
        }

        Commands::Password { action } => passwords::run(action, &args),
    }
}
