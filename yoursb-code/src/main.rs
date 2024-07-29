//! YourSB Code, an encrypted files manager
//!
//! This is an executable able to encrypt files using the XChaCha20Poly1305 algorithm,
//! secured by a password.
//!
//! Note: the password is not directly used to encrypt everything, a random key is used
//! instead, itself encrypted with the password.

pub mod crypto;
pub mod errors;
pub mod key;
pub mod passwords;
pub mod repo;

use passwords::CharsDist;
use repo::{find_repo, FilePos, RepoPath, KEY_NAME};
use std::{
    fs::{self, create_dir_all, remove_dir_all},
    io::{stdin, Read},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

use clap::Parser;
use clap::{Args, Subcommand};

use crate::{
    crypto::{decrypt_from, encrypt_to},
    errors::YoursbError,
    key::ask_passphase,
    passwords::PASSWORD_DIR,
    repo::FILES_DIR,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
/// YourSB Code, an encrypted files manager.
///
/// This is an executable able to encrypt files using the XChaCha20Poly1305
/// algorithm, secured by a random secret key. The key is itself encrypted
/// using a passphrase chosen by the user.
pub struct Cli {
    /// The location of the current instance.
    ///
    /// Either "global", "local" or "local:<PATH>":
    ///
    /// * "global" will indicate to use a global instance of YourSBCode
    ///
    /// * "local" will indicate to look in the current directory and its parents
    /// searching for a local directory. For the command "init", local will indicate
    /// to initialize the instance in the current directory
    ///
    /// * "local:<PATH>" will indicate to look at the instance located at PATH
    ///
    /// Defaults to "local" if there's a local instance, or "global" otherwise,
    /// except for command `init`
    #[arg(short, long)]
    instance: Option<RepoPath>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a YourSBCode instance. Prompts for the passphrase to use for this instance.
    Init {
        /// The location of the instance to create. Note that this is an alias to the `-i`
        /// global option, and if both are given, `location` takes priority.
        location: Option<RepoPath>,

        /// The created instance will be an embedded instance, with an included executable.
        /// Useful to put on an USB stick. Note that all USB formats does not support running
        /// applications, we advice to format your stick into NTFS if you're on windows or linux.
        #[clap(short, long)]
        embedded: bool,
    },

    /// Indicates where is the current instance, and where one would be attempted to be
    /// created with `init` command. Takes in account the `-i`/`--instance` option.
    /// Check `YourSBCode -h` for more details.
    /// Aliases: `loc`, `whereis`
    #[clap(aliases = &["loc", "whereis"])]
    Locate,

    /// Deletes the YourSBCode instance designated by --instance. Alias: `del`
    #[clap(aliases = &["del"])]
    Delete {
        /// Remove the prompt asking if user is sure
        #[clap(short)]
        force: bool,
    },

    /// Executes an encryption. Prompts for the passphrase to unlock the key. Aliases: `e`, `en`
    #[clap(aliases = &["e", "en"])]
    Encrypt {
        /// File to encrypt.
        file: PathBuf,

        /// output file.
        #[clap(flatten)]
        output: OutputFilePosArg,
    },

    /// Executes a decryption. Prompts for the passphrase to unlock the key. Aliases: `d`, `de`
    #[clap(aliases = &["d", "de"])]
    Decrypt {
        /// input file.
        #[clap(flatten)]
        input: InputFilePosArg,

        /// Output path of the decrypted file.
        #[arg(short, long, default_value = "output.txt")]
        output: PathBuf,
    },

    /// Displays the elements in the global YourSBCode instance. The displayed element ids stops
    /// {n}at the first encountered `/` after the prefix. This does NOT require the passphrase.
    Ls {
        /// The prefix of the elements to display
        #[clap(default_value = ".")]
        prefix: String,
    },

    /// Executes a decryption. Prompts for the passphrase to unlock the key. Aliases: `p`, `pass`
    #[clap(aliases = &["p", "pass"])]
    Password {
        /// The action to do.
        #[command(subcommand)]
        action: Action,
    },

    /// Copies the encrypted files from an instance to another. One of them is the one specified
    /// by `--instance` on the start of the command (current instance), the other one is either
    /// from the option `--from` or `--into` in this subcommand (remote instance).
    ///
    /// This command will first ask the key of the "current instance" and then the one of the
    /// "remote instance".
    #[clap(aliases = &["up"])]
    #[group(required = true, multiple = false)]
    Update {
        /// Location of the "remote" instance. The command will then copy files from this instance
        /// into the "current instance".
        ///
        /// Either "global", "local" or "local:<PATH>".
        #[arg(short, long)]
        from: Option<RepoPath>,

        /// Location of the "remote instance". The command will then copy files from the
        /// "current instance" into this "remote instance".
        ///
        /// Either "global", "local" or "local:<PATH>".
        #[arg(short, long)]
        into: Option<RepoPath>,

        /// If set, passwords will be copied. If neither `--passwords` nor `--files` is set,
        /// copies both.
        #[arg(short, long)]
        passwords: bool,

        /// If set, files will be copied. If neither `--passwords` nor `--files` is set,
        /// copies both.
        #[arg(short, long)]
        files: bool,

        /// Be default, if the passphrase for the current instance works for the remote one,
        /// YourSBCode does not prompt for the password for a second time. This option prevents
        /// this behaviour.
        #[arg(long)]
        no_reuse_passphrase: bool,
    },
}

#[derive(Debug, Args, Clone)]
#[group(required = true, multiple = false)]
pub struct InputFilePosArg {
    /// Identifier of the internal file to decrypt from the YourSBCode instance
    #[arg(id = "identifier", short, long)]
    internal: Option<PathBuf>,

    /// Path to the encrypted input file
    #[arg(id = "path", short, long)]
    external: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
#[group(required = true, multiple = false)]
pub struct OutputFilePosArg {
    /// Identifier of the internal file to store the encrypted input in the YourSBCode instance
    #[arg(id = "identifier", short, long)]
    internal: Option<PathBuf>,

    /// Path towards which we'll encrypt the file
    #[arg(id = "path", short, long)]
    external: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Action {
    /// Creates and encrypts a password. Alias: `c`
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
        #[arg(short, long, default_value = "20")]
        len: u16,

        /// The allowed characters in the password when it's randomly generated.
        /// The syntax for ranges is `s..e` where `s` is the start and `e` is
        /// the end. Spaces are allowed anywhere except in a range and will not
        /// be in the password.
        #[arg(short, long, default_value = "a..z A..Z !#$%&'*+,-./:;<>=?@^_`|~")]
        allowed_chars: CharsDist,

        /// If the password is randombly generated, YourSBCode will by default
        /// copy it into your clipboard. To prevent this behaviour, use this option.
        #[arg(long)]
        no_copy: bool,
    },
    /// Queries for a password, alias: `g`
    #[clap(aliases = &["g"])]
    Get {
        /// The password to find
        identifier: String,
    },
    /// List all password ids, aliases: `l`, `ls`
    #[clap(aliases = &["l", "ls"])]
    List,
    /// Delete a password, alias: `del`
    #[clap(aliases = &["del"])]
    Delete {
        /// The password to delete
        identifier: String,
    },
}

fn main() -> Result<(), errors::Error> {
    let args = Cli::parse();

    match args.command {
        Commands::Init { location, embedded } => {
            let instance = location.or(args.instance).unwrap_or(RepoPath::Global);
            match &instance {
                RepoPath::Local(path) => {
                    println!("Creating YourSBCode instance in dir {path:?}")
                }
                RepoPath::Global => println!("Creating global YourSBCode instance"),
            }
            let instance_dir = instance.get_path()?;

            let keypath = instance_dir.join(KEY_NAME);
            if keypath.exists() {
                return Err(errors::Error::RepoAlreadyExists);
            }

            if let Some(p) = keypath.parent() {
                let _ = create_dir_all(p);
            }

            key::new_key(&keypath)?;

            if embedded {
                repo::write_embedded_execs(&instance_dir)?;
            }

            Ok(())
        }

        Commands::Locate => {
            let instance_path = args
                .instance
                .clone()
                .map(|p| p.find())
                .unwrap_or_else(find_repo);

            let new_instance_path = args.instance.unwrap_or(RepoPath::Global).get_path()?;

            match instance_path {
                Ok(path) => println!("The current instance is located at {path:?}"),
                Err(e) => println!("No current instance has been found: {e:?}"),
            }

            println!("The attempt of instance creation would be at {new_instance_path:?}");

            Ok(())
        }

        Commands::Delete { force } => {
            let instance_path = args.instance.map(|p| p.find()).unwrap_or_else(find_repo)?;

            if !force {
                println!("This will delete all the content of directory {instance_path:?}.");
                println!("Are you sure? (Y/n)");
                let mut buf = [0];
                stdin()
                    .read_exact(&mut buf)
                    .map_err(errors::Error::ConsoleError)?;
                if (buf[0] as char).to_ascii_lowercase() != 'y' {
                    return Err(errors::Error::Abort);
                }
            }

            _try!(remove_dir_all(&instance_path), [instance_path]);
            Ok(())
        }

        Commands::Encrypt { file, output } => {
            let output: FilePos = output.clone().into();
            let input = _try!(fs::File::open(&file), [file.to_owned()]);
            let bytes = input.bytes().map(|e| e.unwrap()); // TODO

            let instance_path = args.instance.map(|p| p.find()).unwrap_or_else(find_repo)?;

            let key = key::unlock_key(&instance_path.join(KEY_NAME))?;

            let output = output.to_path(&instance_path);

            crypto::encrypt_to(bytes, &output, (&key).into())
        }

        Commands::Decrypt { input, output } => {
            let input: FilePos = input.clone().into();

            let instance_path = args.instance.map(|p| p.find()).unwrap_or_else(find_repo)?;

            let key = key::unlock_key(&instance_path.join(KEY_NAME))?;

            let input = input.to_path(&instance_path);

            let decrypted = crypto::decrypt_from(&input, (&key).into())?;
            _try!(fs::write(&output, decrypted), [output.to_owned()]);
            Ok(())
        }

        Commands::Ls { prefix } => {
            let instance_path = args.instance.map(|p| p.find()).unwrap_or_else(find_repo)?;

            repo::find_files(instance_path, &prefix)?.for_each(|e| {
                if let Ok(p) = e {
                    println!("{p:?}");
                }
            });
            Ok(())
        }

        Commands::Password { ref action } => passwords::run(action, &args),

        Commands::Update {
            from,
            into,
            passwords,
            files,
            no_reuse_passphrase,
        } => {
            println!("Finding instances...");

            let instance_path = args.instance.map(|p| p.find()).unwrap_or_else(find_repo)?;

            let (source, dest, source_is_remote) = if let Some(source) = from {
                let source_path = source.find()?;
                (source_path, instance_path, true)
            } else if let Some(dest) = into {
                let dest_path = dest.find()?;
                (instance_path, dest_path, false)
            } else {
                unreachable!()
            };

            println!();
            println!("Copying from:");
            println!("{source:?}");
            println!("to:");
            println!("{dest:?}");
            println!();

            let (source_key, dest_key);

            let get_keys = |current: &Path, remote: &Path| -> Result<_, errors::Error> {
                println!("Unlocking current instance key (at {current:?})...");
                let passphrase = ask_passphase()?;
                let current_key = key::unlock_key_with(&current.join(KEY_NAME), &passphrase)?;
                println!("Passphrase valid.");

                println!("Unlocking remote instance key (at {remote:?})...");
                let keypath = &remote.join(KEY_NAME);
                let res = if !no_reuse_passphrase {
                    key::unlock_key_with(keypath, &passphrase).ok()
                } else {
                    None
                };
                let remote_key = match res {
                    Some(k) => {
                        println!("Passphrase valid.");
                        k
                    }
                    None => key::unlock_key(keypath)?,
                };
                Ok((current_key, remote_key))
            };
            if source_is_remote {
                (dest_key, source_key) = get_keys(&dest, &source)?;
            } else {
                (source_key, dest_key) = get_keys(&source, &dest)?;
            };

            let copy_dir = |subdir| {
                if !source.join(subdir).exists() {
                    println!("Nothing in {subdir}.");
                    return;
                };
                if !dest.join(subdir).exists() {
                    if let Err(e) = create_dir_all(dest.join(subdir)) {
                        eprintln!("ERROR: {e}");
                    }
                    return;
                }
                for entry in WalkDir::new(source.join(subdir)) {
                    let entry: PathBuf = match entry {
                        Ok(e) => e.into_path(),
                        Err(err) => {
                            eprintln!("ERROR: {err}");
                            continue;
                        }
                    };

                    if entry.is_dir() {
                        eprintln!(
                            "- Entering {:?}",
                            entry
                                .strip_prefix(source.clone())
                                .expect("Internal error: entry isn't in source;")
                        );
                        continue;
                    }

                    if !entry.is_file() {
                        eprintln!("ERROR: entry {entry:?} is neither a directory nor a file");
                        continue;
                    }

                    let decrypted = match decrypt_from(&entry, (&source_key).into()) {
                        Ok(d) => d,
                        Err(err) => {
                            eprintln!("DECRYPTING ERROR: {err:?}");
                            continue;
                        }
                    };

                    let dest_file = dest.join(
                        entry
                            .strip_prefix(source.clone())
                            .expect("Internal error: entry isn't in source;"),
                    );
                    match encrypt_to(decrypted.into_iter(), &dest_file, (&dest_key).into()) {
                        Ok(()) => {
                            eprintln!(
                                "- Copied {:?}",
                                entry
                                    .strip_prefix(source.clone())
                                    .expect("Internal error: entry isn't in source;")
                            );
                        }
                        Err(err) => {
                            eprintln!("DECRYPTING ERROR: {err:?}");
                        }
                    }
                }
            };
            println!();
            if passwords || !files {
                println!("Copying passwords...");
                copy_dir(PASSWORD_DIR);
            } else {
                println!("Skipped passwords");
            }

            println!();
            if files || !passwords {
                println!("Copying regular files...");
                copy_dir(FILES_DIR);
            } else {
                println!("Skipped regular files");
            }

            Ok(())
        }
    }
}
