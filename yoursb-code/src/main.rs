//! YourSB Code, an encrypted files manager
//!
//! This is an executable able to encrypt files using the XChaCha20Poly1305 algorithm,
//! secured by a password.
//!
//! Note: the password is not directly used to encrypt everything, a random key is used
//! instead, itself encrypted with the password.

pub mod cli_ctx;
pub mod errors;
pub mod repo;

use std::io::{stdin, Read};
use std::path::PathBuf;

use clap::Parser;
use clap::{Args, Subcommand};
use cli_ctx::{CliCharDist, CliCtx, CliInstance, PathBufLeaf, PathBufPath};
use repo::RepoPath;
use yoursb_domain::commands as domain_cmd;
use yoursb_domain::interfaces::{Instance, NewPasswordDetails};

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
    ///   searching for a local directory. For the command "init", local will indicate
    ///   to initialize the instance in the current directory
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
        /// The location of the instance to create. Note that this is an alias to the `-i`{n}
        /// global option, and if both are given, `location` takes priority.
        location: Option<RepoPath>,

        /// The created instance will be an embedded instance, with an included executable.{n}
        /// Useful to put on an USB stick. Note that all USB formats does not support running{n}
        /// applications, we advice to format your stick into NTFS if you're on windows or linux.
        #[clap(short, long)]
        embedded: bool,
    },

    /// Indicates where is the current instance, and where one would be attempted to be{n}
    /// created with `init` command. Takes in account the `-i`/`--instance` option.{n}
    /// Check the description of the `--instance` option in `ysbc -h` for more details.{n}
    /// Aliases: `loc`, `whereis`
    #[clap(aliases = &["loc", "whereis"])]
    Locate,

    /// Clears the clipboard. Useful to easily remove a password from your clipboard{n}
    /// Aliases: `c`, `cl`
    #[clap(aliases = &["c", "cl"])]
    Clear,

    /// Allows to install or update an embedded instance
    Embedded {
        /// The location of the instance to update.
        location: RepoPath,

        /// Force the "update", even if the existing version is a newer release than the
        /// one that will be put instead
        #[clap(short, long)]
        force: bool,
    },

    /// Deletes the YourSBCode instance designated by --instance. Alias: `del`
    #[clap(aliases = &["del"])]
    Delete {
        /// Remove the prompt asking if user is sure
        #[clap(short)]
        force: bool,
    },

    /// Operations for passwords. Aliases: `p`, `pass`
    #[clap(aliases = &["p", "pass"])]
    Password {
        /// The action to do.
        #[command(subcommand)]
        action: PasswordAction,
    },

    /// Operations for files. Aliases: `f`
    #[clap(aliases = &["f"])]
    File {
        /// The action to do.
        #[command(subcommand)]
        action: FileAction,
    },
    /*/// Copies the encrypted files from an instance to another. One of them is the one specified{n}
    /// by `--instance` on the start of the command (current instance), the other one is either{n}
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
        #[arg(short = 'F', long)]
        files: bool,

        /// Be default, if the passphrase for the current instance works for the remote one,
        /// YourSBCode does not prompt for the password for a second time. This option prevents
        /// this behavior.
        #[arg(long)]
        no_reuse_passphrase: bool,
    },*/
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
pub enum PasswordAction {
    /// Creates and encrypts a password. Aliases: `e`, `en`, `encr`, `encrypt`, `c`, `new`, `add`
    #[clap(aliases = &["e", "en", "encr", "encrypt", "c", "new", "add"])]
    Create {
        /// How to name/identify the password
        identifier: String,

        /// Additional data about the password. These will be printed when
        /// the password gets decrypted (could be a comment for instance)
        data: Option<String>,

        /// When set, prompts for the password instead of generating it randomly
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
        allowed_chars: CliCharDist,

        /// If the password is randomly generated, YourSBCode will by default
        /// copy it into your clipboard. To prevent this behavior, use this option.
        #[arg(long)]
        no_copy: bool,
    },
    /// Queries for a password. Aliases: `g`, `d`, `de`, `decrypt`
    #[clap(aliases = &["g", "d", "de", "decrypt"])]
    Get {
        /// The password to find
        identifier: String,
    },
    /// List all password ids, aliases: `l`, `ls`
    #[clap(aliases = &["l", "ls"])]
    List {
        /// If specified, will filter out all the passwords that do not start by this
        #[clap(default_value = ".")]
        prefix: String,
    },
    /// Delete a password, alias: `d`, `del`
    #[clap(aliases = &["d", "del"])]
    Delete {
        /// The password to delete
        identifier: String,
    },
}

#[derive(Subcommand)]
pub enum FileAction {
    /// Encrypts a file. Aliases: `e`, `en`, `encr`, `c`, `create`, `new`, `add`
    #[clap(aliases = &["e", "en", "encr", "c", "create", "new", "add"])]
    Encrypt {
        /// File to encrypt.
        file: PathBuf,

        #[clap(flatten)]
        output: OutputFilePosArg,
    },
    /// Queries for a encrypted file. Aliases: `g`, `get`, `d`, `de`
    #[clap(aliases = &["g", "get", "d", "de"])]
    Decrypt {
        #[clap(flatten)]
        input: InputFilePosArg,

        /// Output path of the decrypted file.
        #[arg(short, long, default_value = "decrypted.txt")]
        output: PathBuf,
    },
    /// List all encrypted file ids, aliases: `l`, `ls`
    #[clap(aliases = &["l", "ls"])]
    List {
        /// If specified, will filter out all the encrypted files that do not start by this
        #[clap(default_value = ".")]
        prefix: String,
    },
    /// Delete a encrypted file from the YSBC instance, alias: `d`, `del`
    #[clap(aliases = &["d", "del"])]
    Delete {
        /// The encrypted file to delete
        identifier: String,
    },
}

fn main() /* -> Result<(), errors::Error>*/
{
    let args = Cli::parse();

    let ctx = domain_cmd::Commands::new(CliCtx);

    match args.command {
        Commands::Init { location, embedded } => {
            if embedded {
                todo!()
            }
            ctx.init_intance(location.or(args.instance).unwrap_or_default(), None)
                .unwrap();
        }
        Commands::Locate => {
            let current = CliInstance::locate();
            let new_instance_loc = args.instance.unwrap_or_default();

            println!("The current instance is located at {current}");
            // match current {
            //     Ok(current) => println!("The current instance is located at {current:?}"),
            //     Err(e) => println!("No current instance has been found: {e:?}"),
            // }

            println!("The attempt of instance creation would be at {new_instance_loc}");
        }
        Commands::Clear => todo!(),
        Commands::Embedded { location, force } => todo!(),
        Commands::Delete { force } => {
            let instance = ctx.get_instance(args.instance).unwrap();
            if !force {
                println!(
                    "This will delete all the content of directory {:?}.",
                    instance.instance.root
                );
                println!("Are you sure? (Y/n)");
                let mut buf = [0];
                stdin()
                    .read_exact(&mut buf)
                    .map_err(errors::Error::ConsoleError)
                    .unwrap();
                if (buf[0] as char).to_ascii_lowercase() != 'y' {
                    panic!("{:?}", errors::Error::Abort)
                }
            }
            instance.del_intance().unwrap();
        }
        Commands::Password { action } => {
            let mut instance = ctx.get_instance(args.instance).unwrap();
            match action {
                PasswordAction::Create {
                    identifier,
                    data,
                    prompt,
                    len,
                    allowed_chars,
                    no_copy,
                } => {
                    // TODO: check exists?

                    instance
                        .new_password(
                            PathBufLeaf(identifier.into()),
                            data,
                            if prompt {
                                NewPasswordDetails::Prompt
                            } else {
                                NewPasswordDetails::Random { len, allowed_chars }
                            },
                        )
                        .unwrap();
                    // TODO: copy
                }
                PasswordAction::Get { identifier } => {
                    let password = instance
                        .get_password(PathBufLeaf(identifier.into()))
                        .unwrap();
                    todo!("{:?}", password)
                }
                PasswordAction::List { prefix } => {
                    let _content = instance.list_content::<true>(
                        PathBufPath(instance.instance.root.to_owned()),
                        &prefix,
                    );
                    todo!()
                }
                PasswordAction::Delete { identifier } => {
                    todo!()
                }
            }
        }
        Commands::File { action } => {
            let instance = ctx.get_instance(args.instance).unwrap();
            match action {
                FileAction::Encrypt { file, output } => todo!(),
                FileAction::Decrypt { input, output } => todo!(),
                FileAction::List { prefix } => {
                    let _content = instance.list_content::<false>(
                        PathBufPath(instance.instance.root.to_owned()),
                        &prefix,
                    );
                    todo!()
                }
                FileAction::Delete { identifier } => todo!(),
            }
        }
    }
}
