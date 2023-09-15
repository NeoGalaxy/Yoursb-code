use std::fs;
use std::fs::read_dir;
use std::io::stdout;
use std::io::Write;
use std::matches;
use std::path::Path;
use std::path::PathBuf;

use chacha20poly1305::aead::OsRng;
use rand::distributions::Standard;
use rand::Rng;

use crate::_try;
use crate::crypto;
use crate::errors;
use crate::errors::Error::ConsoleError;
use crate::errors::YoursbError;
use crate::key;
use crate::project::find_project;
use crate::project::KEY_NAME;
use crate::Action;
use crate::Cli;

use serde::{Deserialize, Serialize};

const PASSWORD_DIR: &str = "passwords";

#[derive(Debug)]
pub enum PasswordError {
    IdAlreadyUsed(String),
    InvalidUTF8File(PathBuf),
    FileNotPassword(PathBuf),
    Clipboard(arboard::Error),
}

impl From<arboard::Error> for PasswordError {
    fn from(value: arboard::Error) -> Self {
        PasswordError::Clipboard(value)
    }
}

impl From<arboard::Error> for errors::Error {
    fn from(value: arboard::Error) -> Self {
        PasswordError::from(value).into()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
    pub password: String,
    pub data: Option<String>,
}

pub fn run(action: &Action, args: &Cli) -> Result<(), errors::Error> {
    let proj_dir = args
        .project
        .as_ref()
        .map(|p| p.find())
        .unwrap_or_else(find_project)?;

    let pass_dir = proj_dir
        .parent()
        .unwrap_or(Path::new("."))
        .join(PASSWORD_DIR);

    match action {
        Action::Create {
            identifier,
            data,
            prompt,
            len,
        } => {
            let id = pass_dir.join(identifier);

            if id.exists() {
                return Err(PasswordError::IdAlreadyUsed(identifier.clone()).into());
            }

            let pass = if *prompt {
                pass_input("Enter the password to save", None)?
            } else {
                println!("Generating random password...");
                OsRng
                    .sample_iter::<char, _>(Standard)
                    .take(*len as usize)
                    .collect()
            };

            let full_data = Password {
                password: pass,
                data: data.clone(),
            };

            println!("Password will be saved as {:?}", identifier);

            crypto::encrypt(
                serde_json::to_string(&full_data)
                    .unwrap()
                    .as_bytes()
                    .iter()
                    .copied(),
                &id,
                &key::unlock_key(&proj_dir.join(KEY_NAME))?.into(),
            )?;
            println!("Password saved");
            Ok(())
        }
        Action::Get { identifier } => {
            let id_path = pass_dir.join(identifier);
            let full_data =
                crypto::decrypt(&id_path, &key::unlock_key(&proj_dir.join(KEY_NAME))?.into())?;

            let full_data: Password = serde_json::from_str(
                std::str::from_utf8(&full_data)
                    .map_err(|_| (PasswordError::InvalidUTF8File(id_path.clone())))?,
            )
            .map_err(|_| PasswordError::FileNotPassword(id_path))?;

            println!("Sucessfully uncrypted the password");
            println!();

            arboard::Clipboard::new()?.set_text(full_data.password)?;

            println!("== Password copied to Clipboard ==");

            if let Some(data) = full_data.data {
                println!("---------   associated data   ---------");
                println!("{data:?}");
                println!("---------------------------------------");
            }

            Ok(())
        }
        Action::List => {
            println!("Listing all encrypted data in the password collection:");
            for pass in _try!(read_dir(&pass_dir), [pass_dir]) {
                let pass = _try!(pass, [pass_dir]);
                println!("- {}", pass.file_name().to_string_lossy());
            }
            Ok(())
        }
        Action::Delete { identifier } => {
            let id_path = pass_dir.join(identifier);
            println!("Deleting...");
            fs::remove_file(&id_path).map_err(|e| e.convert(id_path))?;
            println!("Successfully deleted password {:?}", identifier);
            Ok(())
        }
    }
}

pub fn pass_input(prompt: &str, limit: Option<u16>) -> Result<String, errors::Error> {
    loop {
        print!("{prompt}: ");
        stdout().flush().map_err(ConsoleError)?;
        let pass = rpassword::read_password().map_err(ConsoleError)?;
        println!();
        if matches!(limit, Some(l) if pass.len() > l as usize) {
            println!("Too long password, max is 32 characters.");
            println!();
            continue;
        }
        print!("Enter the same password: ");
        stdout().flush().map_err(ConsoleError)?;
        if pass == rpassword::read_password().map_err(ConsoleError)? {
            println!();
            println!();
            break Ok(pass);
        } else {
            println!();
            println!();
            println!("Passwords do not match.");
            println!();
        }
    }
}
