//! Module that manages passwords

use std::fmt::Display;
use std::fs;
use std::fs::read_dir;
use std::io::stdout;
use std::io::Write;
use std::matches;
use std::ops::RangeInclusive;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use chacha20poly1305::aead::OsRng;

use rand::distributions::Uniform;
use rand::Rng;

use crate::_try;
use crate::crypto;
use crate::errors;
use crate::errors::Error::ConsoleError;
use crate::errors::YoursbError;
use crate::key;
use crate::repo::find_repo;
// use crate::repo::FILES_DIR;
use crate::repo::KEY_NAME;
use crate::Action;
use crate::Cli;

use serde::{Deserialize, Serialize};

/// The name of the directory containing passwords
pub const PASSWORD_DIR: &str = "passwords";

/// An error while handleing passwords
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

/// A password with optionnal data
#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<String>,
}

/// A representation of the allowed chars in a password. It contains a vector
/// of the allowed intervals of characters.
///
/// It can be parsed from a string, see the [`allowed_chars`](crate::Cli.allowed_chars)
/// command-line argument for more details.
#[derive(Clone, Debug)]
pub struct CharsDist(Vec<(char, char)>);

/// An error kind indicating the parsing of a [`CharsDist`] didn't go well.
#[derive(Clone, Debug)]
pub struct InvalidSyntax {
    pos: usize,
}

impl Display for InvalidSyntax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Invalid syntax at index {}", self.pos))
    }
}

impl std::error::Error for InvalidSyntax {}

impl FromStr for CharsDist {
    type Err = InvalidSyntax;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars().enumerate().peekable();
        let mut res = vec![];
        while let Some((_, c)) = chars.next() {
            if c == ' ' {
                continue;
            }

            let start = c;
            if let Some((_, '.')) = chars.peek() {
                chars.next().unwrap();
                if let Some((i, '.')) = chars.peek().copied() {
                    let end = chars
                        .nth(1)
                        .and_then(|(_, c)| if c == ' ' { None } else { Some(c) })
                        .ok_or(InvalidSyntax { pos: i })?;
                    if start > end {
                        return Err(InvalidSyntax { pos: i });
                    }
                    res.push((start, end));
                    continue;
                }

                res.push((start, start));
                res.push(('.', '.'));
                continue;
            }

            res.push((start, start));
        }

        Ok(Self(res))
    }
}

/// Run the password manager
///
/// TODO: make functions with each fonctionnality
pub fn run(action: &Action, args: &Cli) -> Result<(), errors::Error> {
    let proj_dir = args
        .instance
        .as_ref()
        .map(|p| p.find())
        .unwrap_or_else(find_repo)?;

    let pass_dir = proj_dir.join(PASSWORD_DIR);

    match action {
        Action::Create {
            identifier,
            data,
            prompt,
            len,
            allowed_chars,
            no_copy,
        } => {
            let id = pass_dir.join(identifier);
            let sections = &allowed_chars.0;

            if id.exists() {
                return Err(PasswordError::IdAlreadyUsed(identifier.clone()).into());
            }

            // let sections = ['a'..='z', 'A'..='Z', '!'..='@'];

            let sections_len = sections
                .iter()
                .fold(0, |acc, (start, end)| acc + 1 + *end as u32 - *start as u32);

            let pass = if *prompt {
                pass_input("Enter the password to save", None)?
            } else {
                println!("Generating random password...");
                OsRng
                    .sample_iter(Uniform::new_inclusive(0, sections_len - 1))
                    .take(*len as usize)
                    .map(|mut i| {
                        let mut j = 0;
                        while i > sections[j].1 as u32 - sections[j].0 as u32 {
                            i -= 1 + sections[j].1 as u32 - sections[j].0 as u32;
                            j += 1;
                        }
                        let s = sections[j];
                        RangeInclusive::new(s.0, s.1).nth(i as usize).unwrap()
                    })
                    .collect()
            };

            let full_data = Password {
                password: pass,
                data: data.clone(),
            };

            println!("Password will be saved as {:?}", identifier);

            crypto::encrypt_to(
                serde_json::to_string(&full_data)
                    .unwrap()
                    .as_bytes()
                    .iter()
                    .copied(),
                &id,
                &key::unlock_key(&proj_dir.join(KEY_NAME))?.into(),
            )?;
            println!("Password saved");

            if !*prompt && !no_copy {
                let res =
                    arboard::Clipboard::new().and_then(|mut c| c.set_text(&full_data.password));
                if let Err(err) = res {
                    println!("Unable to copy password to Clipboard: {err}");
                } else {
                    println!("== Password copied to Clipboard ==");
                }
            }
            Ok(())
        }
        Action::Get { identifier } => {
            let id_path = pass_dir.join(identifier);
            let full_data =
                crypto::decrypt_from(&id_path, &key::unlock_key(&proj_dir.join(KEY_NAME))?.into())?;

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
            for pass in _try!(read_dir(&pass_dir), [Path::new("passwords/").into()]) {
                let pass = _try!(pass, [Path::new("passwords/").into()]);
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

/// Prompts for a new password
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
