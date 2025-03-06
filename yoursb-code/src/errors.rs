//! This module defines the possible errors from this software

use std::{fmt::Display, io, path::PathBuf};

use yoursb_domain::crypto::{Argon2Error, DecryptionError, KeyDecryptionError};

use crate::repo::RepoPath;

// use crate::passwords::PasswordError;

/// Type enumerating all the possible errors
#[derive(Debug)]
pub enum Error {
    /// An IO error occured while using the said path on the filesystem
    FileError(PathBuf, io::Error),
    /// An IO error occured while using the console
    ConsoleError(io::Error),
    /// The password was invalid
    InvalidPasswordError,
    /// The key was invalid, the file was probably encrypted using another key
    InvalidKeyError,
    NoKey,
    DecryptionError(DecryptionError<yoursb_domain::crypto::Never>),
    PasswordHashingError(Argon2Error),
    NoRepo(RepoPath),
    NoConfigDir,
    // NoLocalProj,
    RepoAlreadyExists,
    // The repo was corrupted
    Corrupted(CorruptionError),
    Abort,
}

#[derive(Debug)]
pub enum CorruptionError {
    InvalidKeyfile,
    InvalidEncryptedFile,
}

impl From<KeyDecryptionError> for Error {
    fn from(err: KeyDecryptionError) -> Error {
        match err {
            KeyDecryptionError::DecryptionError(e) => Self::DecryptionError(e),
            KeyDecryptionError::PasswordHashingError(e) => Self::PasswordHashingError(e),
            KeyDecryptionError::InvalidPassphrase => Self::InvalidKeyError,
        }
    }
}

impl From<CorruptionError> for Error {
    fn from(err: CorruptionError) -> Error {
        Error::Corrupted(err)
    }
}

impl From<DecryptionError<Error>> for Error {
    fn from(err: DecryptionError<Error>) -> Error {
        match err {
            DecryptionError::ReadError(e) => e,
            DecryptionError::SmallChunk => Error::Corrupted(CorruptionError::InvalidEncryptedFile),
            DecryptionError::CipherError => Error::Corrupted(CorruptionError::InvalidEncryptedFile),
        }
    }
}

/// Macro to call the [`YoursbError::convert`] function seemlessly
#[macro_export]
macro_rules! _try {
    ([$data:expr] $content:expr) => {
        match $content {
            Ok(val) => val,
            Err(e) => {
                return Err($crate::errors::YoursbError::convert(e, $data));
            }
        }
    };
    ($content:expr, [$data:expr]) => {
        match $content {
            Ok(val) => val,
            Err(e) => {
                return Err($crate::errors::YoursbError::convert(e, $data));
            }
        }
    };
}

/// Trait used to convert from any kind of error to [self::Error] using
/// some additionnal data.
pub trait YoursbError {
    type Data;
    fn convert(self, data: Self::Data) -> Error;
}

/// Creates a [yoursb_code::errors::Error] file error from a [io::Error]
/// by adding the file path
impl YoursbError for io::Error {
    type Data = PathBuf;
    fn convert(self, data: Self::Data) -> Error {
        Error::FileError(data, self)
    }
}

impl YoursbError for DecryptionError<std::io::Error> {
    type Data = PathBuf;
    fn convert(self, data: Self::Data) -> Error {
        match self {
            DecryptionError::ReadError(e) => Error::FileError(data, e),
            DecryptionError::SmallChunk => Error::Corrupted(CorruptionError::InvalidEncryptedFile),
            DecryptionError::CipherError => Error::Corrupted(CorruptionError::InvalidEncryptedFile),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FileError(path_buf, error) => {
                write!(f, "can't use path {path_buf:?}: {error}")
            }
            Error::ConsoleError(error) => {
                write!(f, "error while using the console: {error}")
            }
            Error::InvalidPasswordError => write!(f, "passphrase is invalid"),
            Error::InvalidKeyError => write!(f, "can't decrypt: the wrong key is being used"),
            Error::NoKey => write!(f, "there's no key in the instance"),
            Error::NoRepo(path) => write!(f, "there's no '{path}' instance"),
            Error::NoConfigDir => {
                write!(f, "can't find a location for a global instance on this OS")
            }
            Error::DecryptionError(decryption_error) => match decryption_error {
                DecryptionError::ReadError(e) => match *e {},
                DecryptionError::SmallChunk => write!(
                    f,
                    "the encrypted file is of invalid size (probably truncated)"
                ),
                DecryptionError::CipherError => {
                    write!(f, "a decryption error occured (cipher error / aead::Error)")
                }
            },
            Error::PasswordHashingError(error) => {
                write!(f, "couldn't hash the passphrase: ")?;
                match error {
                    Argon2Error::AdTooLong => write!(f, "unexpected AdTooLong"),
                    Argon2Error::AlgorithmInvalid => write!(f, "unexpected AlgorithmInvalid"),
                    Argon2Error::B64Encoding(_) => write!(f, "unexpected B64Encoding"),
                    Argon2Error::KeyIdTooLong => write!(f, "unexpected KeyIdTooLong"),
                    Argon2Error::OutputTooShort => write!(f, "unexpected OutputTooShort"),
                    Argon2Error::OutputTooLong => write!(f, "unexpected OutputTooLong"),
                    Argon2Error::SaltTooShort => write!(f, "unexpected SaltTooShort"),
                    Argon2Error::SaltTooLong => write!(f, "unexpected SaltTooLong"),
                    Argon2Error::VersionInvalid => write!(f, "unexpected VersionInvalid"),

                    Argon2Error::MemoryTooLittle => write!(f, "not enough memory on host"),
                    Argon2Error::MemoryTooMuch => write!(f, "too much memory on host"),
                    Argon2Error::PwdTooLong => write!(f, "password too long"),
                    Argon2Error::SecretTooLong => write!(f, "secret too long"),
                    Argon2Error::ThreadsTooFew => write!(f, "not enough threads available on host"),
                    Argon2Error::ThreadsTooMany => write!(f, "too much threads available on host"),
                    Argon2Error::TimeTooSmall => write!(f, "not enough available time"),
                }
            }
            Error::RepoAlreadyExists => write!(f, "there's already a repository here"),
            Error::Corrupted(corruption_error) => {
                write!(
                    f,
                    "the {} was corrupted (modified, replaced, truncated, ...).",
                    {
                        match corruption_error {
                            CorruptionError::InvalidKeyfile => "repository's key",
                            CorruptionError::InvalidEncryptedFile => "encrypted file",
                        }
                    }
                )
            }
            Error::Abort => write!(f, "aborting"),
        }
    }
}
