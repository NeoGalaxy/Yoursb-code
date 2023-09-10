//! This module defines the possible errors from this software

use std::{io, path::PathBuf};

/// Type enumerating all the possible errors
#[derive(Debug)]
pub enum Error {
    /// An IO error occured while using the said file
    FileError(PathBuf, io::Error),
    /// An IO error occured while using the console
    ConsoleError(io::Error),
    /// The password was invalid
    InvalidPasswordError,
    /// The key was invalid, the file was probably encrypted using another key
    InvalidKeyError,
    NoKey,
}

/// Macro to call the YoursbError::convert function seemlessly
#[macro_export]
macro_rules! _try {
    ([$data:expr] $content:expr) => {
        match $content {
            Ok(val) => val,
            Err(e) => {
                return e.convert($data);
            }
        }
    };
    ($content:expr, [$data:expr]) => {
        match $content {
            Ok(val) => val,
            Err(e) => {
                return Err(e.convert($data));
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
