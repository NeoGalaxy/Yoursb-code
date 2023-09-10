use std::{io, path::PathBuf};

#[derive(Debug)]
pub enum Error {
    FileError(PathBuf, io::Error),
    ConsoleError(io::Error),
    InvalidPasswordError,
    InvalidKeyError,
}

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

pub trait YoursbError {
    type Data;
    fn convert(self, data: Self::Data) -> Error;
}

impl YoursbError for io::Error {
    type Data = PathBuf;
    fn convert(self, data: Self::Data) -> Error {
        Error::FileError(data, self)
    }
}
