#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

extern crate alloc;

pub use zeroize::Zeroize;

pub mod commands;
pub mod crypto;
pub mod interfaces;
mod testing;
