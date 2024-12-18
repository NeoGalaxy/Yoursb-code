//! This module is aimed towards manging the keys, encrypting and decrypting them.

use crate::{crypto::decrypt, Finish};
use core::ffi::CStr;

#[cfg(unix)]
pub use unix::*;
#[cfg(unix)]
mod unix {
    use core::mem::MaybeUninit;

    use crate::utils::eprintfln;

    use libc::{getchar, tcgetattr, tcsetattr, termios, ECHO, EOF, STDIN_FILENO, TCSANOW};

    pub fn ask_passphase() -> [u8; 32] {
        let mut passphrase = [0; 32];

        let mut old_term: termios = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe { tcgetattr(STDIN_FILENO, &mut old_term as *mut _) };

        let mut new_term = old_term;

        new_term.c_lflag &= !(ECHO);

        loop {
            unsafe { eprintfln!("Enter the passphrase: ") };

            let mut curr_i = 0;
            unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &new_term as *const _) };
            loop {
                let c = unsafe { getchar() };
                if c == '\n' as i32 || c == '\0' as i32 || c == EOF {
                    break;
                }

                if curr_i < 32 {
                    passphrase[curr_i] = c as u8;
                    curr_i += 1;
                }
            }
            unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &old_term as *const _) };

            if curr_i >= 32 {
                unsafe {
                    eprintfln!("Too long passphrase, max is 32 characters.");
                    eprintfln!();
                }
            } else {
                break;
            }
        }

        passphrase
    }
}

#[cfg(windows)]
pub use windows::*;
#[cfg(windows)]
mod windows {
    use crate::eprintfln;

    use libc::{getchar, EOF};

    pub fn ask_passphase() -> [u8; 32] {
        let mut passphrase = [0; 32];

        // let mut old_term: termios = unsafe { MaybeUninit::zeroed().assume_init() };
        // unsafe { tcgetattr(STDIN_FILENO, &mut old_term as *mut _) };

        // let mut new_term = old_term;

        // new_term.c_lflag &= !(ECHO);

        loop {
            unsafe { eprintfln!("Enter the passphrase: ") };

            let mut curr_i = 0;
            // unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &new_term as *const _) };

            // windows::Win32::System::Console::SetConsoleMode;

            loop {
                let c = unsafe { getchar() };
                if c == '\n' as i32 || c == '\0' as i32 || c == EOF {
                    break;
                }

                if curr_i < 32 {
                    passphrase[curr_i] = c as u8;
                    curr_i += 1;
                }
            }
            // unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &old_term as *const _) };

            if curr_i >= 32 {
                unsafe {
                    eprintfln!("Too long passphrase, max is 32 characters.");
                    eprintfln!();
                }
            } else {
                break;
            }
        }

        passphrase
    }
}

/// Decrypts an encrypted key
pub fn unlock_key(keypath: &CStr) -> [u8; 32] {
    let passphrase = ask_passphase();

    let mut res = decrypt(keypath, &passphrase.into());

    let key = match res.next().unwrap() {
        Some(v) => v,
        None => unsafe { "Invalid passphrase".finish() },
    };
    assert!(res.next().is_none());
    assert!(key.len() == 32);

    (&key[0..32])
        .try_into()
        .expect("Encrypted key is not the right size")
}
