//! Minimal YourSBCode implementation allowing to access elements in a local instance.
//! It aims to be as small as possible.

#![feature(c_variadic)]
#![no_std]
#![no_main]

// extern crate libc;

// Gave up using libclipboard
// pub mod c_deps;
pub mod crypto;
pub mod key;
pub mod project;
pub mod utils;

use core::{
    ffi::{c_int, CStr},
    mem::size_of,
    ops::{Deref, DerefMut},
    ptr::{null, null_mut},
    slice, todo,
};

use crypto::decrypt;
use key::unlock_key;
use libc::{
    exit, fdopen, fflush, fopen, fprintf, free, getchar, malloc, memcpy, printf, realloc, snprintf,
    system, STDERR_FILENO, STDOUT_FILENO,
};
use project::find_loc;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize,
};

use utils::eprintln;

trait Finish {
    unsafe fn finish(&self) -> !;
}

impl Finish for *const i8 {
    unsafe fn finish(&self) -> ! {
        let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
        libc::fprintf(stderr, "ERROR: %s\n\0".as_ptr() as _, *self);
        unsafe { exit(1) }
    }
}

impl Finish for *const u8 {
    unsafe fn finish(&self) -> ! {
        (*self as *const i8).finish()
    }
}

impl Finish for *mut i8 {
    unsafe fn finish(&self) -> ! {
        (*self as *const i8).finish()
    }
}

impl Finish for *mut u8 {
    unsafe fn finish(&self) -> ! {
        (*self as *const i8).finish()
    }
}

impl Finish for str {
    unsafe fn finish(&self) -> ! {
        let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
        libc::fprintf(
            stderr,
            "ERROR: %.*s\n\0".as_ptr() as _,
            self.len(),
            self.as_ptr(),
        );
        unsafe { exit(1) }
    }
}

impl Finish for Heaped<i8> {
    unsafe fn finish(&self) -> ! {
        let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
        libc::fprintf(
            stderr,
            "ERROR: %.*s\n\0".as_ptr() as _,
            self.size,
            self.content,
        );
        unsafe { exit(1) }
    }
}

impl Finish for Heaped<u8> {
    unsafe fn finish(&self) -> ! {
        let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
        libc::fprintf(
            stderr,
            "ERROR: %.*s\n\0".as_ptr() as _,
            self.size,
            self.content,
        );
        unsafe { exit(1) }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

unsafe fn usage(cmd: *const i8) {
    let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
    libc::fprintf(
        stderr,
        "YourSBCode_tiny v%.*s by Naeio, the minimal encrypted file utility\n\0".as_ptr()
            as *const _,
        VERSION.len(),
        VERSION.as_ptr(),
    );
    libc::fprintf(
        stderr,
        "Exported from YourSBCode v%.*s\n\0".as_ptr() as *const _,
        VERSION.len(),
        VERSION.as_ptr(),
    );
    libc::fprintf(stderr, "\n\0".as_ptr() as *const _);
    libc::fprintf(
        stderr,
        "It allows to decrypt a password/encrypted file from\n\0".as_ptr() as *const _,
    );
    libc::fprintf(stderr, "the current instance. \n\0".as_ptr() as *const _);
    libc::fprintf(
        stderr,
        "If no argument is supplied, it opens an interactive interface\n\0".as_ptr() as *const _,
    );
    libc::fprintf(stderr, "\n\0".as_ptr() as *const _);
    libc::fprintf(
        stderr,
        "USAGE: %s [-h|--help] [-v|--version] [<KIND> <IDENTIFIER> [<OUTPUT>]]\n\0".as_ptr()
            as *const _,
        cmd,
    );
    libc::fprintf(stderr, "\n\0".as_ptr() as *const _);
    libc::fprintf(stderr, "Arguments:\n\0".as_ptr() as *const _);
    libc::fprintf(
        stderr,
        "  <KIND> \tThe kind of data to decrypt. Either `password` or `file`.\n\0".as_ptr()
            as *const _,
    );
    libc::fprintf(
        stderr,
        "  <IDENTIFIER> \tThe identifier of the data to decrypt\n\0".as_ptr() as *const _,
    );
    libc::fprintf(
        stderr,
        "  <OUTPUT> \tWhen decrypting a file, write result in said\n\0".as_ptr() as *const _,
    );
    libc::fprintf(
        stderr,
        "           \tfile instead of stdout\n\0".as_ptr() as *const _,
    );
}

fn version() {
    unsafe {
        eprintln!(
            "YourSBCode_tiny v%.*s (from YourSBCode v%.*s)",
            VERSION.len(),
            VERSION.as_ptr(),
            VERSION.len(),
            VERSION.as_ptr()
        );
    }
}

pub struct Heaped<T> {
    content: *mut T,
    size: usize,
}

impl<T> Heaped<T> {
    unsafe fn new(content: *mut T, size: usize) -> Self {
        Heaped { content, size }
    }

    fn malloc(size: usize) -> Self {
        unsafe {
            Heaped {
                content: malloc(size * size_of::<T>()) as _,
                size,
            }
        }
    }

    fn ptr_mut(&mut self) -> *mut T {
        self.content
    }

    fn ptr(&self) -> *const T {
        self.content
    }

    unsafe fn realloc(&mut self, new_size: usize) -> Result<(), ()> {
        let new_loc = realloc(self.content as _, new_size * size_of::<T>());
        if new_loc.is_null() {
            Err(())
        } else {
            self.content = new_loc as _;
            self.size = new_size;
            Ok(())
        }
    }
}

impl<T: Clone> Heaped<T> {
    unsafe fn dupplicate(&self) -> Self {
        let new_mem = malloc(self.size * size_of::<T>());
        memcpy(new_mem, self.ptr() as *const _, self.size * size_of::<T>());
        Heaped {
            content: new_mem as *mut _,
            size: self.size,
        }
    }
}

impl<T> Deref for Heaped<T> {
    type Target = *mut T;
    fn deref(&self) -> &Self::Target {
        &self.content
    }
}

impl<T> DerefMut for Heaped<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.content
    }
}

impl<T> Drop for Heaped<T> {
    fn drop(&mut self) {
        unsafe { free(self.content as _) }
    }
}

/// A password with optionnal data
pub struct Password {
    pub password: Heaped<u8>,
    pub data: Option<Heaped<u8>>,
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Field(Heaped<u8>);

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_str(FieldVisit)
            }
        }

        struct FieldVisit;

        impl<'de> Visitor<'de> for FieldVisit {
            type Value = Field;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct Password")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let res = Heaped::<u8>::malloc(v.len());
                unsafe { memcpy(res.ptr() as _, v.as_ptr() as _, v.len()) };
                Ok(Field(res))
            }
        }

        struct PswVisit;

        impl<'de> Visitor<'de> for PswVisit {
            type Value = Password;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct Password")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Password, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut password: Option<Field> = None;
                let mut data: Option<Field> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "password" => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"));
                            }
                            password = Some(map.next_value()?)
                        }
                        "data" => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?)
                        }
                        k => {
                            return Err(serde::de::Error::unknown_field(k, KEYS));
                        }
                    }
                }
                let password = password.ok_or_else(|| de::Error::missing_field("password"))?;
                Ok(Password {
                    password: password.0,
                    data: data.map(|v| v.0),
                })
            }
        }

        const KEYS: &[&str] = &["password", "data"];

        deserializer.deserialize_struct("Password", KEYS, PswVisit)
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn main(argc: isize, argv: *const *const i8) -> isize {
    // Since we are passing a C string the final null character is mandatory.
    let args = unsafe { slice::from_raw_parts(argv, argc as usize) };
    if args
        .iter()
        .map(|a| unsafe { CStr::from_ptr(*a) })
        .map(|a| a.to_str())
        .any(|a| a == Ok("-h") || a == Ok("--help"))
    {
        unsafe { usage(args[0]) };
        return 0;
    }
    if args
        .iter()
        .map(|a| unsafe { CStr::from_ptr(*a) })
        .map(|a| a.to_str())
        .any(|a| a == Ok("-v") || a == Ok("--version"))
    {
        version();
        return 0;
    }

    if args.len() < 2 {
        unsafe { "Not yet implemented".finish() };
    }

    let is_file = match unsafe { CStr::from_ptr(args[1]).to_str() } {
        Ok("f" | "file") => true,
        Ok("p" | "pass" | "password") => false,
        _ => unsafe { "first argument is not either 'file' or 'password'".finish() },
    };

    if args.len() < 3 {
        unsafe {
            let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
            libc::fprintf(stderr, "Missing argument <IDENTIFIER>\n\0".as_ptr() as _);
        }
        return 0;
    }

    if args.len() > 4 {
        unsafe { "Too many arguments.".finish() };
    }

    let output = if args.len() == 4 { Some(args[3]) } else { None };

    let identifier = unsafe { CStr::from_ptr(args[2]) };

    let (path, keypath) = find_loc(is_file, identifier);
    unsafe { eprintln!("Unlocking key...") };
    let key = unlock_key(unsafe { CStr::from_ptr(*keypath) });
    if !is_file || output.is_some() {
        unsafe { eprintln!("Key valid.") };
        unsafe { eprintln!() };
        unsafe { eprintln!("Opening file...") };
    }

    let content = decrypt(unsafe { CStr::from_ptr(*path) }, &key.into());
    if is_file {
        let output = if let Some(f) = output {
            let res = unsafe { fopen(f, "w".as_ptr() as _) };
            if res.is_null() {
                unsafe { "Can't open input file".finish() };
            } else {
                res
            }
        } else {
            unsafe { fdopen(STDOUT_FILENO, "w".as_ptr() as _) }
        };
        for bloc in content {
            if let Some(v) = bloc {
                unsafe { fprintf(output, "%.*s\0".as_ptr() as _, v.len(), v.as_ptr()) };
            } else {
                unsafe { "Invalid content".finish() }
            }
        }
    } else {
        unsafe { eprintln!("Parsing password...") };
        let mut body: Heaped<u8> = Heaped::malloc(0);
        for bloc in content {
            let bloc = bloc.unwrap();
            let start = unsafe { body.offset(body.size as isize) };
            unsafe { body.realloc(body.size + bloc.len()) }.unwrap();
            unsafe { memcpy(start as _, bloc.as_ptr() as _, bloc.len()) };
        }
        let (password, _): (Password, _) = match serde_json_core::from_slice(unsafe {
            if body.is_null() {
                b""
            } else {
                slice::from_raw_parts(body.ptr(), body.size)
            }
        }) {
            Ok(v) => v,
            Err(e) => {
                let str_container;
                let msg = match e {
                    serde_json_core::de::Error::EofWhileParsingList => "Eof while parsing list",
                    serde_json_core::de::Error::EofWhileParsingObject => "Eof while parsing object",
                    serde_json_core::de::Error::EofWhileParsingString => "Eof while parsing string",
                    serde_json_core::de::Error::EofWhileParsingNumber => "Eof while parsing number",
                    serde_json_core::de::Error::EofWhileParsingValue => "Eof while parsing value",
                    serde_json_core::de::Error::ExpectedColon => "Expected colon",
                    serde_json_core::de::Error::ExpectedListCommaOrEnd => {
                        "Expected list comma or end"
                    }
                    serde_json_core::de::Error::ExpectedObjectCommaOrEnd => {
                        "Expected object comma or end"
                    }
                    serde_json_core::de::Error::ExpectedSomeIdent => "Expected some ident",
                    serde_json_core::de::Error::ExpectedSomeValue => "Expected some value",
                    serde_json_core::de::Error::InvalidNumber => "Invalid number",
                    serde_json_core::de::Error::InvalidType => "Invalid type",
                    serde_json_core::de::Error::InvalidUnicodeCodePoint => {
                        "Invalid unicode code point"
                    }
                    serde_json_core::de::Error::KeyMustBeAString => "Key must be a string",
                    serde_json_core::de::Error::TrailingCharacters => "Trailing characters",
                    serde_json_core::de::Error::TrailingComma => "Trailing comma",
                    serde_json_core::de::Error::CustomError => "Custom error",
                    serde_json_core::de::Error::CustomErrorWithMessage(m) => {
                        str_container = m.clone();
                        &str_container
                    }
                    _ => "Unknown parsing error",
                };

                unsafe {
                    eprintln!("---------   Content   ---------");
                    eprintln!("%.*s", body.size, body.ptr());
                    eprintln!("-------------------------------");

                    msg.finish()
                };
            }
        };

        unsafe {
            // eprintln!();
            // fflush(libc::fdopen(libc::STDERR_FILENO, "w".as_ptr() as _));
            // libc::printf(
            //     "%.*s\0".as_ptr() as _,
            //     password.password.size,
            //     password.password.ptr(),
            // );
            // fflush(libc::fdopen(libc::STDOUT_FILENO, "w".as_ptr() as _));
            eprintln!("== Using xclip to put password in clipboard ==");
            let pass = password.password;
            let format = "echo -n %.*s | xclip -selection clipboard\0";
            let buff = Heaped::<u8>::malloc(pass.size + format.len());
            let read = snprintf(
                buff.ptr() as _,
                buff.size,
                format.as_ptr() as _,
                pass.size,
                pass.ptr(),
            );
            if read >= buff.size as _ {
                "Print should've been alright".finish();
            }
            system(buff.ptr() as _);

            if let Some(data) = password.data {
                eprintln!("---------   associated data   ---------");
                eprintln!("(ptr: %d)", data.ptr());
                eprintln!("%.*s", data.size, data.ptr());
                eprintln!("---------------------------------------");
            }
        };
    }
    0
}

#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        let stderr = fdopen(STDERR_FILENO, "w".as_ptr() as _);
        libc::fprintf(stderr, "=== Progam panicked ===\n\0".as_ptr() as _);

        if let Some(s) = info.payload().downcast_ref::<&str>() {
            libc::fprintf(stderr, "ERROR: %.*s\n\0".as_ptr() as _, s.len(), s.as_ptr());
        } else if let Some(location) = info.location() {
            libc::fprintf(
                stderr,
                "panic occurred in file '%.*s' at %d:%d\n\0".as_ptr() as _,
                location.file().len(),
                location.file().as_ptr(),
                location.line(),
                location.column(),
            );
        }
    };
    unsafe { exit(1) }
}
