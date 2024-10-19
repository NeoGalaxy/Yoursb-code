//! Minimal YourSBCode implementation allowing to access elements in a local instance.
//! It aims to be as small as possible.

#![feature(c_variadic)]
// #![no_std]
// TODO: add back the no_std
#![no_main]

// extern crate libc;

pub mod crypto;
pub mod key;
pub mod project;
pub mod utils;

use core::{
    ffi::CStr,
    mem::{align_of, size_of},
    ops::{Deref, DerefMut},
    ptr, slice,
};
use std::{ptr::null_mut, time::Duration};

use crypto::decrypt;
use key::unlock_key;
use libc::{
    c_void, exit, fdopen, fopen, fprintf, free, memcpy, nanosleep, posix_memalign, sleep, usleep,
    STDERR_FILENO, STDOUT_FILENO,
};
use project::find_loc;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize,
};

use utils::eprintfln;

use crate::utils::printfln;

// A custom exit: finishes the execution of the program prematurely with a message
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
        "USAGE: %s [-h|--help] [-v|--version] [clear | <KIND> <IDENTIFIER> [<OUTPUT>]]\n\0".as_ptr()
            as *const _,
        cmd,
    );
    libc::fprintf(stderr, "\n\0".as_ptr() as *const _);
    libc::fprintf(stderr, "Arguments:\n\0".as_ptr() as *const _);
    libc::fprintf(
        stderr,
        "  clear \tclears the clipboard\n\0".as_ptr() as *const _,
    );
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
        eprintfln!(
            "YourSBCode_tiny v%.*s (from YourSBCode v%.*s)",
            VERSION.len(),
            VERSION.as_ptr(),
            VERSION.len(),
            VERSION.as_ptr()
        );
    }
}

/// Data-structure that is saved on the heap. It frees itself upon drop
pub struct Heaped<T> {
    content: *mut T, // Todo: make it non-null for Option optimisation
    size: usize,
}

impl<T> Heaped<T> {
    /// Create a Heaped from a pointer.
    ///
    /// # Safety
    ///
    /// The pointer should be a pointer that is free-able. Also, it is assumed to have the
    /// ownership over the content.
    ///
    /// Behavior is undefined if any of the following conditions are violated:
    ///
    /// * if `content` is not null, it must be valid for reads for `size * mem::size_of::<T>()`
    ///   many bytes, and it must be properly aligned. This means in particular:
    ///
    ///     * The entire memory range of this slice must be contained within a single allocated
    ///       object.
    ///       This can never span across multiple allocated objects.
    ///
    /// * The total size `size * mem::size_of::<T>()` of the slice must be no larger than `isize::MAX`,
    ///   and adding that size to `content` must not "wrap around" the address space.
    ///   See the safety documentation of [`pointer::offset`].
    ///
    unsafe fn new(content: *mut T, size: usize) -> Self {
        Heaped { content, size }
    }

    /// Alloc a new Heaped
    fn alloc(size: usize) -> Self {
        let mut ptr = ptr::null_mut();
        let res = unsafe {
            posix_memalign(
                &mut ptr,
                align_of::<T>().max(size_of::<usize>()),
                size * size_of::<T>(),
            )
        };
        assert_eq!(0, res); // or whatever other way to hnadle errors

        Heaped {
            content: ptr as _,
            size,
        }
    }

    /*/// access the pointer to the content
    fn ptr_mut(&mut self) -> *mut T {
        self.content
    }*/

    /// access the pointer to the content
    fn ptr(&self) -> *const T {
        self.content
    }

    /// access the content as a slice
    ///
    /// # Safety
    ///
    /// (inherited from [slice::from_raw_parts], but the case of null pointers is checked)
    ///
    /// Behavior is undefined if any of the following conditions are violated:
    ///
    /// * The content of `self` must be properly initialized values of type `T`.
    ///
    /// * The memory referenced by the returned slice must not be mutated for the duration
    ///   of lifetime `'a`, except inside an `UnsafeCell`.
    ///
    /// * The total size `len * mem::size_of::<T>()` of the slice must be no larger than `isize::MAX`,
    ///   and adding that size to `data` must not "wrap around" the address space.
    ///   See the safety documentation of [`pointer::offset`].
    ///
    unsafe fn sliced(&self) -> &[T] {
        slice::from_raw_parts(self.ptr(), self.size)
    }

    /// Reallocs the content
    fn realloc(&mut self, new_size: usize) -> Result<(), ()> {
        // TODO: optimise
        if new_size > self.size {
            let mut ptr = ptr::null_mut();
            let res = unsafe {
                posix_memalign(
                    &mut ptr,
                    align_of::<T>().max(size_of::<usize>()),
                    new_size * size_of::<T>(),
                )
            };
            assert_eq!(0, res); // or whatever other way to hnadle errors
            unsafe { free(self.content as *mut c_void) };
            self.content = ptr as *mut T;
        }

        self.size = new_size;
        Ok(())
    }
}

impl<T: Copy> Heaped<T> {
    /// Dupplicates the content of the Heaped by memcpy-ing the content
    fn dupplicate(&self) -> Self {
        let new_mem = Self::alloc(self.size);
        unsafe {
            memcpy(
                new_mem.content as *mut c_void,
                self.ptr() as *const c_void,
                self.size * size_of::<T>(),
            )
        };
        new_mem
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
                let res = Heaped::<u8>::alloc(v.len());
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
    /************** Parsing args **************/

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
        Ok("c" | "cl" | "clear") => {
            let clip = x11_clipboard::Clipboard::new().unwrap();
            clip.store(
                clip.setter.atoms.clipboard,
                clip.setter.atoms.utf8_string,
                b" \0",
            )
            .unwrap();
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            };
            unsafe { nanosleep(&ts, null_mut()) };
            unsafe { printfln!("Clip content successfully cleared") };
            return 0;
        }
        _ => unsafe { "first argument should be 'file', 'password' or 'clear'".finish() },
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

    /************** Unlock key **************/

    let output = if args.len() == 4 { Some(args[3]) } else { None };

    let identifier = unsafe { CStr::from_ptr(args[2]) };

    let (path, keypath) = find_loc(is_file, identifier);
    unsafe { eprintfln!("Unlocking key...") };
    let key = unlock_key(unsafe { CStr::from_ptr(*keypath) });
    if !is_file || output.is_some() {
        unsafe { eprintfln!("Key valid.") };
        unsafe { eprintfln!() };
        unsafe { eprintfln!("Opening file...") };
    }

    /************** Decrypt **************/

    let content = decrypt(unsafe { CStr::from_ptr(*path) }, &key.into());

    /************** Write results **************/

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
        unsafe { eprintfln!("Parsing password...") };
        let mut body: Heaped<u8> = Heaped::alloc(0);
        for bloc in content {
            let bloc = bloc.unwrap();
            let start = unsafe { body.offset(body.size as isize) };
            body.realloc(body.size + bloc.len()).unwrap();
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
                    eprintfln!("---------   Content   ---------");
                    eprintfln!("%.*s", body.size, body.ptr());
                    eprintfln!("-------------------------------");

                    msg.finish()
                };
            }
        };

        unsafe { eprintfln!("== Putting password in clipboard ==") };
        let clip = x11_clipboard::Clipboard::new().unwrap();
        let mut pass = password.password;
        pass.realloc(pass.size + 1).unwrap();
        unsafe { *pass.offset(pass.size as isize - 1) = b'\0' };
        clip.store(
            clip.setter.atoms.clipboard,
            clip.setter.atoms.utf8_string,
            unsafe { pass.sliced() },
        )
        .unwrap();

        unsafe {
            if let Some(data) = password.data {
                eprintfln!("---------   associated data   ---------");
                eprintfln!("(ptr: %d)", data.ptr());
                eprintfln!("%.*s", data.size, data.ptr());
                eprintfln!("---------------------------------------");
            }
        };
    }
    0
}

/*#[panic_handler]
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
}*/
