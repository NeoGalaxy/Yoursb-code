//! Minimal YourSBCode implementation allowing to access elements in a local instance.
//! It aims to be as small as possible.

#![feature(core_panic)]
#![no_std]
#![no_main]

// extern crate libc;

pub mod crypto;
pub mod project;

use core::{
    ffi::CStr,
    mem::size_of,
    ops::{Deref, DerefMut},
    slice,
};

use libc::{exit, free, malloc, realloc};
use project::{find_loc, find_project};

trait Finish {
    unsafe fn finish(&self) -> !;
}

impl Finish for *const i8 {
    unsafe fn finish(&self) -> ! {
        libc::printf("ERROR: %s\n\0".as_ptr() as _, *self);
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
        libc::printf("ERROR: %.*s\n\0".as_ptr() as _, self.len(), self.as_ptr());
        unsafe { exit(1) }
    }
}

impl Finish for Heaped<i8> {
    unsafe fn finish(&self) -> ! {
        libc::printf("ERROR: %.*s\n\0".as_ptr() as _, self.size, self.content);
        unsafe { exit(1) }
    }
}

impl Finish for Heaped<u8> {
    unsafe fn finish(&self) -> ! {
        libc::printf("ERROR: %.*s\n\0".as_ptr() as _, self.size, self.content);
        unsafe { exit(1) }
    }
}

unsafe fn usage(cmd: *const i8) {
    libc::printf("YourSBCode-mini, the minimal encrypted file utility\n\0".as_ptr() as *const _);
    libc::printf("\n\0".as_ptr() as *const _);
    libc::printf("It allows to decrypt a password/encrypted file from\n\0".as_ptr() as *const _);
    libc::printf("the current instance. \n\0".as_ptr() as *const _);
    libc::printf(
        "If no argument is supplied, it opens an interactive interface\n\0".as_ptr() as *const _,
    );
    libc::printf("\n\0".as_ptr() as *const _);
    libc::printf(
        "USAGE: %s [-h|--help] [<KIND> <IDENTIFIER>]\n\0".as_ptr() as *const _,
        cmd,
    );
    libc::printf("\n\0".as_ptr() as *const _);
    libc::printf("Arguments:\n\0".as_ptr() as *const _);
    libc::printf(
        "  <KIND> \tThe kind of data to decrypt. Either `password` or `file`.\n\0".as_ptr()
            as *const _,
    );
    libc::printf("  <IDENTIFIER> \tThe identifier of the data to decrypt\n\0".as_ptr() as *const _);
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
        let new_loc = realloc(self.content as _, new_size);
        if new_loc.is_null() {
            Err(())
        } else {
            self.content = new_loc as _;
            self.size = new_size;
            Ok(())
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

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn main(argc: isize, argv: *const *const i8) -> isize {
    // Since we are passing a C string the final null character is mandatory.
    let args = unsafe { slice::from_raw_parts(argv, argc as usize) };
    if args
        .iter()
        .map(|a| unsafe { CStr::from_ptr(*a) })
        .any(|a| a.to_str() == Ok("-h") || a.to_str() == Ok("--help"))
    {
        unsafe { usage(args[0]) };
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
        unsafe { libc::printf("Missing argument <IDENTIFIER>\n\0".as_ptr() as _) };
        return 0;
    }

    let identifier = unsafe { CStr::from_ptr(args[2]) };

    let path = find_loc(is_file, identifier);

    0
}

#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        libc::printf("=== Progam panicked ===\n\0".as_ptr() as _);

        if let Some(s) = info.payload().downcast_ref::<&str>() {
            libc::printf("ERROR: %.*s\n\0".as_ptr() as _, s.len(), s.as_ptr());
        } else if let Some(location) = info.location() {
            libc::printf(
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
