//! Module relative to anything helping finding a project

use core::{ffi::CStr, mem::MaybeUninit, ptr::null_mut};

use libc::{getcwd, snprintf, stat, strlen, ENOENT};

use crate::{utils::eprintfln, Finish, Heaped};

/// The name of the directory in which everything is stored when in a local dir
pub const LOCAL_PROJECT_SUBDIR: &str = ".yoursbcode";

/// The name of the directory in which everything is stored when in the config dir
pub const GLOBAL_CONFIG_NAME: &str = "yoursbcode\0";

/// The name of the key file
pub const KEY_NAME: &str = "key\0";

/// The subdirectory in which files are stored
pub const FILES_DIR: &str = "files\0";

/// The name of the directory containing passwords
pub const PASSWORD_DIR: &str = "passwords\0";

pub fn find_project() -> Heaped<i8> {
    let mut size = 64;
    let mut project_dir = loop {
        let buf = unsafe { getcwd(null_mut(), size) };
        if !buf.is_null() {
            break unsafe { Heaped::new(buf, size as _) };
        } else {
            size *= 2;
        }
    };

    let curr_dir_len = unsafe { strlen(*project_dir) };

    if curr_dir_len + 1 + LOCAL_PROJECT_SUBDIR.len() + 1 > project_dir.size {
        project_dir
            .realloc(curr_dir_len + 1 + LOCAL_PROJECT_SUBDIR.len() + 1 + 30)
            .expect("ERROR: not enough memory");
    }

    let mut dir_end = curr_dir_len;

    'main_loop: loop {
        let printed_size = unsafe {
            snprintf(
                project_dir.offset(dir_end as _),
                LOCAL_PROJECT_SUBDIR.len() + 2 + 30,
                "/%.*s\0".as_ptr() as _,
                LOCAL_PROJECT_SUBDIR.len(),
                LOCAL_PROJECT_SUBDIR.as_ptr(),
            )
        };

        assert_eq!(printed_size as usize, LOCAL_PROJECT_SUBDIR.len() + 1);

        // Check dir exists
        let sb: MaybeUninit<stat> = MaybeUninit::zeroed();
        if unsafe { stat(*project_dir, &mut sb.assume_init()) } == 0 {
            // Everything's good
            break project_dir;
        }

        // There's an error, let's manage it
        let e = errno::errno();
        if e.0 != ENOENT {
            let beginning = "Can't call `opendir` for some reason: ";
            let error = Heaped::alloc(beginning.len() + 10);
            unsafe {
                snprintf(
                    *error,
                    beginning.len() + 10,
                    "%.*s%d\0".as_ptr() as _,
                    beginning.len(),
                    beginning,
                    e,
                )
            };
            unsafe { error.finish() };
        }

        // ENOENT: Dir not found -> remove last element
        for i in (0..dir_end).rev() {
            let c = unsafe { project_dir.offset(i as isize) };
            if unsafe { *c } == '/' as i8 || unsafe { *c } == '\\' as i8 {
                unsafe { *c = '\0' as i8 };
                dir_end = c as usize - project_dir.ptr() as usize;
                continue 'main_loop;
            };
        }

        unsafe { "Instance not found".finish() };
    }
}

/// Seaches for a project in the current dir and all its parents. Returns `Err(...)` if there's
/// an issue knowing the current directory, and returns `Ok(None)` if no projet was found.
///
/// If a project is found, returns `Ok(path)` with the path directing to the root dir of the
/// project
pub fn find_loc(is_file: bool, identifier: &CStr) -> (Heaped<i8>, Heaped<i8>) {
    let project_path = find_project();

    let mut file_path = project_path.dupplicate();
    let mut key_path = project_path;

    // file path
    let curr_dir_len = unsafe { strlen(*file_path) };
    let identifier_len = identifier.to_bytes().len();

    let to_add = if is_file { FILES_DIR } else { PASSWORD_DIR };

    let new_len = curr_dir_len + to_add.len() + 1 + identifier_len + 1;
    if new_len > file_path.size {
        file_path
            .realloc(new_len)
            .expect("ERROR: not enough memory");
    }

    let printed_size = unsafe {
        snprintf(
            file_path.offset(curr_dir_len as _),
            new_len - curr_dir_len,
            "/%s/%s\0".as_ptr() as _,
            to_add.as_ptr(),
            identifier,
        )
    };

    if printed_size as usize + 1 > new_len {
        unsafe { "INTERNAL ERROR: too small path size".finish() };
    }

    // key path
    let curr_dir_len = unsafe { strlen(*key_path) };

    let new_len = curr_dir_len + KEY_NAME.len() + 1;
    if new_len > key_path.size {
        key_path.realloc(new_len).expect("ERROR: not enough memory");
    }

    let printed_size = unsafe {
        snprintf(
            key_path.offset(curr_dir_len as _),
            new_len - curr_dir_len,
            "/%s\0".as_ptr() as _,
            KEY_NAME.as_ptr(),
        )
    };

    if printed_size as usize + 1 > new_len {
        unsafe { "INTERNAL ERROR: too small path size".finish() };
    }

    unsafe { eprintfln!("Key pos: %s", *key_path) };
    (file_path, key_path)
}
