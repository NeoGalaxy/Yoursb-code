mod desktop_ctx;
mod errors;
mod repo;

use std::{
    path::PathBuf,
    sync::mpsc,
    thread::{sleep, spawn},
    time::Duration,
};

use rfd::FileDialog;
use slint::{invoke_from_event_loop, SharedString};

use crate::repo::RepoPath;

slint::include_modules!();

fn run_start_window() -> Option<RepoPath> {
    let (snd, rcv) = mpsc::sync_channel(2);
    invoke_from_event_loop(move || {
        let start_screen = StartScreen::new().unwrap();

        start_screen.on_browse_files(|curr_file| {
            let diag = FileDialog::new().set_directory("/").pick_folder();
            match diag {
                Some(new_file) => SharedString::from(new_file.to_string_lossy().to_string()),
                None => curr_file,
            }
        });
        start_screen.on_submit({
            let snd = snd.clone();
            let start_screen = start_screen.as_weak();
            move |global, local_path| {
                let msg = if global {
                    RepoPath::Global
                } else {
                    RepoPath::Local(Some(PathBuf::from(&local_path)))
                };
                let _ = snd.send((start_screen.clone(), Some(msg))); // Todo: do we want to close the window?
            }
        });

        start_screen.show().unwrap();
        start_screen.window().on_close_requested({
            let start_screen = start_screen.as_weak();
            move || {
                let _ = snd.send((start_screen.clone(), None)); // Todo: do we want to close the window?
                slint::CloseRequestResponse::KeepWindowShown
            }
        });
    })
    .unwrap();

    let Ok((screen, path)) = rcv.recv() else {
        return None;
    };

    screen
        .upgrade_in_event_loop(|s| s.window().hide().unwrap())
        .unwrap();
    path // Err(_) => canal closed => window dropped => close everything
}
fn run_app() {
    let path = run_start_window();
    invoke_from_event_loop(move || {
        let home = HomeScreen::new().unwrap();
        home.show().unwrap();
        home.window().on_close_requested(|| {
            slint::quit_event_loop().unwrap();
            slint::CloseRequestResponse::HideWindow
        });
    })
    .unwrap();
}

fn main() -> Result<(), slint::PlatformError> {
    let event_loop_thread = spawn(|| {
        slint::run_event_loop_until_quit().unwrap();
    });

    sleep(Duration::from_millis(100));
    run_app();

    event_loop_thread.join().unwrap();
    Ok(())
}
