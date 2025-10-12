mod desktop_ctx;
mod errors;
mod repo;

use std::{
    iter,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    thread::{sleep, spawn},
    time::Duration,
};

use rfd::FileDialog;
use slint::{invoke_from_event_loop, ModelRc, SharedString, VecModel};
use yoursb_domain::{
    crypto::create_key,
    interfaces::{FilePath, InitInstanceContext, Instance, PathOrLeaf},
};

use crate::{
    desktop_ctx::{DesktopCtx, DesktopInstance},
    repo::RepoPath,
};

slint::include_modules!();

fn open_instance() -> Option<DesktopInstance> {
    let start_screen_handle = Arc::new(Mutex::new(None));
    let (snd, rcv) = mpsc::sync_channel(2);
    invoke_from_event_loop({
        let start_screen_handle = start_screen_handle.clone();
        move || {
            let start_screen = StartScreen::new().unwrap();
            *start_screen_handle.lock().unwrap() = Some(start_screen.as_weak());
            drop(start_screen_handle); // 10000% force unlock

            start_screen.on_browse_files(|curr_file| {
                let diag = FileDialog::new().set_directory("/").pick_folder();
                match diag {
                    Some(new_file) => SharedString::from(new_file.to_string_lossy().to_string()),
                    None => curr_file,
                }
            });

            start_screen.on_open_instance({
                let snd = snd.clone();
                move |create, global, local_path| {
                    let msg = if global {
                        RepoPath::Global
                    } else {
                        RepoPath::Local(Some(PathBuf::from(&local_path)))
                    };
                    let _ = snd.send(Some((create, msg))); // Todo: do we want to close the window?
                }
            });

            start_screen.show().unwrap();
            start_screen.window().on_close_requested({
                move || {
                    match snd.send(None) {
                        Ok(_) => slint::CloseRequestResponse::KeepWindowShown,
                        Err(_) => slint::CloseRequestResponse::HideWindow, // something went wrong
                    }
                }
            });
        }
    })
    .unwrap();
    loop {
        let Ok(Some((create, path))) = rcv.recv() else {
            let _ = start_screen_handle
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| s.upgrade_in_event_loop(|s| s.window().hide().unwrap()));
            return None;
        };

        let instance = if create {
            desktop_ctx::DesktopCtx::new_instance(
                path,
                create_key("blblblbl", &DesktopCtx::new_dummy()),
            )
        } else {
            desktop_ctx::DesktopInstance::open(Some(path))
        };
        match instance {
            Ok(i) => {
                start_screen_handle
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("the closure in event loop should've set the handle but didn't")
                    .upgrade_in_event_loop(|s| s.window().hide().unwrap())
                    .unwrap();
                return Some(i);
            }
            Err(err) => {
                start_screen_handle
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("the closure in event loop should've set the handle but didn't")
                    .upgrade_in_event_loop(move |s| s.set_error_text(format!("{err:?}").into()))
                    .unwrap();
                continue;
            }
        }
    }
}
fn run_app() {
    let Some(instance) = open_instance() else {
        slint::quit_event_loop().unwrap();
        return;
    };
    invoke_from_event_loop(move || {
        let files = instance
            .list_content::<false>(FilePath::<false>::root())
            .map(|c| c.collect::<Vec<_>>())
            .unwrap_or_default();
        let passwords = instance
            .list_content::<true>(FilePath::<true>::root())
            .map(|c| c.collect::<Vec<_>>())
            .unwrap_or_default();

        let home = HomeScreen::new().unwrap();
        home.set_Categories(ModelRc::from([ModelRc::from([
            Category {
                content: ModelRc::new(VecModel::from_iter(files.into_iter().filter_map(
                    |f| match f {
                        Ok(PathOrLeaf::Leaf(p)) => Some(Entry {
                            kind: EntryKind::File,
                            name: p.to_string().into(),
                        }),
                        Ok(PathOrLeaf::Path(p)) => Some(Entry {
                            kind: EntryKind::FileDir,
                            name: p.to_string().into(),
                        }),
                        Err(_) => None,
                    },
                ))),
                icon: Icon::File,
                name: "Files".into(),
            },
            Category {
                content: ModelRc::new(VecModel::from_iter(passwords.into_iter().filter_map(|f| {
                    match f {
                        Ok(PathOrLeaf::Leaf(p)) => Some(Entry {
                            kind: EntryKind::Pass,
                            name: p.to_string().into(),
                        }),
                        Ok(PathOrLeaf::Path(p)) => Some(Entry {
                            kind: EntryKind::PassDir,
                            name: p.to_string().into(),
                        }),
                        Err(_) => None,
                    }
                }))),
                icon: Icon::Pass,
                name: "Passwords".into(),
            },
        ])]));
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

    sleep(Duration::from_millis(100)); // Ensures the event loop thread started
    run_app();

    event_loop_thread.join().unwrap();
    Ok(())
}
