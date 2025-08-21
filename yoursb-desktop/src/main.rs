mod desktop_ctx;
mod errors;
mod repo;

use rfd::FileDialog;
use slint::SharedString;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let start_screen = StartScreen::new()?;
    let home = HomeScreen::new()?;

    start_screen.on_browse_files(|curr_file| {
        let diag = FileDialog::new().set_directory("/").pick_folder();
        match diag {
            Some(new_file) => SharedString::from(new_file.to_string_lossy().to_string()),
            None => curr_file,
        }
    });
    start_screen.on_submit({
        let start_screen = start_screen.as_weak();
        let home = home.as_weak();
        move |global, local_path| {
            if let Some(h) = home.upgrade() {
                h.window().show().unwrap()
            }
            if let Some(s) = start_screen.upgrade() {
                s.window().hide().unwrap()
            }
        }
    });

    home.show()?;
    // start_screen.show()?;
    // home.window().hide()?;
    slint::run_event_loop()?;
    Ok(())
}
