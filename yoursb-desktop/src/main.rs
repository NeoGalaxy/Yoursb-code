use rfd::FileDialog;
use slint::SharedString;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let start_screen = StartScreen::new()?;
    // let main_window;

    start_screen.on_browse_files(|curr_file| {
        let diag = FileDialog::new().set_directory("/").pick_folder();
        match diag {
            Some(new_file) => SharedString::from(new_file.to_string_lossy().to_string()),
            None => curr_file,
        }
    });
    start_screen.on_submit({
        let start_screen = start_screen.as_weak();
        move |global, local_path| {
            start_screen.upgrade().map(|s| s.window().hide());
        }
    });

    start_screen.show()?;
    slint::run_event_loop()?;
    Ok(())
}
