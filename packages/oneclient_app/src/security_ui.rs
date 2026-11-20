//! What the game's sandbox borrows from the launcher's UI: opening links and
//! folders on the real desktop, and file pickers that can see the user's
//! files (the game's own can't)

use std::path::{Path, PathBuf};

use oneclient_broker::{BoxFuture, PickMode};
use oneclient_core::security::SecurityUi;

pub struct AppSecurityUi;

impl SecurityUi for AppSecurityUi {
    fn open_url(&self, url: &str) {
        crate::platform::open_url(url);
    }

    fn open_path(&self, path: &Path) {
        crate::platform::open_path(&path.display().to_string());
    }

    fn pick(&self, mode: PickMode, title: String) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async move {
            let mut dialog = rfd::AsyncFileDialog::new();
            if !title.trim().is_empty() {
                dialog = dialog.set_title(format!("{title} (for your game)"));
            }
            crate::platform::focus_window();
            let handle = match mode {
                PickMode::OpenFile => dialog.pick_file().await,
                PickMode::OpenFolder => dialog.pick_folder().await,
                PickMode::SaveFile => dialog.save_file().await,
            };
            handle.map(|h| h.path().to_path_buf())
        })
    }
}
