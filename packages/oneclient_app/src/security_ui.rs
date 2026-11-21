//! What the game's sandbox borrows from the launcher's UI: opening links and
//! folders on the real desktop, and file pickers that can see the user's
//! files (the game's own can't)

use std::path::{Path, PathBuf};

use oneclient_broker::{BoxFuture, PickMode, PickRequest};
use oneclient_core::security::SecurityUi;

pub struct AppSecurityUi;

impl SecurityUi for AppSecurityUi {
    fn open_url(&self, url: &str) {
        crate::platform::open_url(url);
    }

    fn open_path(&self, path: &Path) {
        crate::platform::open_path(&path.display().to_string());
    }

    fn pick(&self, request: PickRequest) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async move {
            let mut dialog = rfd::AsyncFileDialog::new();
            if !request.title.trim().is_empty() {
                dialog = dialog.set_title(format!("{} (for your game)", request.title));
            }
            // a filter for "any file" makes every other one pointless
            if !request
                .filters
                .iter()
                .any(|f| f.extensions.iter().any(|e| e == "*"))
            {
                for filter in &request.filters {
                    dialog = dialog.add_filter(&filter.name, &filter.extensions);
                }
            }
            crate::platform::focus_window();
            let handle = match request.mode {
                PickMode::OpenFile => dialog.pick_file().await,
                PickMode::OpenFolder => dialog.pick_folder().await,
                PickMode::SaveFile => dialog.save_file().await,
            };
            handle.map(|h| h.path().to_path_buf())
        })
    }
}
