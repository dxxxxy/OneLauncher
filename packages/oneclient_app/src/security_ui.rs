//! What the game's sandbox borrows from the launcher's UI: opening links and
//! folders on the real desktop, and file pickers that can see the user's
//! files (the game's own can't)

use std::path::{Path, PathBuf};

use oneclient_broker::{BoxFuture, ConfirmPrompt, PickMode, PickRequest};
use oneclient_core::security::SecurityUi;

pub struct AppSecurityUi;

/// The broker calls in from its own threads, and the window can only be
/// touched from the UI thread: hand the focus to the loop that runs there
fn focus() {
    crate::ipc::send(crate::ipc::IpcCommand::Focus);
}

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
            focus();
            let handle = match request.mode {
                PickMode::OpenFile => dialog.pick_file().await,
                PickMode::OpenFolder => dialog.pick_folder().await,
                PickMode::SaveFile => dialog.save_file().await,
            };
            handle.map(|h| h.path().to_path_buf())
        })
    }

    fn focus(&self) {
        focus();
    }

    fn reveal(&self, file: &Path) {
        crate::platform::reveal_path(file);
    }

    fn confirm(&self, prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            focus();
            let deny = "Don't allow".to_string();
            let answer = rfd::AsyncMessageDialog::new()
                .set_level(rfd::MessageLevel::Warning)
                .set_title(&prompt.title)
                .set_description(&prompt.body)
                .set_buttons(rfd::MessageButtons::OkCancelCustom(
                    prompt.allow.clone(),
                    deny,
                ))
                .show()
                .await;
            match answer {
                rfd::MessageDialogResult::Custom(label) => label == prompt.allow,
                rfd::MessageDialogResult::Ok | rfd::MessageDialogResult::Yes => true,
                _ => false,
            }
        })
    }
}
