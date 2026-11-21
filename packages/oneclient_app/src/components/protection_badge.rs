//! A small shield beside an instance: how its game is protected while it
//! runs, or how the next launch will be

use freya::prelude::*;
use oneclient_sandbox::Protection;

use crate::components::{Icon, IconType, TooltipPlacement, use_tooltip_anchor};
use crate::hooks::use_game_snapshot;
use crate::i18n::{t, tf};
use crate::theme::colors;

#[derive(PartialEq)]
pub struct ProtectionBadge {
    pub cluster_id: i64,
    pub folder_name: String,
    pub size: f32,
}

impl ProtectionBadge {
    pub fn new(cluster_id: i64, folder_name: impl Into<String>) -> Self {
        Self {
            cluster_id,
            folder_name: folder_name.into(),
            size: 14.,
        }
    }

    pub fn size(mut self, size: f32) -> Self {
        self.size = size;
        self
    }
}

/// What the tooltip says, with every reason the sandbox gave
fn protection_summary(protection: &Protection) -> String {
    match protection {
        Protection::Full => t("oneclient.cluster.security.status.full").to_string(),
        Protection::Partial(gaps) => tf(
            "oneclient.cluster.security.status.partial",
            &[&gaps.join(" ")],
        ),
        Protection::Off(reason) => tf("oneclient.cluster.security.status.off", &[reason]),
    }
}

impl Component for ProtectionBadge {
    fn render(&self) -> impl IntoElement {
        let running = use_game_snapshot().is_running(self.cluster_id);
        let mut shown = use_state(|| None::<Protection>);
        let mut loaded_for = use_state(|| None::<(i64, bool)>);

        // again whenever the game starts or stops: the live protection
        // replaces the prediction, and the other way round
        let key = (self.cluster_id, running);
        let folder_name = self.folder_name.clone();
        use_side_effect_with_deps(&key, move |&(cluster_id, running)| {
            if *loaded_for.peek() == Some((cluster_id, running)) {
                return;
            }
            loaded_for.set(Some((cluster_id, running)));
            let folder_name = folder_name.clone();
            spawn(async move {
                let Ok(state) = crate::launcher::state() else {
                    return;
                };
                let protection =
                    oneclient_core::security::shown_protection(&state, cluster_id, &folder_name)
                        .await;
                shown.set(Some(protection));
            });
        });

        let protection = shown.read().clone();
        let tooltip = protection
            .as_ref()
            .map(|p| protection_summary(p).into_boxed_str());
        let anchor = use_tooltip_anchor(tooltip, TooltipPlacement::default());
        let color = match &protection {
            Some(Protection::Full) => colors::success(),
            Some(Protection::Partial(_)) => colors::code_warn(),
            Some(Protection::Off(_)) => colors::danger(),
            None => colors::fg_secondary(),
        };

        anchor.attach(
            rect()
                .a11y_role(AccessibilityRole::Image)
                .child(Icon::new(IconType::Lock01).size(self.size).color(color)),
        )
    }
}
