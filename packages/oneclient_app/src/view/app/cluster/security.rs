//! Instance settings → Security: the sandbox, what it lets through, and what
//! mods did with the account

use freya::prelude::*;
use oneclient_broker::{Activity, ActivityKind};
use oneclient_core::security::InstanceSecurity;
use oneclient_sandbox::Protection;

use crate::components::{
    Button, Dropdown, IconType, OverlayPopup, caution_card, toggle_controlled,
};
use crate::i18n::{t, tf};
use crate::theme::{colors, rounded, text_size};
use crate::ui::border_all_color;
use crate::view::app::settings::{section_header, settings_row, settings_row_danger};

const ACTIVITY_SHOWN: usize = 20;
const DIALOG_WIDTH: f32 = 420.;

#[derive(PartialEq)]
pub struct SecuritySection {
    pub cluster_id: i64,
}

/// The row description for the sandbox: how the last launch was protected
fn sandbox_description(on: bool, protection: Option<&Protection>) -> String {
    if !on {
        return t("oneclient.cluster.security.sandbox.description_off").to_string();
    }
    match protection {
        Some(Protection::Full) => t("oneclient.cluster.security.status.full").to_string(),
        _ => t("oneclient.cluster.security.sandbox.description_on").to_string(),
    }
}

/// Partial and off launches get a card that says what's missing
fn protection_card(protection: Option<&Protection>) -> Option<Element> {
    let body = match protection? {
        Protection::Full => return None,
        Protection::Partial(gaps) => tf(
            "oneclient.cluster.security.status.partial",
            &[&gaps.join(" ")],
        ),
        Protection::Off(reason) => tf("oneclient.cluster.security.status.off", &[reason]),
    };
    Some(caution_card(t("oneclient.cluster.security.status.title"), body).into_element())
}

fn describe(activity: &Activity) -> String {
    match &activity.kind {
        ActivityKind::Connected { .. } => {
            t("oneclient.cluster.security.activity.connected").to_string()
        }
        ActivityKind::BadHandshake => {
            t("oneclient.cluster.security.activity.bad_handshake").to_string()
        }
        ActivityKind::Join { caller, .. } => {
            tf("oneclient.cluster.security.activity.join", &[caller])
        }
        ActivityKind::JoinLimited { caller } => tf(
            "oneclient.cluster.security.activity.join_limited",
            &[caller],
        ),
        ActivityKind::Denied { method, url, .. } => {
            tf("oneclient.cluster.security.activity.denied", &[method, url])
        }
        ActivityKind::Alarm { reason, caller, .. } => tf(
            "oneclient.cluster.security.activity.alarm",
            &[reason, caller],
        ),
        ActivityKind::Opened { target, .. } => {
            tf("oneclient.cluster.security.activity.opened", &[target])
        }
        ActivityKind::OpenRefused { target, .. } => tf(
            "oneclient.cluster.security.activity.open_refused",
            &[target],
        ),
        ActivityKind::Picked { path, .. } => tf(
            "oneclient.cluster.security.activity.picked",
            &[&path.as_deref().unwrap_or("-")],
        ),
        ActivityKind::SensitiveAccess { path, caller } => tf(
            "oneclient.cluster.security.activity.sensitive",
            &[caller, path],
        ),
        ActivityKind::DiscordDenied { command } => tf(
            "oneclient.cluster.security.activity.discord_denied",
            &[command],
        ),
    }
}

/// A bordered list under a row, styled like the other settings lists
fn list_card(rows: Vec<Element>) -> Element {
    rect()
        .vertical()
        .width(Size::fill())
        .spacing(6.)
        .padding(Gaps::new_all(10.))
        .corner_radius(rounded(8.))
        .background(colors::component_bg())
        .border(border_all_color(1., colors::component_border()))
        .children(rows)
        .into_element()
}

fn list_text(text: String, color: Color) -> Element {
    label()
        .text(text)
        .width(Size::flex(1.))
        .font_size(text_size(12.5))
        .max_lines(2)
        .text_overflow(TextOverflow::Ellipsis)
        .color(color)
        .into_element()
}

fn activity_row(activity: &Activity) -> Element {
    let time = activity
        .at
        .with_timezone(&chrono::Local)
        .format("%H:%M")
        .to_string();
    rect()
        .horizontal()
        .width(Size::fill())
        .content(Content::Flex)
        .spacing(10.)
        .child(
            label()
                .text(time)
                .font_size(text_size(12.5))
                .color(colors::fg_secondary()),
        )
        .child(list_text(
            describe(activity),
            if activity.is_alarm() {
                colors::danger()
            } else {
                colors::fg_primary()
            },
        ))
        .into_element()
}

fn save(mut settings: State<Option<InstanceSecurity>>, cluster_id: i64, next: InstanceSecurity) {
    settings.set(Some(next.clone()));
    spawn(async move {
        if let Err(err) = next.save(cluster_id).await {
            tracing::warn!("could not save security settings: {err}");
        }
    });
}

impl Component for SecuritySection {
    fn render(&self) -> impl IntoElement {
        let cluster_id = self.cluster_id;
        let mut settings = use_state(|| None::<InstanceSecurity>);
        let mut confirming_off = use_state(|| false);
        let mut grant_error = use_state(|| None::<String>);
        let mut refresh = use_state(|| 0u32);
        use_hook(move || {
            spawn(async move {
                settings.set(Some(InstanceSecurity::load(cluster_id).await));
            })
        });

        let Some(current) = settings.read().clone() else {
            return rect().into_element();
        };
        let state = crate::launcher::state().ok();
        let _ = *refresh.read();
        let protection = state
            .as_ref()
            .and_then(|s| s.security.protection(cluster_id));
        let activity: Vec<Activity> = state
            .as_ref()
            .map(|s| s.security.activity_for(cluster_id))
            .unwrap_or_default();

        // ---- sandbox: turning it off goes through a confirmation
        let sandbox_toggle = {
            let current = current.clone();
            toggle_controlled(
                current.sandbox,
                (move |()| {
                    if current.sandbox {
                        confirming_off.set(true);
                    } else {
                        let mut on = current.clone();
                        on.sandbox = true;
                        save(settings, cluster_id, on);
                    }
                })
                .into(),
            )
        };
        let sandbox_description = sandbox_description(current.sandbox, protection.as_ref());
        let sandbox_row = if current.sandbox {
            settings_row(
                IconType::Lock01,
                t("oneclient.cluster.security.sandbox.title"),
                sandbox_description,
                sandbox_toggle,
            )
            .into_element()
        } else {
            settings_row_danger(
                IconType::AlertTriangle,
                t("oneclient.cluster.security.sandbox.title"),
                sandbox_description,
                sandbox_toggle,
            )
            .into_element()
        };
        let confirm_off = confirming_off.read().then(|| {
            let mut off = current.clone();
            off.sandbox = false;
            SandboxOffModal {
                on_close: (move |()| confirming_off.set(false)).into(),
                on_confirm: (move |()| save(settings, cluster_id, off.clone())).into(),
            }
            .into_element()
        });

        // ---- microphone: automatic, allowed, blocked
        let mic_options = [None, Some(true), Some(false)];
        let mic_label = |value: Option<bool>| match value {
            None => t("oneclient.cluster.security.microphone.auto").to_string(),
            Some(true) => t("oneclient.cluster.security.microphone.on").to_string(),
            Some(false) => t("oneclient.cluster.security.microphone.off").to_string(),
        };
        let mic_row = {
            let current = current.clone();
            settings_row(
                IconType::Users01,
                t("oneclient.cluster.security.microphone.title"),
                t("oneclient.cluster.security.microphone.description"),
                Dropdown::new(
                    mic_label(current.microphone),
                    mic_options.iter().map(|v| mic_label(*v)).collect(),
                )
                .width(Size::px(220.))
                .height(Size::px(34.))
                .on_select(move |idx: usize| {
                    if let Some(value) = mic_options.get(idx).copied() {
                        let mut next = current.clone();
                        next.microphone = value;
                        save(settings, cluster_id, next);
                    }
                }),
            )
        };

        // ---- servers on this computer
        let localhost_row = {
            let current = current.clone();
            settings_row(
                IconType::Globe01,
                t("oneclient.cluster.security.localhost.title"),
                t("oneclient.cluster.security.localhost.description"),
                toggle_controlled(
                    current.localhost,
                    (move |()| {
                        let mut next = current.clone();
                        next.localhost = !current.localhost;
                        save(settings, cluster_id, next);
                    })
                    .into(),
                ),
            )
        };

        // ---- shared folders
        let add_folder = {
            let current = current.clone();
            move |_| {
                let mut next = current.clone();
                spawn(async move {
                    let Some(handle) = rfd::AsyncFileDialog::new()
                        .set_title(t("oneclient.cluster.security.folders.picker"))
                        .pick_folder()
                        .await
                    else {
                        return;
                    };
                    match next.grant(handle.path().to_path_buf(), false) {
                        Ok(()) => {
                            grant_error.set(None);
                            save(settings, cluster_id, next);
                        }
                        Err(reason) => grant_error.set(Some(tf(
                            "oneclient.cluster.security.folders.refused",
                            &[&reason],
                        ))),
                    }
                });
            }
        };
        let folders_row = settings_row(
            IconType::Folder,
            t("oneclient.cluster.security.folders.title"),
            t("oneclient.cluster.security.folders.description"),
            Button::new()
                .small()
                .secondary()
                .on_press(add_folder)
                .text(t("oneclient.cluster.security.folders.add")),
        );
        let grants = (!current.grants.is_empty()).then(|| {
            list_card(
                current
                    .grants
                    .iter()
                    .map(|grant| {
                        let mut without = current.clone();
                        without.grants.retain(|g| g.path != grant.path);
                        let revoked = grant.path.clone();
                        rect()
                            .horizontal()
                            .width(Size::fill())
                            .content(Content::Flex)
                            .cross_align(Alignment::Center)
                            .spacing(10.)
                            .child(list_text(
                                grant.path.display().to_string(),
                                colors::fg_primary(),
                            ))
                            .child(
                                Button::new()
                                    .small()
                                    .ghost()
                                    .on_press(move |_| {
                                        if let Err(err) =
                                            oneclient_sandbox::revoke_grant(cluster_id, &revoked)
                                        {
                                            tracing::warn!(
                                                "could not revoke a folder grant: {err}"
                                            );
                                        }
                                        save(settings, cluster_id, without.clone());
                                    })
                                    .text(t("oneclient.cluster.security.folders.remove")),
                            )
                            .into_element()
                    })
                    .collect(),
            )
        });
        let grant_error = grant_error.read().clone().map(|error| {
            caution_card(t("oneclient.cluster.security.folders.refused_title"), error)
                .into_element()
        });

        // ---- activity
        let activity_row_header = settings_row(
            IconType::Eye,
            t("oneclient.cluster.security.activity.title"),
            t("oneclient.cluster.security.activity.description"),
            Button::new()
                .small()
                .secondary()
                .on_press(move |_| *refresh.write() += 1)
                .text(t("oneclient.cluster.security.activity.refresh")),
        );
        let activity_list = list_card(if activity.is_empty() {
            vec![list_text(
                t("oneclient.cluster.security.activity.empty").to_string(),
                colors::fg_secondary(),
            )]
        } else {
            activity
                .iter()
                .take(ACTIVITY_SHOWN)
                .map(activity_row)
                .collect()
        });

        rect()
            .vertical()
            .width(Size::fill())
            .spacing(4.)
            .child(section_header(t(
                "oneclient.cluster.settings.section.security",
            )))
            .maybe_child(protection_card(protection.as_ref()))
            .child(sandbox_row)
            .child(mic_row)
            .child(localhost_row)
            .child(folders_row)
            .maybe_child(grants)
            .maybe_child(grant_error)
            .child(activity_row_header)
            .child(activity_list)
            .maybe_child(confirm_off)
            .into_element()
    }
}

/// Second step before an instance runs without the sandbox
#[derive(PartialEq)]
struct SandboxOffModal {
    on_close: EventHandler<()>,
    on_confirm: EventHandler<()>,
}

impl Component for SandboxOffModal {
    fn render(&self) -> impl IntoElement {
        let close_scrim = self.on_close.clone();
        let close_cancel = self.on_close.clone();
        let close_confirm = self.on_close.clone();
        let on_confirm = self.on_confirm.clone();

        OverlayPopup::new()
            .on_close(move |()| close_scrim.call(()))
            .child(
                rect()
                    .width(Size::window_percent(100.))
                    .height(Size::window_percent(100.))
                    .center()
                    .child(
                        rect()
                            .vertical()
                            .width(Size::px(DIALOG_WIDTH))
                            .max_width(Size::window_percent(92.))
                            .spacing(16.)
                            .padding(Gaps::new_all(20.))
                            .corner_radius(rounded(16.))
                            .background(colors::page_elevated())
                            .border(border_all_color(1., colors::component_border()))
                            .child(
                                label()
                                    .text(t("oneclient.cluster.security.sandbox.confirm_title"))
                                    .font_size(text_size(18.))
                                    .font_weight(FontWeight::SEMI_BOLD)
                                    .color(colors::fg_primary()),
                            )
                            .child(
                                label()
                                    .text(t("oneclient.cluster.security.sandbox.warning"))
                                    .font_size(text_size(13.))
                                    .color(colors::fg_secondary()),
                            )
                            .child(
                                rect()
                                    .horizontal()
                                    .width(Size::fill())
                                    .main_align(Alignment::End)
                                    .spacing(8.)
                                    .child(
                                        Button::new()
                                            .ghost()
                                            .on_press(move |_| close_cancel.call(()))
                                            .text(t("oneclient.common.cancel")),
                                    )
                                    .child(
                                        Button::new()
                                            .danger()
                                            .on_press(move |_| {
                                                on_confirm.call(());
                                                close_confirm.call(());
                                            })
                                            .text(t(
                                                "oneclient.cluster.security.sandbox.confirm_off",
                                            )),
                                    ),
                            ),
                    ),
            )
            .into_element()
    }
}
