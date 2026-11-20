//! Instance settings → Security: the sandbox, what it lets through, and what
//! mods did with the account

use freya::prelude::*;
use oneclient_broker::{Activity, ActivityKind};
use oneclient_core::security::InstanceSecurity;
use oneclient_sandbox::Protection;

use crate::components::{Button, IconType};
use crate::i18n::{t, tf};
use crate::theme::{self, text_size};
use crate::view::app::settings::{section_header, settings_row, settings_row_danger};

const ACTIVITY_SHOWN: usize = 20;

#[derive(PartialEq)]
pub struct SecuritySection {
    pub cluster_id: i64,
}

fn note(text: String) -> Element {
    rect()
        .width(Size::fill())
        .padding(Gaps::new(2., 0., 6., 46.))
        .child(
            label()
                .text(text)
                .font_size(text_size(12.))
                .color(theme::colors::fg_secondary()),
        )
        .into_element()
}

fn protection_text(protection: Option<Protection>) -> String {
    match protection {
        None => t("oneclient.cluster.security.status.unknown").to_string(),
        Some(Protection::Full) => t("oneclient.cluster.security.status.full").to_string(),
        Some(Protection::Partial(gaps)) => tf(
            "oneclient.cluster.security.status.partial",
            &[&gaps.join(" ")],
        ),
        Some(Protection::Off(reason)) => tf("oneclient.cluster.security.status.off", &[&reason]),
    }
}

fn describe(activity: &Activity) -> String {
    let time = activity
        .at
        .with_timezone(&chrono::Local)
        .format("%H:%M")
        .to_string();
    let what = match &activity.kind {
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
    };
    format!("{time}  {what}")
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

        // ---- sandbox switch, with a deliberate second step to turn it off
        let sandbox_row = if current.sandbox {
            let button = if *confirming_off.read() {
                let mut off = current.clone();
                off.sandbox = false;
                Button::new()
                    .small()
                    .danger()
                    .on_press(move |_| {
                        confirming_off.set(false);
                        save(settings, cluster_id, off.clone());
                    })
                    .text(t("oneclient.cluster.security.sandbox.confirm_off"))
            } else {
                Button::new()
                    .small()
                    .secondary()
                    .on_press(move |_| confirming_off.set(true))
                    .text(t("oneclient.cluster.security.sandbox.turn_off"))
            };
            settings_row(
                IconType::Lock01,
                t("oneclient.cluster.security.sandbox.title"),
                t("oneclient.cluster.security.sandbox.description_on"),
                button,
            )
            .into_element()
        } else {
            let mut on = current.clone();
            on.sandbox = true;
            settings_row_danger(
                IconType::AlertTriangle,
                t("oneclient.cluster.security.sandbox.title"),
                t("oneclient.cluster.security.sandbox.description_off"),
                Button::new()
                    .small()
                    .on_press(move |_| save(settings, cluster_id, on.clone()))
                    .text(t("oneclient.cluster.security.sandbox.turn_on")),
            )
            .into_element()
        };

        // ---- microphone: automatic, always, never
        let mic_label = match current.microphone {
            None => t("oneclient.cluster.security.microphone.auto"),
            Some(true) => t("oneclient.cluster.security.microphone.on"),
            Some(false) => t("oneclient.cluster.security.microphone.off"),
        };
        let mut next_mic = current.clone();
        next_mic.microphone = match current.microphone {
            None => Some(true),
            Some(true) => Some(false),
            Some(false) => None,
        };
        let mic_row = settings_row(
            IconType::Lock01,
            t("oneclient.cluster.security.microphone.title"),
            t("oneclient.cluster.security.microphone.description"),
            Button::new()
                .small()
                .secondary()
                .on_press(move |_| save(settings, cluster_id, next_mic.clone()))
                .text(mic_label),
        );

        // ---- servers on this computer
        let mut next_local = current.clone();
        next_local.localhost = !current.localhost;
        let localhost_row = settings_row(
            IconType::Link03,
            t("oneclient.cluster.security.localhost.title"),
            t("oneclient.cluster.security.localhost.description"),
            Button::new()
                .small()
                .secondary()
                .on_press(move |_| save(settings, cluster_id, next_local.clone()))
                .text(if current.localhost {
                    t("oneclient.cluster.security.allowed")
                } else {
                    t("oneclient.cluster.security.blocked")
                }),
        );

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
        let grant_rows: Vec<Element> = current
            .grants
            .iter()
            .map(|grant| {
                let mut without = current.clone();
                without.grants.retain(|g| g.path != grant.path);
                let revoked = grant.path.clone();
                rect()
                    .horizontal()
                    .width(Size::fill())
                    .cross_align(Alignment::Center)
                    .padding(Gaps::new(2., 0., 2., 46.))
                    .spacing(10.)
                    .child(
                        label()
                            .text(grant.path.display().to_string())
                            .font_size(text_size(12.))
                            .color(theme::colors::fg_secondary()),
                    )
                    .child(
                        Button::new()
                            .small()
                            .ghost()
                            .on_press(move |_| {
                                if let Err(err) =
                                    oneclient_sandbox::revoke_grant(cluster_id, &revoked)
                                {
                                    tracing::warn!("could not revoke a folder grant: {err}");
                                }
                                save(settings, cluster_id, without.clone());
                            })
                            .text(t("oneclient.cluster.security.folders.remove")),
                    )
                    .into_element()
            })
            .collect();

        // ---- activity
        let activity_rows: Vec<Element> = if activity.is_empty() {
            vec![note(
                t("oneclient.cluster.security.activity.empty").to_string(),
            )]
        } else {
            activity
                .iter()
                .take(ACTIVITY_SHOWN)
                .map(|a| {
                    let line = label().text(describe(a)).font_size(text_size(12.)).color(
                        if a.is_alarm() {
                            theme::colors::danger()
                        } else {
                            theme::colors::fg_secondary()
                        },
                    );
                    rect()
                        .width(Size::fill())
                        .padding(Gaps::new(1., 0., 1., 46.))
                        .child(line)
                        .into_element()
                })
                .collect()
        };
        let activity_row = settings_row(
            IconType::Eye,
            t("oneclient.cluster.security.activity.title"),
            t("oneclient.cluster.security.activity.description"),
            Button::new()
                .small()
                .ghost()
                .on_press(move |_| *refresh.write() += 1)
                .text(t("oneclient.cluster.security.activity.refresh")),
        );

        rect()
            .vertical()
            .width(Size::fill())
            .child(section_header(t(
                "oneclient.cluster.settings.section.security",
            )))
            .child(note(protection_text(protection)))
            .child(sandbox_row)
            .maybe_child(
                confirming_off
                    .read()
                    .then(|| note(t("oneclient.cluster.security.sandbox.warning").to_string())),
            )
            .child(mic_row)
            .child(localhost_row)
            .child(folders_row)
            .children(grant_rows)
            .maybe_child(grant_error.read().clone().map(note))
            .child(activity_row)
            .children(activity_rows)
            .into_element()
    }
}
