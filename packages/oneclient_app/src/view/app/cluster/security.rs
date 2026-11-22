//! Instance → Security: the sandbox, what it lets through, what mods may
//! change on the profile, and what they did with the account

use freya::prelude::*;
use oneclient_broker::{Activity, ActivityKind, ChangeRule};
use oneclient_core::security::InstanceSecurity;
use oneclient_sandbox::Protection;

use crate::components::{
    Button, Dropdown, IconType, OverlayPopup, ScrollArea, caution_card, toggle_controlled,
};
use crate::i18n::{t, tf};
use crate::layout::cluster_content;
use crate::theme::{colors, rounded, text_size};
use crate::ui::border_all_color;
use crate::view::app::settings::{section_header, settings_row, settings_row_danger};

const DIALOG_WIDTH: f32 = 420.;
/// The activity box scrolls on its own past this height
const ACTIVITY_MAX_HEIGHT: f32 = 420.;
const DROPDOWN_WIDTH: f32 = 220.;

#[derive(PartialEq)]
pub struct ClusterSecurity {
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
        ActivityKind::Launched => tf(
            "oneclient.cluster.security.activity.launched",
            &[&local_time(activity, "%-d %b, %H:%M")],
        ),
        ActivityKind::Connected { .. } => {
            t("oneclient.cluster.security.activity.reconnected").to_string()
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
        ActivityKind::Allowed { what, caller, .. } => tf(
            "oneclient.cluster.security.activity.allowed",
            &[what, caller],
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
        ActivityKind::SwitchedAccount { to, .. } => tf(
            "oneclient.cluster.security.activity.switched_account",
            &[to],
        ),
        ActivityKind::Imported {
            from, to: Some(_), ..
        } => tf("oneclient.cluster.security.activity.imported", &[from]),
        ActivityKind::Imported { from, to: None, .. } => tf(
            "oneclient.cluster.security.activity.import_refused",
            &[from],
        ),
        ActivityKind::Trashed {
            path, done: true, ..
        } => tf("oneclient.cluster.security.activity.trashed", &[path]),
        ActivityKind::Trashed {
            path, done: false, ..
        } => tf("oneclient.cluster.security.activity.trash_refused", &[path]),
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

/// One launch's activity: the launch itself (none for what came before the
/// launcher recorded launches) and what happened during it, newest first
#[derive(Debug, PartialEq)]
struct LaunchGroup<'a> {
    launched: Option<&'a Activity>,
    entries: Vec<&'a Activity>,
}

/// Splits activity (newest first, as the launcher keeps it) into launches,
/// newest first. The game connecting right after its launch says nothing the
/// launch header doesn't, so only later reconnects are kept
fn group_by_launch(activity: &[Activity]) -> Vec<LaunchGroup<'_>> {
    let mut groups = Vec::new();
    let mut current = LaunchGroup {
        launched: None,
        entries: Vec::new(),
    };
    let mut connected = false;
    // oldest first, so each launch collects what follows it
    for entry in activity.iter().rev() {
        match entry.kind {
            ActivityKind::Launched => {
                if current.launched.is_some() || !current.entries.is_empty() {
                    groups.push(current);
                }
                current = LaunchGroup {
                    launched: Some(entry),
                    entries: Vec::new(),
                };
                connected = false;
            }
            ActivityKind::Connected { .. } if current.launched.is_some() && !connected => {
                connected = true;
            }
            _ => current.entries.push(entry),
        }
    }
    if current.launched.is_some() || !current.entries.is_empty() {
        groups.push(current);
    }
    for group in &mut groups {
        group.entries.reverse();
    }
    groups.reverse();
    groups
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

fn local_time(activity: &Activity, format: &str) -> String {
    activity
        .at
        .with_timezone(&chrono::Local)
        .format(format)
        .to_string()
}

fn activity_row(activity: &Activity) -> Element {
    rect()
        .horizontal()
        .width(Size::fill())
        .content(Content::Flex)
        .spacing(10.)
        .child(
            label()
                .text(local_time(activity, "%H:%M"))
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

/// The line that opens a launch: when it started, ruled off from the
/// launch above it
fn launch_header(launched: Option<&Activity>, first: bool) -> Element {
    let text = match launched {
        Some(launch) => tf(
            "oneclient.cluster.security.activity.launched",
            &[&local_time(launch, "%-d %b, %H:%M")],
        ),
        None => t("oneclient.cluster.security.activity.earlier").to_string(),
    };
    let mut header =
        rect()
            .width(Size::fill())
            .padding(Gaps::new(if first { 0. } else { 10. }, 0., 2., 0.));
    if !first {
        header = header.border(
            Border::new()
                .width(BorderWidth {
                    top: 1.,
                    ..Default::default()
                })
                .fill(colors::component_border()),
        );
    }
    header
        .child(
            label()
                .text(text)
                .font_size(text_size(12.5))
                .font_weight(FontWeight::SEMI_BOLD)
                .color(colors::fg_strong()),
        )
        .into_element()
}

fn activity_list(activity: &[Activity]) -> Element {
    let groups = group_by_launch(activity);
    if groups.is_empty() {
        return list_card(vec![list_text(
            t("oneclient.cluster.security.activity.empty").to_string(),
            colors::fg_secondary(),
        )]);
    }
    let mut rows = Vec::new();
    for (i, group) in groups.iter().enumerate() {
        rows.push(launch_header(group.launched, i == 0));
        if group.entries.is_empty() {
            rows.push(list_text(
                t("oneclient.cluster.security.activity.quiet").to_string(),
                colors::fg_secondary(),
            ));
        }
        rows.extend(group.entries.iter().map(|entry| activity_row(entry)));
    }
    rect()
        .width(Size::fill())
        .corner_radius(rounded(8.))
        .background(colors::component_bg())
        .border(border_all_color(1., colors::component_border()))
        .overflow(Overflow::Clip)
        .child(
            ScrollArea::new()
                .width(Size::fill())
                .height(Size::Inner)
                .max_height(Size::px(ACTIVITY_MAX_HEIGHT))
                .padding(Gaps::new_all(10.))
                .spacing(6.)
                .children(rows),
        )
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

const RULES: [ChangeRule; 3] = [ChangeRule::Allow, ChangeRule::Ask, ChangeRule::Deny];

fn rule_label(rule: ChangeRule) -> String {
    match rule {
        ChangeRule::Allow => t("oneclient.cluster.security.changes.allow"),
        ChangeRule::Ask => t("oneclient.cluster.security.changes.ask"),
        ChangeRule::Deny => t("oneclient.cluster.security.changes.deny"),
    }
    .to_string()
}

/// A dropdown row for one kind of profile change
fn rule_row(
    settings: State<Option<InstanceSecurity>>,
    cluster_id: i64,
    current: &InstanceSecurity,
    icon: IconType,
    title: &'static str,
    description: &'static str,
    field: fn(&mut InstanceSecurity) -> &mut ChangeRule,
) -> Element {
    let mut copy = current.clone();
    let value = *field(&mut copy);
    let current = current.clone();
    settings_row(
        icon,
        title,
        description,
        Dropdown::new(
            rule_label(value),
            RULES.iter().map(|r| rule_label(*r)).collect(),
        )
        .width(Size::px(DROPDOWN_WIDTH))
        .height(Size::px(34.))
        .on_select(move |idx: usize| {
            if let Some(rule) = RULES.get(idx).copied() {
                let mut next = current.clone();
                *field(&mut next) = rule;
                save(settings, cluster_id, next);
            }
        }),
    )
    .into_element()
}

fn access_label(write: bool) -> String {
    if write {
        t("oneclient.cluster.security.folders.read_write")
    } else {
        t("oneclient.cluster.security.folders.read_only")
    }
    .to_string()
}

impl Component for ClusterSecurity {
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
            return cluster_content().into_element();
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
                .width(Size::px(DROPDOWN_WIDTH))
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

        // ---- profile changes
        let skin_row = rule_row(
            settings,
            cluster_id,
            &current,
            IconType::Brush01,
            t("oneclient.cluster.security.changes.skin.title"),
            t("oneclient.cluster.security.changes.skin.description"),
            |s| &mut s.skin_changes,
        );
        let name_row = rule_row(
            settings,
            cluster_id,
            &current,
            IconType::Pencil01,
            t("oneclient.cluster.security.changes.name.title"),
            t("oneclient.cluster.security.changes.name.description"),
            |s| &mut s.name_changes,
        );
        let cape_row = rule_row(
            settings,
            cluster_id,
            &current,
            IconType::LayersThree01,
            t("oneclient.cluster.security.changes.cape.title"),
            t("oneclient.cluster.security.changes.cape.description"),
            |s| &mut s.cape_changes,
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
        let grants = (!current.grants.is_empty()).then(|| {
            list_card(
                current
                    .grants
                    .iter()
                    .map(|grant| {
                        let mut without = current.clone();
                        without.grants.retain(|g| g.path != grant.path);
                        let revoked = grant.path.clone();
                        let path = grant.path.clone();
                        let was_write = grant.write;
                        let edited = current.clone();
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
                                Dropdown::new(
                                    access_label(grant.write),
                                    vec![access_label(false), access_label(true)],
                                )
                                .width(Size::px(160.))
                                .height(Size::px(30.))
                                .on_select(move |idx: usize| {
                                    let write = idx == 1;
                                    if write == was_write {
                                        return;
                                    }
                                    // taking write away: the next launch grants
                                    // reading only, so drop what's there now
                                    if was_write
                                        && let Err(err) =
                                            oneclient_sandbox::revoke_grant(cluster_id, &path)
                                    {
                                        tracing::warn!("could not revoke a folder grant: {err}");
                                    }
                                    let mut next = edited.clone();
                                    if next.grant(path.clone(), write).is_ok() {
                                        save(settings, cluster_id, next);
                                    }
                                }),
                            )
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

        cluster_content()
            .child(
                ScrollArea::new()
                    .width(Size::fill())
                    .height(Size::fill())
                    .scrollbar_gutter(true)
                    .spacing(4.)
                    .child(section_header(t(
                        "oneclient.cluster.security.section.protection",
                    )))
                    .append_children(protection_card(protection.as_ref()))
                    .child(sandbox_row)
                    .child(mic_row)
                    .child(localhost_row)
                    .child(section_header(t(
                        "oneclient.cluster.security.section.changes",
                    )))
                    .child(skin_row)
                    .child(name_row)
                    .child(cape_row)
                    .child(section_header(t(
                        "oneclient.cluster.security.section.folders",
                    )))
                    .child(folders_row)
                    .append_children(grants)
                    .append_children(grant_error)
                    .child(section_header(t(
                        "oneclient.cluster.security.section.activity",
                    )))
                    .child(activity_row_header)
                    .child(activity_list(&activity)),
            )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(kind: ActivityKind) -> Activity {
        Activity::now(1, kind)
    }

    fn join(caller: &str) -> ActivityKind {
        ActivityKind::Join {
            server_hash: String::new(),
            caller: caller.into(),
        }
    }

    fn connected() -> ActivityKind {
        ActivityKind::Connected {
            agent_version: "t".into(),
        }
    }

    #[test]
    fn activity_is_grouped_by_launch_newest_first() {
        // oldest first, then reversed the way the launcher hands it out
        let mut log = vec![
            at(join("older")),
            at(ActivityKind::Launched),
            at(connected()),
            at(join("a")),
            at(connected()),
            at(ActivityKind::Launched),
            at(connected()),
            at(join("b")),
        ];
        log.reverse();

        let groups = group_by_launch(&log);
        let callers = |g: &LaunchGroup<'_>| {
            g.entries
                .iter()
                .map(|e| match &e.kind {
                    ActivityKind::Join { caller, .. } => caller.clone(),
                    ActivityKind::Connected { .. } => "reconnected".into(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(groups.len(), 3);
        assert!(groups[0].launched.is_some());
        assert_eq!(callers(&groups[0]), ["b"]);
        // the first connection belongs to the launch; a later one is news
        assert_eq!(callers(&groups[1]), ["reconnected", "a"]);
        assert!(groups[2].launched.is_none());
        assert_eq!(callers(&groups[2]), ["older"]);
    }
}
