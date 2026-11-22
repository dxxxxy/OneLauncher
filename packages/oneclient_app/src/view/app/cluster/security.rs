//! Instance → Security: the sandbox, what it lets through, what mods may
//! change on the profile, and what they did with the account

use freya::prelude::*;
use oneclient_broker::{Activity, ActivityKind, ChangeRule};
use oneclient_core::security::InstanceSecurity;
use oneclient_sandbox::Protection;

use crate::components::{
    Button, Dropdown, Icon, IconType, OverlayPopup, ScrollArea, caution_card, toggle_controlled,
};
use crate::hooks::{use_cluster, use_game_snapshot};
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

/// A row that keeps its own state however the rows around it change: rows
/// come and go with the sandbox, and a switch must not inherit another's
fn keyed(key: &'static str, row: impl IntoElement) -> Element {
    rect()
        .key(key)
        .width(Size::fill())
        .child(row)
        .into_element()
}

fn caption(text: &'static str) -> Element {
    label()
        .text(text)
        .width(Size::fill())
        .margin(Gaps::new(0., 2., 6., 2.))
        .font_size(text_size(12.5))
        .color(colors::fg_secondary())
        .into_element()
}

fn save(mut settings: State<Option<InstanceSecurity>>, cluster_id: i64, next: InstanceSecurity) {
    settings.set(Some(next.clone()));
    spawn(async move {
        if let Err(err) = next.save(cluster_id).await {
            tracing::warn!("could not save security settings: {err}");
        }
        // the shield beside Play follows
        if let Ok(state) = crate::launcher::state() {
            state.security.settings_changed();
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

/// What one launch amounted to, for the overview
#[derive(Debug, Default, PartialEq)]
struct LaunchStats {
    blocked: usize,
    changes: usize,
    joins: usize,
}

fn launch_stats(group: &LaunchGroup<'_>) -> LaunchStats {
    let mut stats = LaunchStats::default();
    for entry in &group.entries {
        match entry.kind {
            ActivityKind::Denied { .. }
            | ActivityKind::Alarm { .. }
            | ActivityKind::SensitiveAccess { .. }
            | ActivityKind::OpenRefused { .. }
            | ActivityKind::DiscordDenied { .. }
            | ActivityKind::BadHandshake
            | ActivityKind::JoinLimited { .. } => stats.blocked += 1,
            ActivityKind::Allowed { .. } | ActivityKind::SwitchedAccount { .. } => {
                stats.changes += 1;
            }
            ActivityKind::Join { .. } => stats.joins += 1,
            _ => {}
        }
    }
    stats
}

/// Mods that did what no legitimate mod does (raised the alarm, reached for
/// private files), most often first. The name is the jar the agent saw on
/// the stack: a hint, since a hostile mod can fake it
fn suspects(activity: &[Activity]) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for entry in activity {
        let caller = match &entry.kind {
            ActivityKind::Alarm { caller, .. } | ActivityKind::SensitiveAccess { caller, .. } => {
                caller
            }
            _ => continue,
        };
        let name = if caller.trim().is_empty() {
            t("oneclient.cluster.security.suspects.unknown").to_string()
        } else {
            caller.clone()
        };
        match counts.iter_mut().find(|(n, _)| *n == name) {
            Some((_, count)) => *count += 1,
            None => counts.push((name, 1)),
        }
    }
    counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    counts
}

fn check_line(kept: bool, text: String) -> Element {
    let (icon, color) = if kept {
        (IconType::Check, colors::success())
    } else {
        (IconType::AlertCircle, colors::danger())
    };
    rect()
        .horizontal()
        .width(Size::fill())
        .content(Content::Flex)
        .cross_align(Alignment::Center)
        .spacing(8.)
        .child(Icon::new(icon).size(14.).color(color))
        .child(list_text(text, colors::fg_primary()))
        .into_element()
}

/// A line in "what mods can use": not a problem, just worth knowing
fn reach_line(text: String) -> Element {
    rect()
        .horizontal()
        .width(Size::fill())
        .content(Content::Flex)
        .cross_align(Alignment::Center)
        .spacing(8.)
        .child(
            Icon::new(IconType::InfoCircle)
                .size(14.)
                .color(colors::fg_secondary()),
        )
        .child(list_text(text, colors::fg_primary()))
        .into_element()
}

fn column(title: &'static str, lines: Vec<Element>) -> Element {
    rect()
        .vertical()
        .width(Size::flex(1.))
        .spacing(6.)
        .child(
            label()
                .text(title)
                .font_size(text_size(12.))
                .font_weight(FontWeight::SEMI_BOLD)
                .color(colors::fg_secondary()),
        )
        .children(lines)
        .into_element()
}

fn stat_tile(value: usize, caption: &'static str) -> Element {
    rect()
        .vertical()
        .width(Size::flex(1.))
        .spacing(2.)
        .padding(Gaps::new_all(10.))
        .corner_radius(rounded(8.))
        .background(colors::page_elevated())
        .child(
            label()
                .text(value.to_string())
                .font_size(text_size(20.))
                .font_weight(FontWeight::BOLD)
                .color(colors::fg_strong()),
        )
        .child(
            label()
                .text(caption)
                .font_size(text_size(12.))
                .color(colors::fg_secondary()),
        )
        .into_element()
}

/// The top of the page: how protected the game is, what mods can and can't
/// reach, and how the latest launch went
fn overview(
    protection: Option<&Protection>,
    running: bool,
    settings: &InstanceSecurity,
    latest: Option<&LaunchGroup<'_>>,
) -> Element {
    let (title, color) = match protection {
        Some(Protection::Full) => (
            t("oneclient.cluster.security.overview.full"),
            colors::success(),
        ),
        Some(Protection::Partial(_)) => (
            t("oneclient.cluster.security.overview.partial"),
            colors::code_warn(),
        ),
        Some(Protection::Off(_)) => (
            t("oneclient.cluster.security.overview.off"),
            colors::danger(),
        ),
        None => (
            t("oneclient.cluster.security.overview.checking"),
            colors::fg_secondary(),
        ),
    };
    let subtitle = if running {
        t("oneclient.cluster.security.overview.now")
    } else {
        t("oneclient.cluster.security.overview.next")
    };
    let sandboxed = protection.is_some_and(Protection::is_sandboxed);
    // what's missing from a partial launch, or why there's no sandbox
    let detail = match protection {
        Some(Protection::Partial(gaps)) => Some((gaps.join(" "), colors::code_warn())),
        Some(Protection::Off(reason)) if !reason.is_empty() => {
            Some((reason.clone(), colors::danger()))
        }
        _ => None,
    };

    let kept: Vec<Element> = if sandboxed {
        [
            "oneclient.cluster.security.overview.kept.token",
            "oneclient.cluster.security.overview.kept.browsers",
            "oneclient.cluster.security.overview.kept.discord",
            "oneclient.cluster.security.overview.kept.wallets",
            "oneclient.cluster.security.overview.kept.launchers",
            "oneclient.cluster.security.overview.kept.files",
        ]
        .into_iter()
        .map(|key| check_line(true, t(key).to_string()))
        .collect()
    } else {
        vec![check_line(
            false,
            t("oneclient.cluster.security.overview.exposed").to_string(),
        )]
    };

    let mut reach = vec![
        reach_line(t("oneclient.cluster.security.overview.reach.instance").to_string()),
        reach_line(t("oneclient.cluster.security.overview.reach.internet").to_string()),
    ];
    if !settings.grants.is_empty() {
        reach.push(reach_line(tf(
            "oneclient.cluster.security.overview.reach.folders",
            &[&settings.grants.len()],
        )));
    }
    match settings.microphone {
        Some(true) => reach.push(reach_line(
            t("oneclient.cluster.security.overview.reach.microphone").to_string(),
        )),
        None => reach.push(reach_line(
            t("oneclient.cluster.security.overview.reach.microphone_auto").to_string(),
        )),
        Some(false) => {}
    }
    if settings.localhost {
        reach.push(reach_line(
            t("oneclient.cluster.security.overview.reach.localhost").to_string(),
        ));
    }

    // without the sandbox the list is everything
    if !sandboxed {
        reach = vec![reach_line(
            t("oneclient.cluster.security.overview.reach.everything").to_string(),
        )];
    }

    let latest = latest.map(|group| {
        let stats = launch_stats(group);
        rect()
            .vertical()
            .width(Size::fill())
            .spacing(6.)
            .child(
                label()
                    .text(t("oneclient.cluster.security.overview.latest"))
                    .font_size(text_size(12.))
                    .font_weight(FontWeight::SEMI_BOLD)
                    .color(colors::fg_secondary()),
            )
            .child(
                rect()
                    .horizontal()
                    .width(Size::fill())
                    .content(Content::Flex)
                    .spacing(8.)
                    .child(stat_tile(
                        stats.blocked,
                        t("oneclient.cluster.security.overview.blocked"),
                    ))
                    .child(stat_tile(
                        stats.changes,
                        t("oneclient.cluster.security.overview.changes"),
                    ))
                    .child(stat_tile(
                        stats.joins,
                        t("oneclient.cluster.security.overview.joins"),
                    )),
            )
            .into_element()
    });

    rect()
        .vertical()
        .width(Size::fill())
        .spacing(16.)
        .padding(Gaps::new_all(16.))
        .margin(Gaps::new(12., 0., 4., 0.))
        .corner_radius(rounded(12.))
        .background(colors::component_bg())
        .border(border_all_color(1., colors::component_border()))
        .child(
            rect()
                .horizontal()
                .cross_align(Alignment::Center)
                .spacing(12.)
                .child(Icon::new(IconType::Lock01).size(28.).color(color))
                .child(
                    rect()
                        .vertical()
                        .spacing(2.)
                        .child(
                            label()
                                .text(title)
                                .font_size(text_size(18.))
                                .font_weight(FontWeight::SEMI_BOLD)
                                .color(colors::fg_strong()),
                        )
                        .child(
                            label()
                                .text(subtitle)
                                .font_size(text_size(12.5))
                                .color(colors::fg_secondary()),
                        )
                        .maybe_child(detail.map(|(text, color)| {
                            label()
                                .text(text)
                                .margin(Gaps::new(4., 0., 0., 0.))
                                .font_size(text_size(12.5))
                                .color(color)
                                .into_element()
                        })),
                ),
        )
        .child(
            rect()
                .horizontal()
                .width(Size::fill())
                .content(Content::Flex)
                .spacing(16.)
                .child(column(
                    t("oneclient.cluster.security.overview.kept_title"),
                    kept,
                ))
                .child(column(
                    t("oneclient.cluster.security.overview.reach_title"),
                    reach,
                )),
        )
        .maybe_child(latest)
        .into_element()
}

/// A warning card naming the mods that set off alarms, if any did
fn suspects_card(activity: &[Activity]) -> Option<Element> {
    let suspects = suspects(activity);
    if suspects.is_empty() {
        return None;
    }
    let lines = suspects
        .into_iter()
        .take(5)
        .map(|(name, count)| tf("oneclient.cluster.security.suspects.line", &[&name, &count]))
        .collect::<Vec<_>>()
        .join("\n");
    Some(
        caution_card(
            t("oneclient.cluster.security.suspects.title"),
            format!(
                "{}\n\n{lines}",
                t("oneclient.cluster.security.suspects.body")
            ),
        )
        .into_element(),
    )
}

impl Component for ClusterSecurity {
    fn render(&self) -> impl IntoElement {
        let cluster_id = self.cluster_id;
        let mut settings = use_state(|| None::<InstanceSecurity>);
        let mut confirming_off = use_state(|| false);
        let mut grant_error = use_state(|| None::<String>);
        let mut refresh = use_state(|| 0u64);
        let mut shown = use_state(|| None::<Protection>);
        let running = use_game_snapshot().is_running(cluster_id);
        let folder_name = use_cluster(cluster_id)
            .map(|c| c.folder_name.clone())
            .unwrap_or_default();
        use_hook(move || {
            spawn(async move {
                settings.set(Some(InstanceSecurity::load(cluster_id).await));
            })
        });
        // new activity and protection changes show as they happen
        use_hook(move || {
            spawn(async move {
                let Ok(state) = crate::launcher::state() else {
                    return;
                };
                let mut changes = state.security.subscribe();
                while changes.changed().await.is_ok() {
                    let revision = *changes.borrow_and_update();
                    refresh.set(revision);
                }
            })
        });
        // live while the game runs, predicted from the settings otherwise
        let key = (running, *refresh.read(), settings.read().clone());
        use_side_effect_with_deps(&key, move |(running, _, settings)| {
            // the settings on screen, not the file: a change being saved
            // shows straight away
            let Some(settings) = settings.clone() else {
                return;
            };
            let running = *running;
            let folder_name = folder_name.clone();
            spawn(async move {
                let Ok(state) = crate::launcher::state() else {
                    return;
                };
                let live = running
                    .then(|| state.security.protection(cluster_id))
                    .flatten();
                let protection = match live {
                    Some(live) => live,
                    None => {
                        oneclient_core::security::predicted_protection(&settings, &folder_name)
                            .await
                    }
                };
                shown.set(Some(protection));
            });
        });

        let Some(current) = settings.read().clone() else {
            return cluster_content().into_element();
        };
        let state = crate::launcher::state().ok();
        let protection = shown.read().clone();
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
        let groups = group_by_launch(&activity);
        // history from before launches were marked isn't one launch
        let latest = groups.first().filter(|group| group.launched.is_some());
        let overview = overview(shown.read().as_ref(), running, &current, latest);
        let suspects = suspects_card(&activity);

        // only meaningful while the game is sandboxed
        let sandbox_settings: Vec<Element> = if current.sandbox {
            let mut rows = vec![
                keyed("microphone", mic_row),
                keyed("localhost", localhost_row),
                keyed("folders", folders_row),
            ];
            rows.extend(grants.map(|grants| keyed("grants", grants)));
            rows.extend(grant_error.map(|error| keyed("grant-error", error)));
            rows
        } else {
            vec![keyed(
                "sandbox-off-note",
                caption(t("oneclient.cluster.security.sandbox.off_note")),
            )]
        };

        cluster_content()
            .child(
                ScrollArea::new()
                    .width(Size::fill())
                    .height(Size::fill())
                    .scrollbar_gutter(true)
                    .spacing(4.)
                    .child(keyed("overview", overview))
                    .append_children(suspects.map(|card| keyed("suspects", card)))
                    .child(keyed(
                        "sandbox-header",
                        section_header(t("oneclient.cluster.security.section.protection")),
                    ))
                    .child(keyed("sandbox", sandbox_row))
                    .append_children(sandbox_settings)
                    .child(keyed(
                        "changes-header",
                        section_header(t("oneclient.cluster.security.section.changes")),
                    ))
                    .child(keyed("skin", skin_row))
                    .child(keyed("name", name_row))
                    .child(keyed("cape", cape_row))
                    .child(keyed(
                        "activity-header",
                        section_header(t("oneclient.cluster.security.section.activity")),
                    ))
                    .child(keyed(
                        "activity-caption",
                        caption(t("oneclient.cluster.security.activity.description")),
                    ))
                    .child(keyed("activity", activity_list(&activity))),
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

    fn alarm(caller: &str) -> ActivityKind {
        ActivityKind::Alarm {
            method: "POST".into(),
            url: "https://authserver.mojang.com/".into(),
            reason: "r".into(),
            caller: caller.into(),
        }
    }

    #[test]
    fn mods_that_set_off_alarms_are_counted_most_often_first() {
        let log = vec![
            at(alarm("mods/a.jar")),
            at(join("mods/b.jar")),
            at(ActivityKind::SensitiveAccess {
                path: "Login Data".into(),
                caller: "mods/b.jar".into(),
            }),
            at(alarm("mods/b.jar")),
        ];
        assert_eq!(
            suspects(&log),
            [("mods/b.jar".to_string(), 2), ("mods/a.jar".to_string(), 1)]
        );
    }

    #[test]
    fn a_launch_counts_what_was_blocked_changed_and_joined() {
        let mut log = vec![
            at(ActivityKind::Launched),
            at(join("a")),
            at(join("a")),
            at(alarm("b")),
            at(ActivityKind::Allowed {
                method: "PUT".into(),
                url: "u".into(),
                what: "change your cape".into(),
                caller: "c".into(),
            }),
        ];
        log.reverse();
        let groups = group_by_launch(&log);
        assert_eq!(
            launch_stats(&groups[0]),
            LaunchStats {
                blocked: 1,
                changes: 1,
                joins: 2,
            }
        );
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
