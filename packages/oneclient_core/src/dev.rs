use std::collections::HashMap;
use std::sync::Arc;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tokio::sync::mpsc;
use uuid::Uuid;

use oneclient_content::packages::provider::PackageProviderRegistry;
use oneclient_events::{
    Answer, Choice, ChoiceInput, ChoiceStyle, Event, EventBus, GameEvent, GroupedProgressEvent,
    InputValue, Level, Notification, ProgressEvent, PromptRequest,
};
use oneclient_net::RequestClient;

use crate::{LauncherResult, LauncherServices, LauncherState};

struct GroupedSessionUi {
    title: String,
    parent: ProgressBar,
    children: HashMap<Uuid, ProgressBar>,
    child_bytes: HashMap<Uuid, (u64, u64)>,
}

fn spawn_notification_handler(mut rx: oneclient_events::EventReceiver) {
    tokio::spawn(async move {
        let mp = MultiProgress::new();
        let mut progress_bars: HashMap<Uuid, ProgressBar> = HashMap::new();
        let mut grouped_sessions: HashMap<Uuid, GroupedSessionUi> = HashMap::new();

        let flat_style = ProgressStyle::with_template(
            "{spinner:.green} {msg:<20} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
        )
        .unwrap()
        .progress_chars("#>-");

        let parent_style = ProgressStyle::with_template(
            "{spinner:.green} {msg:<30} [{elapsed_precise}] [{wide_bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .progress_chars("#>-");

        let child_style = ProgressStyle::with_template(
            "  {spinner:.cyan} {msg:<38} [{bar:32.cyan/blue}] {bytes}/{total_bytes}",
        )
        .unwrap()
        .progress_chars("#>-");

        while let Some(event) = rx.recv().await {
            match event {
                Event::Notification(Notification::Message(message)) => {
                    let (title, body) = (message.title, message.body);
                    mp.suspend(|| match message.level {
                        Level::Info => tracing::info!(%title, %body),
                        Level::Error => tracing::error!(%title, %body),
                    });
                }
                Event::Progress(ProgressEvent::Update {
                    id,
                    label,
                    current,
                    total,
                }) => {
                    if current >= total {
                        if let Some(pb) = progress_bars.remove(&id) {
                            pb.finish_with_message(format!("{label} Done!"));
                        }
                    } else {
                        let pb = progress_bars.entry(id).or_insert_with(|| {
                            let pb = mp.add(ProgressBar::new(total));
                            pb.set_style(flat_style.clone());
                            pb.set_message(label.clone());
                            pb
                        });

                        pb.set_length(total);
                        pb.set_position(current);
                    }
                }
                Event::Progress(ProgressEvent::Complete {
                    id, title, body, ..
                }) => {
                    if let Some(pb) = progress_bars.remove(&id) {
                        pb.finish_with_message(format!("{title}: {body}"));
                    } else {
                        mp.suspend(|| tracing::info!(%title, %body));
                    }
                }
                Event::Progress(ProgressEvent::Grouped(event)) => match event {
                    GroupedProgressEvent::Start { session_id, title } => {
                        let parent = mp.add(ProgressBar::new(1));
                        parent.set_style(parent_style.clone());
                        parent.set_message(title.clone());

                        grouped_sessions.insert(
                            session_id,
                            GroupedSessionUi {
                                title,
                                parent,
                                children: HashMap::new(),
                                child_bytes: HashMap::new(),
                            },
                        );
                    }
                    GroupedProgressEvent::Expect { .. } => {}
                    GroupedProgressEvent::AddChild {
                        session_id,
                        child_id,
                        label,
                        total,
                        ..
                    } => {
                        let Some(session) = grouped_sessions.get_mut(&session_id) else {
                            continue;
                        };

                        let child = ProgressBar::new(total);
                        child.set_style(child_style.clone());
                        child.set_message(label.clone());
                        mp.add(child.clone());

                        session.children.insert(child_id, child);
                        session.child_bytes.insert(child_id, (0, total));
                        refresh_grouped_parent(session);
                    }
                    GroupedProgressEvent::UpdateChild {
                        session_id,
                        child_id,
                        current,
                        total,
                    } => {
                        let Some(session) = grouped_sessions.get_mut(&session_id) else {
                            continue;
                        };

                        if let Some(child) = session.children.get(&child_id) {
                            child.set_length(total);
                            child.set_position(current);
                        }
                        session.child_bytes.insert(child_id, (current, total));
                        refresh_grouped_parent(session);
                    }
                    GroupedProgressEvent::SetChildPhase {
                        session_id,
                        child_id,
                        phase,
                    } => {
                        if let Some(session) = grouped_sessions.get(&session_id)
                            && let Some(child) = session.children.get(&child_id)
                        {
                            child.set_prefix(phase.label());
                        }
                    }
                    GroupedProgressEvent::FinishChild {
                        session_id,
                        child_id,
                    } => {
                        let Some(session) = grouped_sessions.get_mut(&session_id) else {
                            continue;
                        };

                        if let Some(child) = session.children.remove(&child_id) {
                            child.finish_and_clear();
                        }
                        session.child_bytes.remove(&child_id);
                        refresh_grouped_parent(session);
                    }
                    GroupedProgressEvent::Abort { session_id } => {
                        if let Some(session) = grouped_sessions.remove(&session_id) {
                            session
                                .parent
                                .abandon_with_message(format!("{} - failed", session.title));
                        }
                    }
                    GroupedProgressEvent::End { session_id } => {
                        if let Some(session) = grouped_sessions.remove(&session_id) {
                            session
                                .parent
                                .finish_with_message(format!("{} - complete", session.title));
                        }
                    }
                },
                Event::Signal(_) | Event::Chat(_) => {}
                Event::Game(GameEvent::Stage { cluster_id, stage }) => {
                    mp.suspend(|| tracing::info!(cluster_id, ?stage, "game stage"));
                }
                Event::Game(GameEvent::Log { line, .. }) => {
                    mp.suspend(|| tracing::info!("[game] {line}"));
                }
                Event::Game(GameEvent::Failed {
                    cluster_id,
                    message,
                }) => {
                    mp.suspend(|| tracing::error!(cluster_id, "launch failed: {message}"));
                }
                Event::Game(GameEvent::Crashed(crash)) => {
                    mp.suspend(|| {
                        tracing::error!(
                            cluster_id = crash.cluster_id,
                            fixes = crash.fixes.len(),
                            "{}",
                            crash.title
                        );
                    });
                }
                // In a terminal the prompt is asked there. Elsewhere it's
                // dismissed so the waiting task fails cleanly instead of
                // hanging, unless `ONECLIENT_DEV_PROMPTS=primary` picks the
                // main choice for unattended runs
                Event::Notification(Notification::Prompt(request)) => {
                    let PromptRequest {
                        title,
                        body,
                        choices,
                        dismiss,
                        reply,
                    } = request;
                    let answer =
                        if std::env::var("ONECLIENT_DEV_PROMPTS").as_deref() == Ok("primary") {
                            let choice = choices
                                .iter()
                                .find(|c| c.style == ChoiceStyle::Primary)
                                .or(choices.first());
                            mp.suspend(|| {
                                tracing::info!(
                                    "{title}: answering {:?}",
                                    choice.map(|c| c.label.as_str())
                                );
                            });
                            choice.map(|c| Answer {
                                id: c.id,
                                input: None,
                            })
                        } else if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                            let mp = mp.clone();
                            tokio::task::spawn_blocking(move || {
                                mp.suspend(|| ask_in_terminal(&title, &body, &choices, dismiss))
                            })
                            .await
                            .ok()
                            .flatten()
                        } else {
                            mp.suspend(|| {
                                tracing::warn!("{title}: {body}");
                                tracing::warn!("no terminal to ask in; dismissing");
                            });
                            None
                        };
                    let _ = reply.send(answer);
                }
            }
        }
    });
}

fn ask_in_terminal(
    title: &str,
    body: &str,
    choices: &[Choice],
    dismiss: Option<String>,
) -> Option<Answer> {
    use std::io::Write;

    fn read_line() -> Option<String> {
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok()?;
        Some(line.trim().to_owned())
    }

    println!(
        "
{title}
{body}"
    );
    for (i, choice) in choices.iter().enumerate() {
        println!("  {}. {}", i + 1, choice.label);
    }
    println!("  0. {}", dismiss.as_deref().unwrap_or("Dismiss"));
    print!("> ");
    let picked: usize = read_line()?.parse().ok()?;
    let choice = choices.get(picked.checked_sub(1)?)?;
    let input = match &choice.input {
        Some(ChoiceInput::Folder { title }) => {
            print!("{title}: ");
            Some(InputValue::Folder(read_line()?.into()))
        }
        // the caller falls back to its default selection
        Some(ChoiceInput::Selection { .. }) | None => None,
    };
    Some(Answer {
        id: choice.id,
        input,
    })
}

fn refresh_grouped_parent(session: &mut GroupedSessionUi) {
    let (current, total) = session
        .child_bytes
        .values()
        .fold((0u64, 0u64), |(cur, tot), (c, t)| (cur + c, tot + t));

    let total = total.max(1);
    session.parent.set_length(total);
    session.parent.set_position(current.min(total));
}

pub async fn initialize() -> LauncherResult<Arc<LauncherState>> {
    let (tx, rx) = mpsc::unbounded_channel();

    spawn_notification_handler(rx);

    LauncherState::new(EventBus::new(tx)).await
}

async fn ephemeral_root() -> LauncherResult<std::path::PathBuf> {
    let path = std::env::current_dir()
        .map_err(crate::LauncherError::StdIoError)?
        .join("target")
        .join(format!("ephemeral-{}", Uuid::new_v4()));

    polyio::create_dir_all(&path).await?;

    Ok(path)
}

pub async fn ephemeral_state() -> LauncherResult<Arc<LauncherState>> {
    state_at(ephemeral_root().await?).await
}

/// A launcher kept in `root`, so downloads (Java, game files) survive
/// between runs. Never point it at a real launcher folder
pub async fn state_at(root: std::path::PathBuf) -> LauncherResult<Arc<LauncherState>> {
    polyio::create_dir_all(&root).await?;
    oneclient_common::paths::set_launcher_dir(root.clone());

    let (tx, rx) = mpsc::unbounded_channel();
    spawn_notification_handler(rx);

    let db = oneclient_db::connect(root.join("example.db")).await?;
    let settings = crate::settings::store::load_settings(None).await;

    let services = LauncherServices {
        events: EventBus::new(tx),
        requester: RequestClient::new(oneclient_net::NetConfig::default())?,
        db,
        packages: PackageProviderRegistry::new(),
        prefetches: Arc::default(),
    };
    let auth = Arc::new(oneclient_auth::AuthService::with_store(
        Default::default(),
        services.requester.clone(),
        services.events.clone(),
    ));

    let clusters = crate::clusters::ClusterManager::new(services.db.clone());

    let java = oneclient_java::JavaService::new(
        Arc::new(crate::java_store::SqlJavaStore::new(services.db.clone())),
        services.requester.clone(),
        services.events.clone(),
    );

    Ok(Arc::new(LauncherState {
        services,
        auth,
        java,
        clusters,
        settings: parking_lot::RwLock::new(settings),
        metadata: tokio::sync::Mutex::new(oneclient_mc::MetadataStore::new()),
        bundles: Arc::new(oneclient_content::bundles::BundlesManager::new()),
        versions: Arc::new(crate::versions::VersionsManager::new()),
        images: crate::images::ImageCacheStore::new(),
        games: crate::game::GameProcessManager::new(),
        discord: oneclient_discord::DiscordRpc::spawn(false),
        security: Arc::default(),
    }))
}

pub async fn ephemeral_services() -> LauncherResult<LauncherServices> {
    let root = ephemeral_root().await?;
    oneclient_common::paths::set_launcher_dir(root.clone());
    let db = oneclient_db::connect(root.join("example.db")).await?;
    let (tx, rx) = mpsc::unbounded_channel();
    spawn_notification_handler(rx);

    Ok(LauncherServices {
        events: EventBus::new(tx),
        requester: RequestClient::new(oneclient_net::NetConfig::default())?,
        db,
        packages: PackageProviderRegistry::new(),
        prefetches: Arc::default(),
    })
}

pub async fn seed_bundle_archive(
    state: &LauncherState,
    manifest: oneclient_content::bundles::BundleManifest,
) -> LauncherResult<()> {
    let disk_path = format!("bundles/{}.mrpack", manifest.name);
    let loader = manifest.loader as i64;

    oneclient_db::dao::bundle::upsert_bundle(
        &state.services.db,
        oneclient_db::models::NewBundle {
            remote_path: &disk_path,
            mc_version: &manifest.mc_version,
            mc_loader: loader,
            file_name: &format!("{}.mrpack", manifest.name),
            name: Some(&manifest.name),
            version_id: Some(&manifest.version_id),
            category: Some(&manifest.category),
            loader_version: Some(&manifest.loader_version),
            disk_path: &disk_path,
            hidden: false,
            etag: None,
            synced_at: None,
        },
    )
    .await?;

    let path = oneclient_common::paths::data_dir()?.join(&disk_path);
    state.bundles.cache_archive_manifest(path, manifest).await;

    Ok(())
}
