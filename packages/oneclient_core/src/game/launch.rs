use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use interfrost::api::minecraft::ArgumentType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::ClusterStage;
use crate::LauncherResult;
use crate::clusters::Cluster;
use crate::game::diagnosis::{CrashDiagnosis, CrashWatch};
use crate::game::mod_problems::{
    InstalledJar, attach_bundled, attach_jar, has_unmatched, has_unmatched_missing,
};
use crate::game::session::SessionRecorder;
use crate::game::shared_dir::{cluster_mods, jar_bundled_mod_ids, jar_mod_id};
use crate::game::tail::spawn_log_tail;
use crate::game::{DirBusy, GameError};
use crate::settings::GameSettingsProfile;
use crate::state::{LauncherServices, LauncherState};
use oneclient_auth::MinecraftAccount;
use oneclient_common::paths;
use oneclient_content::bundles::BUNDLE_APPLY_BUDGET;
use oneclient_discord::Presence;
use oneclient_events::{CrashModIssue, CrashRemedy, GroupedProgressSession, LaunchStage};
use oneclient_mc::{
    self as arguments, download_minecraft, download_version_info, game_files_missing,
    get_loader_version, resolve_minecraft_version,
};

pub fn is_running(state: &LauncherState, cluster_id: i64) -> bool {
    state.games.is_running(cluster_id)
}

#[derive(Debug, Clone)]
pub struct LaunchedGame {
    pub cluster_id: i64,
    pub pid: Option<u32>,
}

#[tracing::instrument(skip(state, account))]
pub async fn launch_cluster(
    state: &Arc<LauncherState>,
    cluster_id: i64,
    account: &MinecraftAccount,
    search_for_java: bool,
) -> LauncherResult<LaunchedGame> {
    launch_cluster_with(state, cluster_id, account, search_for_java, None, None).await
}

#[tracing::instrument(skip(state, account))]
pub async fn launch_cluster_with(
    state: &Arc<LauncherState>,
    cluster_id: i64,
    account: &MinecraftAccount,
    search_for_java: bool,
    extra_jvm_arg: Option<&str>,
    bundle_budget: Option<Duration>,
) -> LauncherResult<LaunchedGame> {
    tracing::info!(cluster_id, search_for_java, "launching cluster");

    // Parallel clusters or not a cluster runs only once a second game would
    // share its directory and its slot in the process manager
    if state.games.is_active(cluster_id) {
        tracing::warn!(
            cluster_id,
            "cluster already launching or running; refusing launch"
        );
        return Err(GameError::AlreadyRunning(cluster_id).into());
    }

    let result = start(
        state,
        cluster_id,
        account,
        search_for_java,
        extra_jvm_arg,
        bundle_budget,
    )
    .await;

    if result.is_err() {
        state.games.remove(cluster_id);
        state
            .services
            .events
            .game_stage(cluster_id, LaunchStage::Exited);
    }

    result
}

fn jvm_args_with(profile_args: Option<&str>, extra: Option<&str>) -> String {
    match (profile_args.unwrap_or_default(), extra) {
        ("", Some(extra)) => extra.to_string(),
        (args, Some(extra)) => format!("{args} {extra}"),
        (args, None) => args.to_string(),
    }
}

async fn start(
    state: &Arc<LauncherState>,
    cluster_id: i64,
    account: &MinecraftAccount,
    search_for_java: bool,
    extra_jvm_arg: Option<&str>,
    bundle_budget: Option<Duration>,
) -> LauncherResult<LaunchedGame> {
    let events = state.services.events.clone();
    let stage = |s: LaunchStage| {
        state.games.set_stage(cluster_id, s);
        events.game_stage(cluster_id, s);
    };

    // The stage goes first so a click while this waits is refused as already
    // active rather than queued behind it
    stage(LaunchStage::Checking);
    let launch_slot = match state.games.try_launch_slot() {
        Some(slot) => slot,
        None => {
            tracing::debug!(cluster_id, "another launch is preparing; waiting for it");
            stage(LaunchStage::Waiting);
            let slot = state.games.launch_slot().await;
            stage(LaunchStage::Checking);
            slot
        }
    };

    // Checked only once this launch counts as active, a reset claims itself before checking
    // for that, so the two can't both go ahead
    if crate::clusters::is_resetting(cluster_id) {
        return Err(GameError::Resetting.into());
    }
    match crate::clusters::reset_unfinished(state, cluster_id).await {
        Ok(true) => return Err(GameError::ResetUnfinished.into()),
        Ok(false) => {}
        // Only a guard against launching a half-reset cluster, not worth failing every launch over
        Err(err) => {
            tracing::warn!(cluster_id, error = %err, "could not check for an unfinished reset; launching anyway");
        }
    }

    let existing = state.clusters.get(cluster_id).await?;
    if let Some(group) = existing.missing_shared_group() {
        return Err(GameError::SharedFolderMissing(group).into());
    }

    let game_dir = existing.game_dir()?;
    let dedicated = existing.uses_dedicated_dir();

    // Non-dedicated clusters share one directory so a second game there would
    // materialize over the running one's
    match state.games.claim_dir(cluster_id, &game_dir, !dedicated) {
        Ok(()) => {}
        Err(DirBusy::Syncing(syncing)) if syncing == cluster_id => {
            return Err(GameError::Syncing.into());
        }
        Err(DirBusy::Syncing(syncing)) => {
            tracing::warn!(
                cluster_id,
                syncing,
                "shared game dir is being synced from; refusing launch"
            );
            let name = running_cluster_name(state, syncing).await;
            return Err(GameError::SharedDirectorySyncing(name).into());
        }
        Err(DirBusy::Game(other)) if dedicated => {
            return Err(GameError::DirectoryInUse(other).into());
        }
        Err(DirBusy::Game(other)) => {
            tracing::warn!(cluster_id, other, "shared game dir busy; refusing launch");
            let name = running_cluster_name(state, other).await;
            return Err(GameError::SharedDirectoryBusy(name).into());
        }
    }

    match state.clusters.mark_played(cluster_id).await {
        Ok(()) => events.signal(oneclient_events::Signal::ClustersChanged),
        Err(err) => tracing::debug!(cluster_id, error = %err, "could not record the launch time"),
    }

    let progress = GroupedProgressSession::start(
        &state.services.events,
        format!("Launching {}", existing.name),
    );

    if existing.uses_bundles()
        && let Err(err) = crate::clusters::apply_bundle_java_override(
            state,
            cluster_id,
            search_for_java,
            false,
            Some(&progress),
        )
        .await
    {
        tracing::warn!(cluster_id, error = %err, "failed to apply bundle java override");
    }

    let cluster = if existing.stage == ClusterStage::Ready {
        existing
    } else {
        stage(LaunchStage::Downloading);
        match crate::clusters::prepare_cluster_locked(
            state,
            cluster_id,
            false,
            search_for_java,
            false,
            Some(&progress),
        )
        .await
        {
            Ok(cluster) => cluster,
            Err(err) => {
                progress.finish();
                stage(LaunchStage::Exited);
                return Err(err);
            }
        }
    };
    if cluster.uses_bundles()
        && let Err(err) = oneclient_content::bundles::install_cluster_bundles(
            cluster_id,
            state.bundles.as_ref(),
            Some(&progress),
            &state.services.content(),
            Some(Instant::now() + bundle_budget.unwrap_or(BUNDLE_APPLY_BUDGET)),
        )
        .await
    {
        tracing::warn!(cluster_id, error = %err, "failed to install bundle content");
    }
    let cluster = match crate::clusters::auto_update_loader(state, &cluster).await {
        Ok(updated) => updated.unwrap_or(cluster),
        Err(err) => {
            tracing::warn!(cluster_id, error = %err, "failed to update the loader");
            cluster
        }
    };

    let global = state.settings.read().global_game_settings.clone();
    let profile = state.clusters.resolve_settings(&global, &cluster).await?;

    let mc_version = oneclient_common::version::normalize_mc_version_input(&cluster.mc_version);

    let (version, updated, loader_version, version_info) = {
        let mut metadata = state.metadata.lock().await;

        let (version, _index, updated) =
            resolve_minecraft_version(&mut metadata, &state.services.mc(), &mc_version).await?;

        let loader_version = get_loader_version(
            &mut metadata,
            &state.services.mc(),
            &mc_version,
            cluster.mc_loader,
            cluster.mc_loader_version.as_deref(),
        )
        .await?;

        let version_info = download_version_info(
            &state.services.mc(),
            Some(&progress),
            &version,
            cluster.mc_loader,
            loader_version.as_ref(),
            false,
        )
        .await;

        (version, updated, loader_version, version_info)
    };

    let version_info = match version_info {
        Ok(info) => info,
        Err(err) => {
            progress.finish();
            stage(LaunchStage::Exited);
            return Err(err.into());
        }
    };

    let version_name = loader_version.as_ref().map_or_else(
        || version.id.clone(),
        |lv| format!("{}-{}", version.id, lv.id),
    );

    tracing::info!(
        cluster_id,
        mc_version = %version.id,
        loader = %cluster.mc_loader,
        loader_version = loader_version.as_ref().map(|lv| lv.id.as_str()).unwrap_or("none"),
        version_name = %version_name,
        libraries = version_info.libraries.len(),
        main_class = %version_info.main_class,
        "resolved launch metadata"
    );

    if let Some(dir) = crate::game::natives::natives_dir(&version_name) {
        state.games.set_natives(cluster_id, dir);
    }

    let java = if let Some(runtime) = state
        .java
        .runtime_for_profile(profile.java_path.as_deref())
        .await?
    {
        runtime
    } else {
        let major = version_info
            .java_version
            .as_ref()
            .map(|v| v.major_version)
            .ok_or(GameError::MissingJavaVersion)?;

        state
            .java
            .prepare(major, search_for_java, false, None)
            .await?
    };

    // Stats every library and the asset tree, the same work `plan_downloads`
    // already keeps off the runtime threads. `block_in_place` because
    // `VersionInfo` is not `Clone` and the sweep only reads it
    let missing = tokio::task::block_in_place(|| {
        game_files_missing(&version_info, &java.os_arch, updated)
    });
    match missing {
        Ok(true) => {
            tracing::info!(cluster_id, "missing game files; repairing");
            let _ = state
                .clusters
                .set_stage(cluster_id, ClusterStage::Repairing)
                .await;
            stage(LaunchStage::Downloading);
            let natives_mode =
                crate::game::natives::natives_mode(state, &version_name, Some(cluster_id));
            if let Err(err) = download_minecraft(
                &state.services.mc(),
                &progress,
                &version_info,
                &java.os_arch,
                updated,
                false,
                natives_mode,
            )
            .await
            {
                progress.finish();
                stage(LaunchStage::Exited);
                return Err(err.into());
            }
            let _ = state
                .clusters
                .set_stage(cluster_id, ClusterStage::Ready)
                .await;
        }
        Ok(false) => {}
        Err(err @ oneclient_mc::McError::NoNativesForPlatform { .. }) => {
            progress.finish();
            stage(LaunchStage::Exited);
            return Err(err.into());
        }
        Err(err) => tracing::warn!(cluster_id, error = %err, "repair check failed"),
    }

    progress.finish();

    stage(LaunchStage::Launching);

    let cwd = game_dir;
    polyio::create_dir_all(&cwd).await.ok();

    if let Err(err) = crate::game::write_allowed_symlinks(&cwd).await {
        tracing::warn!(cluster_id, error = %err, "failed to write allowed_symlinks.txt");
    }

    let custom_args = profile.launch_args.clone().unwrap_or_default();
    let loader_version_id = loader_version.as_ref().map(|lv| lv.id.as_str());

    let mods_in_cluster =
        crate::game::uses_cluster_mods_folder(cluster.mc_loader, loader_version_id, &custom_args);

    match crate::game::materialize_content(
        &state.services,
        &cluster,
        &cwd,
        mods_in_cluster,
        profile.copy_mod_files.unwrap_or(false),
    )
    .await
    {
        Ok(()) => {}
        Err(err @ crate::LauncherError::GameError(GameError::ModCopyFailed(_))) => {
            return Err(err);
        }
        Err(err) => {
            tracing::warn!(cluster_id, error = %err, "failed to materialize cluster content");
        }
    }

    if !dedicated {
        crate::game::link_cluster_logs(&cluster, &cwd).await;
    }

    let client_jar = paths::versions_dir()?
        .join(&version_name)
        .join(format!("{version_name}.jar"));
    let natives = paths::natives_dir()?.join(&version_name);
    polyio::create_dir_all(&natives).await?;
    let libraries = paths::libraries_dir()?;
    let assets = paths::assets_dir()?;

    let arg_map = version_info.arguments.clone().unwrap_or_default();

    let protected = protect_launch(state, &cluster, &cwd, &java.absolute_path, account).await?;
    // after the sandbox's grants, so they never spread through the links
    let assets = if protected.sandbox.is_sandboxed() {
        match sandboxed_assets(&cluster.dir()?, &assets).await {
            Ok(view) => view,
            Err(err) => {
                tracing::warn!(
                    cluster_id,
                    "could not set up the instance's skin cache: {err}"
                );
                assets
            }
        }
    } else {
        assets
    };

    let classpaths = arguments::classpaths(
        &libraries,
        &version_info.libraries,
        &client_jar,
        &java.os_arch,
        updated,
    )?;

    let mut jvm_args = arguments::java_arguments(
        arg_map.get(&ArgumentType::Jvm).map(Vec::as_slice),
        &natives,
        &libraries,
        &classpaths,
        &version_name,
        profile
            .mem_max
            .unwrap_or_else(oneclient_common::default_mem_max),
        jvm_args_with(profile.launch_args.as_deref(), extra_jvm_arg),
        &java.os_arch,
        java.major,
        runtime_has_module(&java.absolute_path, "jdk.incubator.vector"),
    )?;
    if protected.sandbox.is_sandboxed() {
        sandboxed_natives(
            &mut jvm_args,
            &natives,
            &cluster.dir()?.join(".oneclient").join("natives"),
        );
    }
    jvm_args.splice(0..0, protected.jvm_arguments());

    let mods_dir = paths::cluster_mods_dir(&cluster.folder_name)?;
    if let Some(arg) = crate::game::mods_folder_argument(
        cluster.mc_loader,
        loader_version_id,
        &custom_args,
        &mods_dir,
    ) {
        tracing::debug!(cluster_id, mods_dir = %mods_dir.display(), "redirecting fabric mods folder");
        jvm_args.push(arg);
    }

    let crash_dir = cluster.dir()?.join("crash-reports");
    polyio::create_dir_all(&crash_dir).await.ok();
    let error_file = crash_dir.join("hs_err_pid").display().to_string();
    jvm_args.insert(
        0,
        format!("-XX:ErrorFile={}%p.log", error_file.replace('%', "%%")),
    );

    oneclient_cluster::logs::censor_username(&account.username);

    let mut mc_args = arguments::minecraft_arguments(
        arg_map.get(&ArgumentType::Game).map(Vec::as_slice),
        version_info.minecraft_arguments.as_deref(),
        // the game never holds the real token, only one the broker answers for
        &protected.game_token,
        &account.username,
        account.id,
        &version.id,
        &version_info.asset_index.id,
        &cwd,
        &assets,
        version.type_,
        profile.resolution.unwrap_or_default(),
        &java.os_arch,
    )?;
    arguments::append_profile_game_arguments(
        &mut mc_args,
        profile.force_fullscreen,
        profile.game_args.as_deref(),
    );

    drop(launch_slot);

    if let Some(reason) = run_hook(profile.hook_pre.as_deref(), &cwd).await {
        events
            .notify("Pre-launch command failed")
            .body(reason)
            .error()
            .send();
    }

    tracing::info!(
        cluster_id,
        java = %java.absolute_path,
        jvm_args = jvm_args.len(),
        mc_args = mc_args.len(),
        cwd = %cwd.display(),
        "spawning minecraft process"
    );
    tracing::debug!(cluster_id, ?jvm_args, main_class = %version_info.main_class, "jvm arguments");

    let (mut command, wrapper) = base_command(&profile, &java.absolute_path);

    if let Some(gpu) = profile.gpu().or(crate::game::gpu::DEFAULT) {
        crate::game::gpu::select(&mut command, &java.absolute_path, gpu).await;
    }

    apply_env(&mut command, &profile);
    protected.apply_env(&mut command);

    command
        .args(jvm_args)
        .arg(&version_info.main_class)
        .args(mc_args)
        .current_dir(&cwd);

    let header = format!(
        "OneClient {} · {} · {version_name} · Java {}\n\n{}\n\n",
        env!("CARGO_PKG_VERSION"),
        cluster.name,
        java.major,
        command_line(command.as_std(), &version_info.main_class),
    );

    let log_path = oneclient_cluster::logs::cluster_output_log(&cluster)?;
    if let Some(parent) = log_path.parent() {
        polyio::create_dir_all(parent).await.ok();
    }

    // A file not a pipe a pipe would die with the launcher and take the game's
    // next stdout write down with it
    // The cloned handle shares the file offset
    // so stdout and stderr interleave instead of overwriting
    let handles = match tokio::fs::File::create(&log_path).await {
        Ok(mut out) => {
            if let Err(err) = out.write_all(header.as_bytes()).await {
                tracing::warn!(cluster_id, error = %err, "failed to write the launch header");
            }
            match out.try_clone().await {
                Ok(err) => Ok((out.into_std().await, err.into_std().await)),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    };

    let (out, err) = match handles {
        Ok((out, err)) => (Some(out), Some(err)),
        Err(err) => {
            tracing::warn!(cluster_id, error = %err, "failed to open game log; discarding output");
            (None, None)
        }
    };
    let spec = if protected.sandbox.is_sandboxed() {
        oneclient_sandbox::SpawnSpec::from_command(command.as_std(), out, err)
    } else {
        oneclient_sandbox::SpawnSpec::inheriting(command.as_std(), out, err)
    };

    let mut child = protected
        .sandbox
        .spawn(spec)
        .map_err(|err| match &wrapper {
            Some(program) => GameError::wrapper_spawn(program, &err),
            None => GameError::Spawn(err.to_string()),
        })?;
    let pid = child.id();
    protected.keep(state, cluster_id);

    stage(LaunchStage::Running);
    state.games.set_pid(cluster_id, pid);
    state.discord.set_presence(Presence::Playing {
        cluster: cluster.name.clone(),
        mc_version: cluster.mc_version.clone(),
    });

    let recorder = SessionRecorder::start(
        state,
        cluster_id,
        profile
            .mem_max
            .unwrap_or_else(oneclient_common::default_mem_max),
        &java,
    )
    .await;

    // Pinned to the session row so that if the launcher exits first the next
    // start can tell whether the game is still playing
    if let (Some(recorder), Some(pid)) = (recorder.as_ref(), pid) {
        recorder
            .record_process(pid, crate::game::process_start_time(pid))
            .await;
    }

    let started_at = recorder
        .as_ref()
        .and_then(SessionRecorder::started_at)
        .unwrap_or_else(Utc::now);
    let crash_watch = CrashWatch::new();
    let tail = spawn_log_tail(
        cluster_id,
        log_path,
        events.clone(),
        recorder.clone(),
        crash_watch.clone(),
    );

    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
    state.games.register_kill(cluster_id, kill_tx);

    let state = Arc::clone(state);
    let post_hook = profile.hook_post.clone();
    tokio::spawn(async move {
        let cluster = cluster;
        let (status, stopped) = tokio::select! {
            status = child.wait() => (status, false),
            _ = kill_rx => (stop_child(&mut child).await, true),
        };

        tail.stop().await;

        let outcome = match status {
            Ok(_) if stopped => Exit::Killed,
            Ok(status) => Exit::Observed {
                code: status.code().map(i64::from),
                success: status.success() || killed(&status),
                display: status.to_string(),
            },
            Err(err) => Exit::Failed(err.to_string()),
        };

        state.security.drop_broker(cluster.id);
        finalize_session(
            &state,
            &cluster,
            &cwd,
            dedicated,
            post_hook.as_deref(),
            recorder,
            SessionEnd {
                started_at,
                ended_at: Utc::now(),
                outcome,
                owns_slot: true,
                diagnosis: crash_watch.take(),
                watch: Some(crash_watch),
            },
        )
        .await;
    });

    Ok(LaunchedGame { cluster_id, pid })
}

async fn running_cluster_name(state: &Arc<LauncherState>, cluster_id: i64) -> String {
    state
        .clusters
        .get(cluster_id)
        .await
        .map_or_else(|_| format!("Cluster {cluster_id}"), |cluster| cluster.name)
}

/// Asks the game to close. Under bubblewrap the PID we hold is bwrap's, which
/// doesn't pass signals on, so the whole process group is asked instead
fn stop_gracefully(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: plain kill(2) on the group the game was started in
        if unsafe { libc::kill(-(pid as i32), libc::SIGTERM) } == 0 {
            return true;
        }
    }
    crate::game::kill_process(pid)
}

#[cfg(unix)]
fn killed(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    const SIGKILL: i32 = 9;
    const JVM_SIGTERM_EXIT: i32 = 143;
    status.signal() == Some(SIGKILL) || status.code() == Some(JVM_SIGTERM_EXIT)
}

#[cfg(not(unix))]
fn killed(_status: &std::process::ExitStatus) -> bool {
    false
}

fn counts_as_crash(outcome: &Exit, diagnosis: Option<&CrashDiagnosis>, reported: bool) -> bool {
    let broken = diagnosis.is_some_and(CrashDiagnosis::leaves_game_broken);

    match outcome {
        Exit::Observed { success, .. } => {
            !success || broken || diagnosis.is_some_and(CrashDiagnosis::is_fatal)
        }
        Exit::Failed(_) => true,
        Exit::Inferred => diagnosis.is_some() || reported,
        Exit::Killed => broken,
    }
}

/// What the game gets to save and shut down in before it is killed outright
///
/// Short on purpose: someone reaching for the launcher's stop button usually
/// has a game that is already stuck, and should not wait long to find out
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(7);

/// Asks the game to close before killing it
///
/// `start_kill` is SIGKILL, so the game gets no chance to save. A terminate
/// runs its shutdown hooks, and the kill is only the fallback for a game that
/// will not go.
async fn stop_child(
    child: &mut oneclient_sandbox::GameChild,
) -> std::io::Result<std::process::ExitStatus> {
    if let Some(pid) = child.id()
        && stop_gracefully(pid)
    {
        match tokio::time::timeout(GRACEFUL_STOP_TIMEOUT, child.wait()).await {
            Ok(status) => return status,
            Err(_elapsed) => tracing::warn!(pid, "game ignored the request to close; killing it"),
        }
    }

    let _ = child.start_kill();
    child.wait().await
}

pub(crate) enum Exit {
    Observed {
        code: Option<i64>,
        success: bool,
        display: String,
    },
    Failed(String),
    Inferred,
    Killed,
}

pub(crate) struct SessionEnd {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub outcome: Exit,
    pub owns_slot: bool,
    pub diagnosis: Option<CrashDiagnosis>,
    pub watch: Option<CrashWatch>,
}

/// Shared by the live exit path and by recovery of sessions that outlived the
/// launcher
pub(crate) async fn finalize_session(
    state: &Arc<LauncherState>,
    cluster: &Cluster,
    cwd: &Path,
    dedicated: bool,
    post_hook: Option<&str>,
    recorder: Option<SessionRecorder>,
    end: SessionEnd,
) {
    let cluster_id = cluster.id;
    let played = (end.ended_at - end.started_at).to_std().unwrap_or_default();

    if end.owns_slot {
        state.games.remove(cluster_id);
        state
            .services
            .events
            .game_stage(cluster_id, LaunchStage::Exited);

        if state.games.running_ids().is_empty() {
            state.discord.set_presence(Presence::Idle);
        }
    }

    if played > Duration::from_secs(1) {
        let _ = state.clusters.add_playtime(cluster_id, played).await;
    }

    if let Some(recorder) = recorder {
        let code = match &end.outcome {
            Exit::Observed { code, .. } => *code,
            Exit::Failed(_) | Exit::Inferred | Exit::Killed => None,
        };
        recorder.finish_at(&end.ended_at.to_rfc3339(), code).await;
    }

    if let Some(reason) = run_hook(post_hook, cwd).await {
        state
            .services
            .events
            .notify("Post-exit command failed")
            .body(reason)
            .error()
            .send();
    }

    if dedicated {
        // The folder stays materialized so it remains a real Minecraft directory
        // for external tools adopting drop-ins now keeps the UI right on close
        crate::game::import_manual_content(&state.services, cluster, cwd).await;
    } else {
        if let Err(err) = crate::game::dematerialize_content(&state.services, cluster, cwd).await {
            tracing::warn!(cluster_id, error = %err, "failed to clear shared content on exit");
        }
        crate::game::unlink_cluster_logs(cwd).await;
    }

    let name = &cluster.name;
    let reported = end.watch.as_ref().is_some_and(CrashWatch::reported_crash);
    let crashed = counts_as_crash(&end.outcome, end.diagnosis.as_ref(), reported);

    crate::bisect::record_bisect_exit(
        state,
        cluster_id,
        match end.outcome {
            Exit::Failed(_) | Exit::Inferred => crate::bisect::GameExit::Unknown,
            _ if crashed => crate::bisect::GameExit::Crashed,
            Exit::Observed { .. } | Exit::Killed => crate::bisect::GameExit::Clean,
        },
        end.watch
            .as_ref()
            .map(CrashWatch::take_missing)
            .unwrap_or_default(),
        cwd,
        std::time::SystemTime::from(end.started_at),
    )
    .await;

    let display = match &end.outcome {
        Exit::Observed {
            success: false,
            display,
            ..
        } => display.clone(),
        Exit::Failed(err) => err.clone(),
        Exit::Observed { .. } | Exit::Inferred | Exit::Killed => String::new(),
    };

    match &end.outcome {
        Exit::Observed { success: true, .. } => {}
        Exit::Observed { .. } => state
            .services
            .events
            .notify("Game crashed")
            .body(format!("{name} exited with {display}"))
            .error()
            .send(),
        Exit::Failed(err) => state
            .services
            .events
            .notify("Game error")
            .body(format!("{name}: {err}"))
            .error()
            .send(),
        Exit::Killed => {}
        Exit::Inferred => {}
    }

    if crashed {
        report_crash(state, cluster, cwd, &display, played, &end).await;
    }
}

async fn report_crash(
    state: &Arc<LauncherState>,
    cluster: &Cluster,
    cwd: &Path,
    display: &str,
    played: Duration,
    end: &SessionEnd,
) {
    let watch = end.watch.as_ref();
    let diagnosis = end.diagnosis.as_ref();

    let reported = watch.is_some_and(CrashWatch::reported_crash);
    let suspects = watch.map(CrashWatch::suspects).unwrap_or_default();
    let excerpt = watch.map(CrashWatch::excerpt).unwrap_or_default();
    let document = watch.map(CrashWatch::document).unwrap_or_default();
    let fixes = crate::game::crashdata::fixes_for(&document);

    if diagnosis.is_none()
        && !reported
        && suspects.is_empty()
        && !crate::game::crashdata::has_solution(&fixes)
    {
        tracing::debug!(
            cluster_id = cluster.id,
            suggestions = fixes.len(),
            "no recognised cause, leaving it to the toast"
        );
        return;
    }

    let mod_issues = match diagnosis {
        Some(diagnosis) => crash_mod_issues(&state.services, cluster.id, diagnosis).await,
        None => Vec::new(),
    };

    state
        .services
        .events
        .game_crashed(oneclient_events::GameCrash {
            cluster_id: cluster.id,
            cluster_name: cluster.name.clone(),
            title: diagnosis.map_or_else(
                || format!("{} crashed", cluster.name),
                CrashDiagnosis::title,
            ),
            exit: display.to_string(),
            played_secs: played.as_secs(),
            cause: diagnosis.map(CrashDiagnosis::body),
            remedy: diagnosis
                .and_then(CrashDiagnosis::remedy)
                .or_else(|| (!suspects.is_empty()).then_some(CrashRemedy::OpenMods)),
            suspects,
            fixes,
            excerpt,
            game_dir: Some(cwd.to_string_lossy().to_string()),
            mod_issues,
        });
}

pub async fn crash_mod_issues(
    services: &LauncherServices,
    cluster_id: i64,
    diagnosis: &CrashDiagnosis,
) -> Vec<CrashModIssue> {
    let mut mod_issues = diagnosis.mod_issues();
    if mod_issues.is_empty() {
        return mod_issues;
    }

    let jars: Vec<InstalledJar> = cluster_mods(services, cluster_id)
        .await
        .into_iter()
        .map(|jar| InstalledJar {
            hash: jar.hash,
            enabled: jar.enabled,
            name: jar.name,
            id: None,
            version: jar.version,
        })
        .collect();

    for jar in &jars {
        attach_jar(&mut mod_issues, jar);
    }

    for jar in &jars {
        if !has_unmatched(&mod_issues) {
            return mod_issues;
        }

        if let Some(found) = jar_mod_id(services, &jar.hash).await {
            attach_jar(
                &mut mod_issues,
                &InstalledJar {
                    id: Some(found.id),
                    version: found.version.or_else(|| jar.version.clone()),
                    ..jar.clone()
                },
            );
        }
    }

    for jar in jars.iter().filter(|jar| !jar.enabled) {
        if !has_unmatched_missing(&mod_issues) {
            break;
        }

        for found in jar_bundled_mod_ids(services, &jar.hash).await {
            attach_bundled(
                &mut mod_issues,
                jar,
                &InstalledJar {
                    hash: jar.hash.clone(),
                    enabled: jar.enabled,
                    name: None,
                    id: Some(found.id),
                    version: found.version,
                },
            );
        }
    }

    mod_issues
}

#[tracing::instrument(skip(state), level = "debug")]
pub async fn repair_cluster(state: &Arc<LauncherState>, cluster_id: i64) {
    match crate::verify::verify_cluster_files(state, cluster_id).await {
        Ok(report) => {
            state
                .services
                .events
                .notify("Repair complete")
                .body(report.summary())
                .send();
        }
        Err(err) => {
            tracing::error!(cluster_id, "post-crash repair failed: {err:#}");
            state
                .services
                .events
                .notify("Repair failed")
                .body(err.to_string())
                .error()
                .send();
        }
    }
}

fn base_command(profile: &GameSettingsProfile, java_path: &str) -> (Command, Option<String>) {
    let Some(wrapper) = profile
        .hook_wrapper
        .as_deref()
        .map(str::trim)
        .filter(|hook| !hook.is_empty())
    else {
        return (Command::new(java_path), None);
    };

    let mut split = wrapper.split_whitespace();
    let Some(program) = split.next() else {
        return (Command::new(java_path), None);
    };

    let mut command = Command::new(program);
    command.args(split);
    command.arg(java_path);
    (command, Some(program.to_string()))
}

fn command_line(command: &std::process::Command, main_class: &str) -> String {
    #[cfg(not(windows))]
    const CONTINUATION: &str = " \\\n  ";
    #[cfg(windows)]
    const CONTINUATION: &str = " `\n  ";

    let mut out = String::new();
    if let Some(dir) = command.get_current_dir() {
        let _ = writeln!(out, "cd {}", shell_quote(&dir.to_string_lossy()));
    }

    for (key, value) in command.get_envs() {
        let (key, Some(value)) = (key.to_string_lossy(), value) else {
            continue;
        };
        let value = shell_quote(&value.to_string_lossy());
        #[cfg(not(windows))]
        let _ = write!(out, "{key}={value} ");
        #[cfg(windows)]
        let _ = writeln!(out, "$env:{key} = {value}");
    }

    #[cfg(windows)]
    {
        out += "& ";
    }
    out += &shell_quote(&command.get_program().to_string_lossy());

    let mut secret_next = false;
    for arg in command.get_args() {
        let raw = arg.to_string_lossy();
        let arg = if std::mem::replace(
            &mut secret_next,
            oneclient_cluster::logs::is_secret_flag(&raw),
        ) {
            std::borrow::Cow::Borrowed("[censored]")
        } else {
            oneclient_cluster::logs::censor(&raw)
        };
        out += if arg.starts_with('-') || arg == main_class {
            CONTINUATION
        } else {
            " "
        };
        out += &shell_quote(&arg);
    }

    out
}

#[cfg(not(windows))]
fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-./=:,+@%".contains(&b));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(windows)]
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "''"))
}

fn apply_env(command: &mut Command, profile: &GameSettingsProfile) {
    command.env_remove("_JAVA_OPTIONS");
    oneclient_common::process::strip_appimage_env(command.as_std_mut());
    #[cfg(all(unix, not(target_os = "macos")))]
    command.env("LC_ALL", "C.UTF-8");

    if let Some(env) = &profile.launch_env {
        for pair in env.split_whitespace() {
            if let Some((key, value)) = pair.split_once('=') {
                command.env(key, value);
            }
        }
    }
}

#[tracing::instrument(skip(cwd), fields(hook), level = "debug")]
async fn run_hook(hook: Option<&str>, cwd: &Path) -> Option<String> {
    let hook = hook.map(str::trim).filter(|h| !h.is_empty())?;

    #[cfg(windows)]
    let mut command = {
        let mut c = Command::new("cmd");
        c.args(["/C", hook]);
        c
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut c = Command::new("sh");
        c.args(["-c", hook]);
        c
    };

    command.current_dir(cwd);
    command.stderr(Stdio::piped());
    command.stdin(Stdio::null());
    oneclient_common::process::no_window(command.as_std_mut());
    oneclient_common::process::strip_appimage_env(command.as_std_mut());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!("hook '{hook}' could not start: {err}");
            return Some(format!("The command shell could not be started: {err}"));
        }
    };

    let collector = child.stderr.take().map(|mut pipe| {
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf).await;
            buf
        })
    });

    let status = match child.wait().await {
        Ok(status) => status,
        Err(err) => {
            if let Some(collector) = collector {
                collector.abort();
            }
            tracing::warn!("hook '{hook}' could not be waited on: {err}");
            return Some(format!("The command could not be waited on: {err}"));
        }
    };

    if status.success() {
        if let Some(collector) = collector {
            collector.abort();
        }
        return None;
    }

    let detail = match collector {
        Some(mut collector) => {
            match tokio::time::timeout(Duration::from_millis(200), &mut collector).await {
                Ok(Ok(buf)) => stderr_detail(&buf),
                _ => {
                    collector.abort();
                    None
                }
            }
        }
        None => None,
    };

    let message = match (detail, status.code()) {
        (Some(detail), _) => detail,
        (None, Some(code)) => format!("The command exited with code {code}"),
        (None, None) => "The command was stopped before it finished".to_string(),
    };

    tracing::warn!("hook '{hook}' failed: {message}");
    Some(message)
}

fn stderr_detail(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())?;

    const MAX: usize = 300;
    if line.chars().count() <= MAX {
        return Some(line.to_string());
    }

    let mut clipped: String = line.chars().take(MAX).collect();
    clipped.push('…');
    Some(clipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sandboxed_assets_link_the_shared_files_and_keep_skins_private() {
        let shared = polyio::tempdir().await.expect("shared dir");
        let cluster = polyio::tempdir().await.expect("cluster dir");
        let (shared, cluster) = (shared.dir_path(), cluster.dir_path());
        polyio::create_dir_all(shared.join("objects/ab"))
            .await
            .unwrap();
        polyio::write(shared.join("objects/ab/abcd"), b"sound")
            .await
            .unwrap();
        polyio::create_dir_all(shared.join("indexes"))
            .await
            .unwrap();
        polyio::create_dir_all(shared.join("skins")).await.unwrap();

        let view = sandboxed_assets(cluster, shared).await.unwrap();
        // twice: a later launch reuses the links
        assert_eq!(sandboxed_assets(cluster, shared).await.unwrap(), view);

        assert_eq!(
            polyio::read(view.join("objects/ab/abcd")).await.unwrap(),
            b"sound"
        );
        assert!(view.join("indexes").is_dir());
        let skins = polyio::symlink_metadata(view.join("skins")).await.unwrap();
        assert!(skins.is_dir() && !skins.file_type().is_symlink());
        polyio::write(view.join("skins/new.png"), b"png")
            .await
            .unwrap();
        assert!(!shared.join("skins/new.png").exists());
    }

    #[test]
    fn command_line_censors_a_token_that_is_not_a_jwt() {
        let mut command = std::process::Command::new("java");
        command.args([
            "net.minecraft.client.main.Main",
            "--accessToken",
            "plainopaquetoken123",
            "--version",
            "1.8.9",
        ]);

        let line = command_line(&command, "net.minecraft.client.main.Main");

        assert!(!line.contains("plainopaquetoken123"), "{line}");
        assert!(line.contains("[censored]"), "{line}");
        assert!(line.contains("1.8.9"), "{line}");
    }

    fn clean() -> Exit {
        Exit::Observed {
            code: Some(0),
            success: true,
            display: "exit code: 0".to_string(),
        }
    }

    #[test]
    fn a_clean_exit_after_running_out_of_memory_is_a_crash() {
        assert!(counts_as_crash(
            &clean(),
            Some(&CrashDiagnosis::OutOfMemory),
            false
        ));
    }

    #[test]
    fn stopping_a_game_that_ran_out_of_memory_is_a_crash() {
        assert!(counts_as_crash(
            &Exit::Killed,
            Some(&CrashDiagnosis::OutOfMemory),
            false
        ));
        assert!(!counts_as_crash(&Exit::Killed, None, false));
    }

    #[test]
    fn a_clean_exit_with_nothing_wrong_is_not_a_crash() {
        assert!(!counts_as_crash(&clean(), None, false));
        assert!(!counts_as_crash(
            &clean(),
            Some(&CrashDiagnosis::ModLinkage),
            false
        ));
    }

    #[test]
    fn a_failing_exit_code_is_always_a_crash() {
        let failed = Exit::Observed {
            code: Some(1),
            success: false,
            display: "exit code: 1".to_string(),
        };
        assert!(counts_as_crash(&failed, None, false));
    }

    #[test]
    fn a_load_failure_counts_on_a_clean_exit_however_long_loading_took() {
        let load_failure = CrashDiagnosis::ModLoadFailure {
            problems: Vec::new(),
        };
        assert!(counts_as_crash(&clean(), Some(&load_failure), false));
    }

    #[test]
    fn an_unobserved_exit_counts_when_the_game_wrote_a_crash_report() {
        assert!(counts_as_crash(&Exit::Inferred, None, true));
        assert!(!counts_as_crash(&Exit::Inferred, None, false));
    }
}

#[cfg(test)]
mod jvm_arg_tests {
    use super::{jvm_args_with, release_lists, sandboxed_natives};

    #[test]
    fn sandboxed_games_unpack_natives_into_their_own_folder() {
        let root = std::env::temp_dir().join(format!("oneclient-natives-{}", uuid::Uuid::new_v4()));
        let shared = root.join("metadata").join("natives").join("26.3");
        let legacy = root.join("metadata").join("natives").join("1.8.9");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("lwjgl64.dll"), b"").unwrap();
        let private = root.join("instance").join(".oneclient").join("natives");

        let mut args = vec![
            format!("-Djava.library.path={}/java", shared.display()),
            format!(
                "-Dorg.lwjgl.system.SharedLibraryExtractPath={}/lwjgl",
                shared.display()
            ),
            "-Djna.tmpdir=C:/elsewhere".to_string(),
            "-Xmx2G".to_string(),
        ];
        sandboxed_natives(&mut args, &shared, &private);
        assert_eq!(
            args[0],
            format!("-Djava.library.path={}", private.join("java").display())
        );
        assert_eq!(
            args[1],
            format!(
                "-Dorg.lwjgl.system.SharedLibraryExtractPath={}",
                private.join("lwjgl").display()
            )
        );
        assert_eq!(args[2], "-Djna.tmpdir=C:/elsewhere");
        assert_eq!(args[3], "-Xmx2G");

        // natives the launcher unpacked stay put
        let mut old = vec![format!("-Djava.library.path={}", legacy.display())];
        sandboxed_natives(&mut old, &legacy, &private);
        assert_eq!(old[0], format!("-Djava.library.path={}", legacy.display()));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_vector_module_is_only_named_when_the_runtime_ships_it() {
        let temurin = "JAVA_VERSION=\"25\"
MODULES=\"java.base jdk.incubator.vector jdk.jfr\"
";
        let jbr = "JAVA_VERSION=\"25.0.4\"
MODULES=\"java.base java.desktop jdk.jfr\"
";
        assert!(release_lists(temurin, "jdk.incubator.vector"));
        assert!(!release_lists(jbr, "jdk.incubator.vector"));
        assert!(!release_lists("", "jdk.incubator.vector"));
    }

    #[test]
    fn the_extra_argument_lands_after_the_profile() {
        assert_eq!(jvm_args_with(Some("-Xss2m"), Some("-Da=1")), "-Xss2m -Da=1");
        assert_eq!(jvm_args_with(None, Some("-Da=1")), "-Da=1");
        assert_eq!(jvm_args_with(Some("-Xss2m"), None), "-Xss2m");
        assert_eq!(jvm_args_with(None, None), "");
    }
}

/// Some runtimes leave the incubator modules out (JetBrains Runtime, jlinked
/// JREs), so this reads the module list from the runtime's `release` file.
/// Without one it answers no: the flags that need a module are optional
fn runtime_has_module(java_path: &str, module: &str) -> bool {
    let Some(home) = Path::new(java_path).parent().and_then(Path::parent) else {
        return false;
    };
    std::fs::read_to_string(home.join("release"))
        .is_ok_and(|release| release_lists(&release, module))
}

fn release_lists(release: &str, module: &str) -> bool {
    release
        .lines()
        .filter_map(|line| line.strip_prefix("MODULES="))
        .any(|modules| {
            modules
                .trim_matches('"')
                .split_whitespace()
                .any(|m| m == module)
        })
}

/// The sandbox and the broker for one launch
struct ProtectedLaunch {
    sandbox: oneclient_sandbox::Prepared,
    broker: Option<(
        oneclient_broker::LaunchDescriptor,
        oneclient_broker::RunningBroker,
    )>,
    /// The agent jar, when the game gets one
    agent: Option<PathBuf>,
    /// Rich presence for sandboxed games, which can't reach Discord
    discord: Option<oneclient_broker::DiscordRelay>,
    game_token: String,
    home: PathBuf,
    temp: PathBuf,
}

impl ProtectedLaunch {
    fn jvm_arguments(&self) -> Vec<String> {
        let mut args = Vec::new();
        match (&self.agent, &self.broker) {
            (Some(jar), Some((_, running))) => {
                args.extend(oneclient_broker::agent::jvm_arguments(jar, running));
            }
            (Some(jar), None) => args.push(format!("-javaagent:{}", jar.display())),
            (None, _) => {}
        }
        if self.sandbox.is_sandboxed() {
            let temp = self.temp.display();
            args.extend([
                "-Doneclient.sandboxed=true".to_string(),
                format!("-Djava.io.tmpdir={temp}"),
                format!("-Djna.tmpdir={temp}"),
                format!("-Dorg.lwjgl.system.SharedLibraryExtractPath={temp}"),
                format!("-Duser.home={}", self.home.display()),
                // hsperfdata would otherwise go to the real temp folder
                "-XX:-UsePerfData".to_string(),
            ]);
        }
        if let Some(property) = self.discord.as_ref().and_then(|r| r.jvm_property()) {
            args.push(property);
        }
        args
    }

    fn apply_env(&self, command: &mut Command) {
        if let Some((descriptor, _)) = &self.broker {
            command.env(oneclient_broker::KEY_ENV, &descriptor.key);
        }
        if self.sandbox.is_sandboxed() {
            let roaming = self.home.join("AppData").join("Roaming");
            let local = self.home.join("AppData").join("Local");
            command
                .env("HOME", &self.home)
                .env("USERPROFILE", &self.home)
                .env("APPDATA", roaming)
                .env("LOCALAPPDATA", local)
                .env("TMP", &self.temp)
                .env("TEMP", &self.temp)
                .env("TMPDIR", &self.temp)
                .env("XDG_CONFIG_HOME", self.home.join(".config"))
                .env("XDG_DATA_HOME", self.home.join(".local").join("share"))
                .env("XDG_CACHE_HOME", self.home.join(".cache"));
            // NVIDIA's driver keeps compiled shaders under the real
            // LocalAppData, which the sandbox can't write, so every launch
            // compiled them all again; it only uses a folder that exists
            if std::env::var_os("__GL_SHADER_DISK_CACHE_PATH").is_none() {
                let shaders = self.home.join(".cache").join("nvidia");
                if std::fs::create_dir_all(&shaders).is_ok() {
                    command.env("__GL_SHADER_DISK_CACHE_PATH", shaders);
                }
            }
            // Discord libraries look for the socket in TMPDIR on macOS, and
            // the instance's temp path is too long for a socket
            #[cfg(target_os = "macos")]
            if let Some(dir) = self.discord.as_ref().and_then(|r| r.path().parent()) {
                command.env("TMPDIR", dir);
            }
        }
    }

    /// The broker must outlive this function, and the launcher if need be
    fn keep(self, state: &Arc<LauncherState>, cluster_id: i64) {
        state
            .security
            .set_protection(cluster_id, self.sandbox.protection.clone());
        if let Some((_, running)) = self.broker {
            state.security.keep_broker(cluster_id, running);
        }
        if let Some(relay) = self.discord {
            state.security.keep_discord_relay(cluster_id, relay);
        }
    }
}

/// The `-D` properties naming folders the game unpacks native libraries into
const NATIVES_PROPERTIES: [&str; 4] = [
    "-Djava.library.path=",
    "-Djna.tmpdir=",
    "-Dorg.lwjgl.system.SharedLibraryExtractPath=",
    "-Dio.netty.native.workdir=",
];

/// Since 26.1 the game unpacks its own native libraries into folders under
/// the shared natives folder, which the sandbox can only read. It has to stay
/// that way: an instance that could write there could plant a DLL every other
/// instance loads. Sandboxed games unpack into their own folder instead.
/// Natives the launcher unpacked itself (older versions) stay where they are
fn sandboxed_natives(args: &mut [String], shared: &Path, private: &Path) {
    for arg in args.iter_mut() {
        let Some(property) = NATIVES_PROPERTIES.iter().find(|p| arg.starts_with(**p)) else {
            continue;
        };
        let value = PathBuf::from(&arg[property.len()..]);
        let Ok(rest) = value.strip_prefix(shared) else {
            continue;
        };
        let unpacked_by_launcher = std::fs::read_dir(&value).is_ok_and(|mut d| d.next().is_some());
        if *property == "-Djava.library.path=" && unpacked_by_launcher {
            continue;
        }
        *arg = format!("{property}{}", private.join(rest).display());
    }
}

/// Starts the Discord relay in a short private directory: socket paths are
/// limited to about 100 bytes. Linux shows it inside the sandbox at
/// `$XDG_RUNTIME_DIR/discord-ipc-0`; macOS points the game's `TMPDIR` at it
#[cfg(unix)]
fn start_discord_relay(
    cluster_id: i64,
    host: Arc<crate::security::LauncherBrokerHost>,
) -> Option<oneclient_broker::DiscordRelay> {
    let root = if cfg!(target_os = "macos") {
        std::env::temp_dir()
    } else {
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?)
    };
    let id = uuid::Uuid::new_v4().simple().to_string();
    let dir = root.join(format!("oneclient-discord-{}", &id[..12]));
    oneclient_broker::DiscordRelay::start(cluster_id, host, dir)
        .inspect_err(|err| tracing::warn!(cluster_id, "no Discord relay: {err}"))
        .ok()
}

/// The game writes downloaded skins into `<assets>/skins`, but the shared
/// assets folder is read-only in the sandbox. Each sandboxed instance gets
/// its own assets folder instead: links to everything shared (nothing is
/// copied) plus a real `skins` folder, so instances never share a writable
/// cache
async fn sandboxed_assets(cluster_dir: &Path, shared: &Path) -> LauncherResult<PathBuf> {
    let view = cluster_dir.join(".oneclient").join("assets");
    polyio::create_dir_all(view.join("skins")).await?;
    let mut entries = polyio::read_dir(shared).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if name == "skins" || !entry.file_type().await?.is_dir() {
            continue;
        }
        let link = view.join(&name);
        if polyio::symlink_metadata(&link).await.is_ok() {
            continue;
        }
        polyio::symlink_dir(entry.path(), &link).await?;
    }
    Ok(view)
}

async fn protect_launch(
    state: &Arc<LauncherState>,
    cluster: &oneclient_cluster::Cluster,
    game_dir: &Path,
    java_path: &str,
    account: &oneclient_auth::MinecraftAccount,
) -> LauncherResult<ProtectedLaunch> {
    use crate::security::{InstanceSecurity, LauncherBrokerHost};

    let settings = InstanceSecurity::load(cluster.id).await;
    let cluster_dir = cluster.dir()?;
    let private = cluster_dir.join(".oneclient");
    let home = private.join("home");
    let temp = private.join("tmp");
    let metadata = paths::metadata_dir()?;
    let host =
        |sandboxed| Arc::new(LauncherBrokerHost::new(state, cluster, cluster_dir.clone(), sandboxed));

    // Unix: the relay socket has to exist before the sandbox is built around it
    #[cfg(unix)]
    let unix_discord = if settings.sandbox {
        start_discord_relay(cluster.id, host(true))
    } else {
        None
    };

    let sandbox = if settings.sandbox {
        let microphone = match settings.microphone {
            Some(choice) => choice,
            None => {
                crate::security::has_voice_mod(&paths::cluster_mods_dir(&cluster.folder_name)?)
                    .await
                    || crate::security::has_voice_mod(&game_dir.join("mods")).await
            }
        };
        let mut extra_read_only: Vec<PathBuf> = settings
            .grants
            .iter()
            .filter(|g| !g.write)
            .map(|g| g.path.clone())
            .collect();
        let extra_read_write = settings
            .grants
            .iter()
            .filter(|g| g.write)
            .map(|g| g.path.clone())
            .collect();
        // a custom Java outside the launcher's own folder
        let java_root = Path::new(java_path)
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        if let Some(root) = java_root.filter(|root| !root.starts_with(&metadata)) {
            extra_read_only.push(root);
        }
        let mut read_write = vec![cluster_dir.clone()];
        if !game_dir.starts_with(&cluster_dir) {
            read_write.push(game_dir.to_path_buf());
        }
        let policy = oneclient_sandbox::SandboxPolicy {
            instance_id: cluster.id,
            runtime: vec![metadata.clone()],
            read_write,
            extra_read_only,
            extra_read_write,
            home: home.clone(),
            temp: temp.clone(),
            microphone,
            localhost: settings.localhost,
            #[cfg(unix)]
            discord_socket: unix_discord.as_ref().map(|r| r.path().to_path_buf()),
            #[cfg(not(unix))]
            discord_socket: None,
        };
        oneclient_sandbox::prepare(&policy)
            .await
            .map_err(|err| GameError::Sandbox(err.to_string()))?
    } else {
        oneclient_sandbox::unsandboxed("The sandbox is turned off for this instance")
    };
    tracing::info!(cluster_id = cluster.id, protection = ?sandbox.protection, "game protection");

    #[cfg(unix)]
    let discord = unix_discord.filter(|_| sandbox.is_sandboxed());
    #[cfg(windows)]
    let discord = if sandbox.is_sandboxed() {
        oneclient_broker::DiscordRelay::start(
            cluster.id,
            host(true),
            sandbox.app_container_sid.as_deref(),
        )
        .inspect_err(|err| tracing::warn!(cluster_id = cluster.id, "no Discord relay: {err}"))
        .ok()
    } else {
        None
    };

    let broker = if account.is_microsoft() && !account.access_token.is_empty() {
        let descriptor = oneclient_broker::LaunchDescriptor::new(
            cluster.id,
            account.id,
            vec![game_dir.to_path_buf(), cluster_dir.clone()],
            sandbox.app_container_sid.clone(),
            cfg!(unix).then(|| private.join("broker")),
        );
        let host = host(sandbox.is_sandboxed());
        let running =
            oneclient_broker::start(&descriptor, host, state.services.requester.http().clone())
                .map_err(|err| GameError::Broker(err.to_string()))?;
        Some((descriptor, running))
    } else {
        None
    };

    let saved = crate::security::SavedSession {
        broker: broker.as_ref().map(|(descriptor, _)| descriptor.clone()),
        discord: discord.as_ref().map(|relay| relay.path().to_path_buf()),
        app_container_sid: sandbox.app_container_sid.clone(),
    };
    if !saved.is_empty() {
        saved
            .save(cluster.id)
            .await
            .map_err(|err| GameError::Broker(err.to_string()))?;
    }

    // the broker needs the agent, and so does a sandboxed game on its own
    // (fullscreen, Discord, paths the sandbox can't list)
    let agent = if broker.is_some() || sandbox.is_sandboxed() {
        Some(
            oneclient_broker::agent::install(&metadata.join("agent"))
                .await
                .map_err(|err| GameError::Broker(err.to_string()))?,
        )
    } else {
        None
    };

    let game_token = match &broker {
        Some((descriptor, _)) => descriptor.fake_token.clone(),
        None => account.access_token.clone(),
    };

    Ok(ProtectedLaunch {
        sandbox,
        broker,
        agent,
        discord,
        game_token,
        home,
        temp,
    })
}
