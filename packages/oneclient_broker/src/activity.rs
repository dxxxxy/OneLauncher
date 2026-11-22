use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One thing a game did with the account, for the Security activity panel
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Activity {
    pub at: DateTime<Utc>,
    pub cluster_id: i64,
    pub kind: ActivityKind,
}

impl Activity {
    pub fn now(cluster_id: i64, kind: ActivityKind) -> Self {
        Self {
            at: Utc::now(),
            cluster_id,
            kind,
        }
    }

    /// Worth interrupting the user for
    pub fn is_alarm(&self) -> bool {
        matches!(self.kind, ActivityKind::Alarm { .. })
    }
}

/// `caller` is the jar the agent found on the stack. A hostile mod can make
/// it say anything, so it is only ever shown as a hint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActivityKind {
    /// The launcher started the game; everything after it belongs to this
    /// launch
    Launched,
    Connected {
        agent_version: String,
    },
    /// Something connected to the broker without the launch key
    BadHandshake,
    Join {
        server_hash: String,
        caller: String,
    },
    JoinLimited {
        caller: String,
    },
    Denied {
        method: String,
        url: String,
        reason: String,
        caller: String,
    },
    Alarm {
        method: String,
        url: String,
        reason: String,
        caller: String,
    },
    /// An account change that went through: the user agreed in the launcher
    /// (`asked`), or their rule for it allows it without asking
    Allowed {
        method: String,
        url: String,
        /// "change your cape"
        what: String,
        caller: String,
        #[serde(default)]
        asked: bool,
    },
    /// An account change the user's rule for it refuses
    Refused {
        method: String,
        url: String,
        what: String,
        caller: String,
    },
    Opened {
        target: String,
        caller: String,
    },
    OpenRefused {
        target: String,
        caller: String,
    },
    Picked {
        path: Option<String>,
        caller: String,
    },
    /// The game switched to another of the user's accounts
    SwitchedAccount {
        to: String,
        caller: String,
    },
    /// The game moved a file inside the instance to the user's trash, or
    /// was refused (`done` false)
    Trashed {
        path: String,
        done: bool,
        caller: String,
    },
    /// A file dropped on the game, copied in (`to`) or refused
    Imported {
        from: String,
        to: Option<String>,
        caller: String,
    },
    /// The game asked Discord for more than rich presence (signing in,
    /// reading servers or messages); the relay refused
    DiscordDenied {
        command: String,
    },
    /// The game touched a file the sandbox keeps away from mods
    SensitiveAccess {
        path: String,
        caller: String,
    },
}
