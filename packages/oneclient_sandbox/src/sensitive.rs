//! Places a game has no business reading. A mod that tries is behaving like a
//! token or password stealer: the launcher never offers to grant these and
//! raises the rat alarm instead

use std::path::Path;

/// (needle, what it is). Matched case-insensitively against the path with
/// `/` separators, so one list covers every OS
const SENSITIVE: &[(&str, &str)] = &[
    // browsers
    ("/google/chrome/", "Chrome passwords and cookies"),
    ("/google/chrome beta/", "Chrome passwords and cookies"),
    ("/chromium/", "Chromium passwords and cookies"),
    ("/microsoft/edge/", "Edge passwords and cookies"),
    ("/bravesoftware/", "Brave passwords and cookies"),
    ("/opera software/", "Opera passwords and cookies"),
    ("/com.operasoftware.", "Opera passwords and cookies"),
    ("/vivaldi/", "Vivaldi passwords and cookies"),
    ("/yandex/yandexbrowser/", "Yandex Browser passwords"),
    ("/mozilla/firefox/", "Firefox passwords and cookies"),
    ("/.mozilla/firefox", "Firefox passwords and cookies"),
    ("/library/safari/", "Safari data"),
    ("/library/cookies/", "Safari cookies"),
    // chat
    ("/discord/local storage", "Discord login token"),
    ("/discordcanary/", "Discord login token"),
    ("/discordptb/", "Discord login token"),
    ("/discord/leveldb", "Discord login token"),
    ("/telegram desktop/tdata", "Telegram session"),
    ("/signal/", "Signal messages"),
    // wallets
    ("/exodus/", "Exodus wallet"),
    ("/electrum/", "Electrum wallet"),
    ("/atomic/", "Atomic wallet"),
    ("/ethereum/keystore", "Ethereum wallet"),
    ("/bitcoin/wallet", "Bitcoin wallet"),
    ("/nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask wallet"),
    // other launchers' Microsoft sessions
    ("launcher_accounts", "Minecraft Launcher accounts"),
    ("launcher_msa_credentials", "Minecraft Launcher accounts"),
    (
        "/.minecraft/essential/microsoft_accounts",
        "Essential accounts",
    ),
    ("/prismlauncher/accounts.json", "Prism Launcher accounts"),
    ("/multimc/accounts.json", "MultiMC accounts"),
    ("/polymc/accounts.json", "PolyMC accounts"),
    ("/com.modrinth.theseus/", "Modrinth App accounts"),
    (
        "/.lunarclient/settings/game/accounts.json",
        "Lunar Client accounts",
    ),
    ("/.feather/accounts", "Feather accounts"),
    ("/.badlion", "Badlion accounts"),
    ("/tlauncher/", "TLauncher accounts"),
    // OneClient itself
    ("/polyfrost/oneclient/auth", "OneClient sign-in"),
    ("/polyfrost/oneclient-dev/auth", "OneClient sign-in"),
    // keys and keychains
    ("/.ssh/", "SSH keys"),
    ("/.gnupg/", "GPG keys"),
    ("/library/keychains/", "macOS Keychain"),
    ("/.local/share/keyrings/", "GNOME Keyring"),
    ("/kwalletd/", "KDE Wallet"),
    ("/microsoft/credentials/", "Windows saved credentials"),
    ("/microsoft/protect/", "Windows encryption keys"),
    ("/.aws/credentials", "AWS keys"),
    ("/.config/gh/hosts.yml", "GitHub CLI token"),
    ("/.git-credentials", "Git credentials"),
    // game stores
    ("/steam/config/loginusers.vdf", "Steam login"),
    ("/steam/ssfn", "Steam login"),
];

/// What a sensitive path holds, or `None` for an ordinary path
pub fn sensitive_reason(path: &Path) -> Option<&'static str> {
    let normal = path.to_string_lossy().replace('\\', "/").to_lowercase();
    SENSITIVE
        .iter()
        .find(|(needle, _)| normal.contains(needle))
        .map(|(_, reason)| *reason)
}

pub fn is_sensitive_path(path: &Path) -> bool {
    sensitive_reason(path).is_some()
}

/// Lowercase, `/`-separated, without Windows' `\\?\` prefix or a trailing
/// separator, then one `/` added, so `a/b/` starts with `a/` but not `a/bc`
fn normal_dir(path: &Path) -> String {
    let normal = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let normal = normal.strip_prefix("//?/").unwrap_or(&normal);
    format!("{}/", normal.trim_end_matches('/'))
}

const USER_DATA: &str = "your user folders, which hold browser data and logins";

/// The folders every app keeps its data in: the home folder, AppData (or
/// `~/.config`, `~/Library/Application Support`)
fn user_data_dirs() -> Vec<String> {
    let Some(dirs) = directories::BaseDirs::new() else {
        return Vec::new();
    };
    [
        dirs.home_dir(),
        dirs.config_dir(),
        dirs.data_dir(),
        dirs.data_local_dir(),
    ]
    .iter()
    .map(|dir| normal_dir(dir))
    .collect()
}

/// A sensitive file directly inside `dir`, like the vanilla launcher's
/// account files in a `.minecraft`
fn holds_sensitive_file(dir: &Path) -> Option<&'static str> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .take(10_000)
        .find_map(|entry| sensitive_reason(&entry.path()))
}

/// Why a folder can't be shared with a game, if it can't: it is sensitive,
/// or holds something that is. Sharing a folder shares everything below
/// it, so `AppData`, the home folder or `AppData\Local\Google` are refused
/// as surely as Chrome's own folder
pub fn grant_refusal(path: &Path) -> Option<&'static str> {
    if let Some(reason) = sensitive_reason(path) {
        return Some(reason);
    }
    let normal = normal_dir(path);
    if user_data_dirs().iter().any(|dir| dir.starts_with(&normal)) {
        return Some(USER_DATA);
    }
    // a folder that ends where a sensitive location starts: `.../google/`
    // holds `.../google/chrome/`
    for (needle, reason) in SENSITIVE.iter().filter(|(n, _)| n.starts_with('/')) {
        let holds = needle
            .match_indices('/')
            .skip(1)
            .any(|(at, _)| normal.ends_with(&needle[..=at]));
        if holds {
            return Some(reason);
        }
    }
    holds_sensitive_file(path)
}

/// Why a folder can't be a sandboxed game's own folder, if it can't. The
/// game reads and writes everything in it, so it can't be or hold the
/// user's app data or another launcher's sign-in, as a `.minecraft` shared
/// with the vanilla launcher does
pub fn game_dir_refusal(dir: &Path) -> Option<&'static str> {
    if let Some(reason) = sensitive_reason(dir) {
        return Some(reason);
    }
    let normal = normal_dir(dir);
    if user_data_dirs()
        .iter()
        .any(|user| user.starts_with(&normal))
    {
        return Some(USER_DATA);
    }
    holds_sensitive_file(dir)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn recognises_what_rats_steal() {
        for path in [
            r"C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\me\AppData\Roaming\discord\Local Storage\leveldb\000003.log",
            "/home/me/.mozilla/firefox/abc.default/logins.json",
            "/Users/me/Library/Application Support/Google/Chrome/Default/Cookies",
            r"C:\Users\me\AppData\Roaming\.minecraft\launcher_accounts_microsoft_store.json",
            r"C:\Users\me\AppData\Roaming\PrismLauncher\accounts.json",
            r"C:\Users\me\AppData\Roaming\Polyfrost\OneClient\auth.vault",
            "/home/me/.ssh/id_ed25519",
        ] {
            assert!(is_sensitive_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn folders_holding_sensitive_places_are_refused() {
        let dirs = directories::BaseDirs::new().unwrap();
        let home = dirs.home_dir();
        for path in [
            home.to_path_buf(),
            home.parent().unwrap().to_path_buf(),
            dirs.config_dir().to_path_buf(),
            dirs.data_local_dir().to_path_buf(),
            // Windows' AppData, above Roaming and Local
            dirs.config_dir().parent().unwrap().to_path_buf(),
            PathBuf::from(r"C:\Users\me\AppData\Local\Google"),
            PathBuf::from(r"C:\Users\me\AppData\Roaming\discord\"),
            PathBuf::from(r"\\?\C:\Users\me\AppData\Roaming\Polyfrost"),
            PathBuf::from("/home/me/.config"),
            PathBuf::from("/Users/me/Library"),
        ] {
            assert!(grant_refusal(&path).is_some(), "{}", path.display());
            assert!(game_dir_refusal(home).is_some());
        }
        #[cfg(windows)]
        assert!(grant_refusal(Path::new(r"C:\")).is_some());
        for path in [
            home.join("Downloads"),
            home.join("Pictures").join("skins"),
            PathBuf::from(r"D:\Games\Replays"),
        ] {
            assert_eq!(grant_refusal(&path), None, "{}", path.display());
        }
    }

    #[test]
    fn a_game_folder_holding_launcher_accounts_is_refused() {
        let dir = std::env::temp_dir().join(format!("sensitive-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("mods")).unwrap();
        assert_eq!(game_dir_refusal(&dir), None);
        std::fs::write(dir.join("launcher_accounts_microsoft_store.json"), b"{}").unwrap();
        assert_eq!(game_dir_refusal(&dir), Some("Minecraft Launcher accounts"));
        assert!(grant_refusal(&dir).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ordinary_folders_can_be_granted() {
        for path in [
            r"C:\Users\me\Downloads\pack.zip",
            "/home/me/Pictures/skin.png",
            r"C:\Users\me\Videos\replays",
        ] {
            assert!(!is_sensitive_path(Path::new(path)), "{path}");
        }
    }
}
