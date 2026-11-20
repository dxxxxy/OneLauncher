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

#[cfg(test)]
mod tests {
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
