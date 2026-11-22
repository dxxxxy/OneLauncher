//! What the game may do with the account
//!
//! The agent forwards every request it makes to a Mojang/Microsoft account
//! host. Each one is matched against this allowlist; only matches are sent on,
//! with the fake token swapped for the real one. Anything that would change
//! the account itself (name, skin, cape, purchases) follows what the user
//! chose for that kind of change, or asks them in the launcher: cosmetics
//! menus do this, but so do rats. What no game feature ever does, like
//! signing in with a password or joining a server as someone else, is
//! refused and raises the rat alarm

use serde::{Deserialize, Serialize};
use url::Url;

/// Hosts the agent routes through the broker instead of the network
pub const BROKERED_HOSTS: &[&str] = &[
    "sessionserver.mojang.com",
    "api.minecraftservices.com",
    "api.mojang.com",
    "authserver.mojang.com",
    "pc.realms.minecraft.net",
    "java.frontendlegacy.realms.minecraft-services.net",
    // 26.3 Realms, which added invite codes
    "java.frontend.realms.minecraft-services.net",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPlacement {
    /// Public endpoint, sent on without any credentials
    None,
    /// `Authorization: Bearer <token>`
    Bearer,
    /// JSON body field `accessToken` (session join)
    JsonAccessToken,
    /// Realms cookie `sid=token:<token>:<uuid>`
    RealmsCookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `POST /session/minecraft/join`, rate limited and logged
    Join,
    /// Anything else on the allowlist
    Plain(TokenPlacement),
}

/// What an account change does, for the question the launcher asks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    Name,
    Skin,
    Cape,
    /// Anything on a Realm beyond playing on it: worlds, invites, backups
    Realms,
    Purchases,
    Redeem,
    Settings,
}

/// What the user chose for a kind of account change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRule {
    #[default]
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountChange {
    pub kind: ChangeKind,
    /// Finishes "A mod wants to ...", e.g. "change your cape"
    pub what: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(Route),
    /// Changes the account: sent on with the token only if the user agrees
    Confirm {
        placement: TokenPlacement,
        change: AccountChange,
    },
    Deny {
        reason: &'static str,
        /// A request no game feature makes: a mod is trying to take over or
        /// change the account
        alarm: bool,
    },
}

fn deny(reason: &'static str) -> Decision {
    Decision::Deny {
        reason,
        alarm: false,
    }
}

fn alarm(reason: &'static str) -> Decision {
    Decision::Deny {
        reason,
        alarm: true,
    }
}

fn confirm(kind: ChangeKind, what: impl Into<String>) -> Decision {
    Decision::Confirm {
        placement: TokenPlacement::Bearer,
        change: AccountChange {
            kind,
            what: what.into(),
        },
    }
}

/// `/minecraft/profile/...` beyond reading it: names, skins and capes.
/// Segments are matched the way a server may read them, decoded and in any
/// case, so `NAME` or `n%61me` is still a rename. Anything else is refused:
/// a vague question about an unknown change is one a user can't answer
fn profile_change(method: &str, path: &str) -> Decision {
    let rest = &path["/minecraft/profile".len()..];
    if !rest.is_empty() && !rest.starts_with('/') {
        return deny("not an endpoint the game uses");
    }
    let decoded: Vec<String> = rest
        .split('/')
        .filter(|s| !s.is_empty())
        .map(percent_decode)
        .collect();
    let lower: Vec<String> = decoded.iter().map(|s| s.to_ascii_lowercase()).collect();
    let segments: Vec<&str> = lower.iter().map(String::as_str).collect();
    let name = || {
        decoded[1]
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(16)
            .collect::<String>()
    };
    match (method, segments.as_slice()) {
        // looking a name up changes nothing
        ("GET" | "HEAD", ["name", _, "available"]) | ("GET" | "HEAD", ["namechange"]) => {
            Decision::Allow(Route::Plain(TokenPlacement::Bearer))
        }
        (_, ["name", _]) if method != "GET" && method != "HEAD" => confirm(
            ChangeKind::Name,
            format!("change your Minecraft name to {}", name()),
        ),
        ("POST", ["skins"]) | ("PUT", ["skins", ..]) => {
            confirm(ChangeKind::Skin, "change your skin")
        }
        ("DELETE", ["skins", ..]) => confirm(ChangeKind::Skin, "reset your skin"),
        ("PUT", ["capes", "active"]) => confirm(ChangeKind::Cape, "change your cape"),
        ("DELETE", ["capes", "active"]) => confirm(ChangeKind::Cape, "hide your cape"),
        _ => deny("not an endpoint the game uses"),
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Realms: playing on a Realm, accepting invites and reading what's there
/// go through; changing a Realm (deleting or resetting worlds, inviting
/// players, restoring backups, starting trials) asks first
fn realms(method: &str, path: &str) -> Decision {
    let route = Decision::Allow(Route::Plain(TokenPlacement::RealmsCookie));
    if method == "GET" || method == "HEAD" {
        return route;
    }
    let path = path.to_ascii_lowercase();
    let player_action = match method {
        "PUT" => path.starts_with("/invites/accept/") || path.starts_with("/invites/reject/"),
        "POST" => matches!(
            path.as_str(),
            // 26.3's invite codes
            "/invites/code"
                | "/regions/ping/stat"
                | "/notifications/seen"
                | "/notifications/dismiss"
                | "/mco/tos/agree"
        ),
        _ => false,
    };
    if player_action {
        return route;
    }
    Decision::Confirm {
        placement: TokenPlacement::RealmsCookie,
        change: AccountChange {
            kind: ChangeKind::Realms,
            what: if method == "DELETE" {
                "delete something on your Realm".into()
            } else {
                "make changes to your Realm".into()
            },
        },
    }
}

/// A path a server could read differently than this policy does: encoded
/// separators or dots, or a NUL
fn ambiguous_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ["%2f", "%5c", "%2e", "%00"]
        .iter()
        .any(|encoded| lower.contains(encoded))
}

pub fn decide(method: &str, url: &Url) -> Decision {
    let Some(host) = url.host_str() else {
        return deny("no host");
    };
    // a sign-in attempt is one whichever way the host or scheme is spelled
    let bare = host.trim_end_matches('.');
    if bare == "authserver.mojang.com" {
        return alarm("a mod tried to sign in to or out of your account");
    }
    if bare != host {
        return deny("not an account host");
    }
    if url.scheme() != "https" {
        return deny("account hosts are only reachable over HTTPS");
    }
    // the real token only ever goes to the hosts' standard port
    if url.port().is_some() {
        return deny("account hosts are only reachable on their standard port");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return deny("not an endpoint the game uses");
    }
    if ambiguous_path(url.path()) {
        return deny("not an endpoint the game uses");
    }
    let method = method.to_ascii_uppercase();
    let get = method == "GET" || method == "HEAD";
    let post = method == "POST";
    let path = url.path().trim_end_matches('/');

    use Route::{Join, Plain};
    use TokenPlacement::{Bearer, None as Public};

    match host {
        "sessionserver.mojang.com" => match path {
            "/session/minecraft/join" if post => Decision::Allow(Join),
            "/session/minecraft/hasJoined" if get => Decision::Allow(Plain(Public)),
            p if get && p.starts_with("/session/minecraft/profile/") => {
                Decision::Allow(Plain(Public))
            }
            "/blockedservers" if get => Decision::Allow(Plain(Public)),
            _ => deny("not an endpoint the game uses"),
        },
        "api.minecraftservices.com" => match path {
            "/player/certificates" if post => Decision::Allow(Plain(Bearer)),
            "/player/attributes" if get || post => Decision::Allow(Plain(Bearer)),
            // 1.16 to 1.18 read multiplayer and Realms permissions here
            "/privileges" if get => Decision::Allow(Plain(Bearer)),
            "/privacy/blocklist" if get => Decision::Allow(Plain(Bearer)),
            "/player/report" if post => Decision::Allow(Plain(Bearer)),
            // 26.3's friends list: reading it, sending and answering friend
            // requests, and showing friends what the player is doing
            "/friends" if get || method == "PUT" => Decision::Allow(Plain(Bearer)),
            "/presence" if post => Decision::Allow(Plain(Bearer)),
            "/publickeys" if get => Decision::Allow(Plain(Public)),
            "/minecraft/profile" if get => Decision::Allow(Plain(Bearer)),
            "/minecraft/profile/lookup/bulk/byname" if post => Decision::Allow(Plain(Public)),
            p if get && p.starts_with("/minecraft/profile/lookup/") => {
                Decision::Allow(Plain(Public))
            }
            // name, skin and cape changes, name availability probes,
            // entitlements: account management that cosmetics menus do
            p if p.starts_with("/minecraft/profile") => profile_change(&method, p),
            p if p.starts_with("/entitlements") => confirm(
                ChangeKind::Purchases,
                "see which Minecraft products you own",
            ),
            p if p.starts_with("/productvoucher") => {
                confirm(ChangeKind::Redeem, "redeem a code on your account")
            }
            _ => deny("not an endpoint the game uses"),
        },
        "api.mojang.com" => match path {
            p if get && p.starts_with("/users/profiles/minecraft/") => {
                Decision::Allow(Plain(Public))
            }
            "/profiles/minecraft" if post => Decision::Allow(Plain(Public)),
            p if p.starts_with("/user") => {
                confirm(ChangeKind::Settings, "reach your Mojang account settings")
            }
            _ => deny("not an endpoint the game uses"),
        },
        // legacy Yggdrasil (authserver.mojang.com, password logins and token
        // refresh, the launcher's job only) raised the alarm above
        "pc.realms.minecraft.net"
        | "java.frontendlegacy.realms.minecraft-services.net"
        | "java.frontend.realms.minecraft-services.net" => realms(&method, path),
        _ => deny("not an account host"),
    }
}

/// Replaces the fake token wherever the route expects a credential, and
/// strips it from everywhere else so it never leaves the machine
pub fn substitute(
    placement: TokenPlacement,
    headers: &mut [(String, String)],
    body: &mut Vec<u8>,
    fake: &str,
    real: &str,
) {
    let wants_header = matches!(
        placement,
        TokenPlacement::Bearer | TokenPlacement::RealmsCookie
    );
    for (name, value) in headers.iter_mut() {
        if !value.contains(fake) {
            continue;
        }
        let credential_header =
            name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie");
        *value = if wants_header && credential_header {
            value.replace(fake, real)
        } else {
            value.replace(fake, "")
        };
    }

    if placement == TokenPlacement::JsonAccessToken {
        *body = join_body(body, fake, real);
        return;
    }
    if contains(body, fake.as_bytes()) {
        *body = replace_bytes(body, fake.as_bytes(), b"");
    }
}

/// The join body as it is sent on: written out again from what was parsed,
/// so the server reads exactly what [`join_names_account`] checked (no
/// duplicate keys), with the real token in `accessToken` and nowhere else
fn join_body(body: &[u8], fake: &str, real: &str) -> Vec<u8> {
    fn strip(value: &mut serde_json::Value, fake: &str) {
        match value {
            serde_json::Value::String(s) if s.contains(fake) => *s = s.replace(fake, ""),
            serde_json::Value::Array(items) => items.iter_mut().for_each(|v| strip(v, fake)),
            serde_json::Value::Object(map) => map.values_mut().for_each(|v| strip(v, fake)),
            _ => {}
        }
    }
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return replace_bytes(body, fake.as_bytes(), b"");
    };
    let wants_token = json.get("accessToken").and_then(|v| v.as_str()) == Some(fake);
    strip(&mut json, fake);
    if wants_token && let Some(map) = json.as_object_mut() {
        map.insert("accessToken".into(), real.into());
    }
    serde_json::to_vec(&json).unwrap_or_default()
}

/// The join body must name this account; anything else is someone else's
/// session the mod is trying to borrow ours for
pub fn join_names_account(body: &[u8], account_uuid: &uuid::Uuid) -> bool {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    json.get("selectedProfile")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .is_some_and(|id| id == *account_uuid)
}

/// The server id hash from a join body, for the activity log
pub fn join_server_hash(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("serverId")?
        .as_str()
        .map(str::to_string)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

pub(crate) fn replace_bytes(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(method: &str, url: &str) -> Decision {
        decide(method, &Url::parse(url).unwrap())
    }

    #[test]
    fn gameplay_endpoints_are_allowed() {
        assert_eq!(
            d(
                "POST",
                "https://sessionserver.mojang.com/session/minecraft/join"
            ),
            Decision::Allow(Route::Join)
        );
        assert_eq!(
            d(
                "POST",
                "https://api.minecraftservices.com/player/certificates"
            ),
            Decision::Allow(Route::Plain(TokenPlacement::Bearer))
        );
        assert_eq!(
            d("GET", "https://api.minecraftservices.com/privileges"),
            Decision::Allow(Route::Plain(TokenPlacement::Bearer))
        );
        assert_eq!(
            d("GET", "https://api.minecraftservices.com/privacy/blocklist"),
            Decision::Allow(Route::Plain(TokenPlacement::Bearer))
        );
        assert_eq!(
            d("GET", "https://api.minecraftservices.com/minecraft/profile"),
            Decision::Allow(Route::Plain(TokenPlacement::Bearer))
        );
        for (method, url) in [
            ("GET", "https://api.minecraftservices.com/friends"),
            ("PUT", "https://api.minecraftservices.com/friends"),
            ("POST", "https://api.minecraftservices.com/presence"),
        ] {
            assert_eq!(
                d(method, url),
                Decision::Allow(Route::Plain(TokenPlacement::Bearer)),
                "{method} {url}"
            );
        }
        assert_eq!(
            d("GET", "https://pc.realms.minecraft.net/worlds"),
            Decision::Allow(Route::Plain(TokenPlacement::RealmsCookie))
        );
        assert_eq!(
            d(
                "POST",
                "https://java.frontend.realms.minecraft-services.net/invites/code"
            ),
            Decision::Allow(Route::Plain(TokenPlacement::RealmsCookie))
        );
        assert_eq!(
            d(
                "GET",
                "https://sessionserver.mojang.com/session/minecraft/profile/abc"
            ),
            Decision::Allow(Route::Plain(TokenPlacement::None))
        );
    }

    fn change(method: &str, url: &str) -> AccountChange {
        match d(method, url) {
            Decision::Confirm {
                placement: TokenPlacement::Bearer,
                change,
            } => change,
            other => panic!("{method} {url}: {other:?}"),
        }
    }

    #[test]
    fn account_changes_ask_first() {
        let profile = "https://api.minecraftservices.com/minecraft/profile";
        let name = change("PUT", &format!("{profile}/name/Notch"));
        assert_eq!(name.kind, ChangeKind::Name);
        assert_eq!(name.what, "change your Minecraft name to Notch");
        // a name in the path can't smuggle text into the question
        assert_eq!(
            change("PUT", &format!("{profile}/name/Ev%20il%0Aclick")).what,
            "change your Minecraft name to Evilclick"
        );
        for lookup in ["name/Steve/available", "namechange"] {
            assert_eq!(
                d("GET", &format!("{profile}/{lookup}")),
                Decision::Allow(Route::Plain(TokenPlacement::Bearer))
            );
        }
        assert_eq!(
            change("POST", &format!("{profile}/skins")).kind,
            ChangeKind::Skin
        );
        assert_eq!(
            change("DELETE", &format!("{profile}/skins/active")).what,
            "reset your skin"
        );
        let cape = change("PUT", &format!("{profile}/capes/active"));
        assert_eq!(cape.what, "change your cape");
        assert_eq!(
            change("DELETE", &format!("{profile}/capes/active")).what,
            "hide your cape"
        );
        assert_eq!(
            change(
                "GET",
                "https://api.minecraftservices.com/entitlements/mcstore"
            )
            .kind,
            ChangeKind::Purchases
        );
        assert_eq!(
            change("POST", "https://api.minecraftservices.com/productvoucher/X").kind,
            ChangeKind::Redeem
        );
        assert_eq!(
            change("GET", "https://api.mojang.com/user/security/location").kind,
            ChangeKind::Settings
        );
    }

    #[test]
    fn what_no_game_does_raises_the_alarm() {
        // however the host or scheme is spelled
        for url in [
            "https://authserver.mojang.com/authenticate",
            "https://AUTHSERVER.Mojang.com/refresh",
            "https://authserver.mojang.com:8443/authenticate",
            "http://authserver.mojang.com/authenticate",
            "https://authserver.mojang.com./authenticate",
        ] {
            assert!(
                matches!(d("POST", url), Decision::Deny { alarm: true, .. }),
                "{url}"
            );
        }
    }

    #[test]
    fn renames_are_renames_however_they_are_spelled() {
        let profile = "https://api.minecraftservices.com/minecraft/profile";
        for (method, path) in [
            ("PUT", "/NAME/Stolen"),
            ("PUT", "/n%61me/Stolen"),
            ("put", "/Name/Stolen/"),
            ("POST", "/name/Stolen"),
        ] {
            let change = change(method, &format!("{profile}{path}"));
            assert_eq!(change.kind, ChangeKind::Name, "{method} {path}");
            assert_eq!(change.what, "change your Minecraft name to Stolen");
        }
        // writes the policy doesn't know are refused, not asked about vaguely
        for (method, path) in [("PUT", ""), ("PATCH", "/whatever"), ("POST", "/name/a/b")] {
            assert!(
                matches!(
                    d(method, &format!("{profile}{path}")),
                    Decision::Deny { .. }
                ),
                "{method} {path}"
            );
        }
        assert!(matches!(
            d(
                "PUT",
                "https://api.minecraftservices.com/minecraft/profilex/name/a"
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn paths_a_server_could_read_differently_are_refused() {
        for url in [
            "https://api.minecraftservices.com/minecraft/profile/name/x%2F..%2F..%2Fentitlements%2Fmcstore%3F/available",
            "https://api.minecraftservices.com/minecraft/profile/name/x%5c/available",
            "https://api.minecraftservices.com/minecraft/profile/name/%2e%2e/available",
            "https://sessionserver.mojang.com/session/minecraft/profile/a%00",
        ] {
            assert!(matches!(d("GET", url), Decision::Deny { .. }), "{url}");
        }
    }

    #[test]
    fn the_token_only_goes_to_the_standard_port() {
        assert!(matches!(
            d(
                "GET",
                "https://api.minecraftservices.com:8443/minecraft/profile"
            ),
            Decision::Deny { alarm: false, .. }
        ));
        // the default port, spelled out, is the same URL
        assert_eq!(
            d(
                "GET",
                "https://api.minecraftservices.com:443/minecraft/profile"
            ),
            Decision::Allow(Route::Plain(TokenPlacement::Bearer))
        );
        assert!(matches!(
            d(
                "GET",
                "https://me:pw@api.minecraftservices.com/minecraft/profile"
            ),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            d(
                "GET",
                "https://api.minecraftservices.com./minecraft/profile"
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn realms_can_be_played_but_changes_ask() {
        let realms = "https://pc.realms.minecraft.net";
        for (method, path) in [
            ("GET", "/worlds"),
            ("GET", "/worlds/v1/123/join/pc"),
            ("PUT", "/invites/accept/9"),
            ("PUT", "/invites/reject/9"),
            ("POST", "/regions/ping/stat"),
            ("POST", "/notifications/seen"),
        ] {
            assert_eq!(
                d(method, &format!("{realms}{path}")),
                Decision::Allow(Route::Plain(TokenPlacement::RealmsCookie)),
                "{method} {path}"
            );
        }
        for (method, path) in [
            ("DELETE", "/worlds/123"),
            ("PUT", "/worlds/123/close"),
            ("POST", "/worlds/123/backups"),
            ("POST", "/invites/123"),
            ("POST", "/trial"),
        ] {
            match d(method, &format!("{realms}{path}")) {
                Decision::Confirm {
                    placement: TokenPlacement::RealmsCookie,
                    change,
                } => assert_eq!(change.kind, ChangeKind::Realms),
                other => panic!("{method} {path}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_join_token_lands_in_access_token_only() {
        let mut body =
            br#"{"accessToken":"FAKE","selectedProfile":"me","serverId":"FAKE","x":["FAKE"]}"#
                .to_vec();
        substitute(
            TokenPlacement::JsonAccessToken,
            &mut vec![],
            &mut body,
            "FAKE",
            "REAL",
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["accessToken"], "REAL");
        assert_eq!(json["serverId"], "");
        assert_eq!(json["x"][0], "");

        // what goes out is what was checked: one selectedProfile
        let mut body =
            br#"{"accessToken":"FAKE","selectedProfile":"other","selectedProfile":"me"}"#.to_vec();
        substitute(
            TokenPlacement::JsonAccessToken,
            &mut vec![],
            &mut body,
            "FAKE",
            "REAL",
        );
        let text = String::from_utf8(body).unwrap();
        assert_eq!(text.matches("selectedProfile").count(), 1, "{text}");
        assert!(text.contains(r#""selectedProfile":"me""#), "{text}");
    }

    #[test]
    fn unknown_and_plain_http_requests_are_denied_quietly() {
        assert!(matches!(
            d("GET", "https://sessionserver.mojang.com/something"),
            Decision::Deny { alarm: false, .. }
        ));
        assert!(matches!(
            d(
                "POST",
                "http://sessionserver.mojang.com/session/minecraft/join"
            ),
            Decision::Deny { alarm: false, .. }
        ));
        assert!(matches!(
            d("GET", "https://evil.example/session/minecraft/join"),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn bearer_tokens_are_swapped_only_in_credential_headers() {
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer FAKE".to_string()),
            ("X-Leak".to_string(), "FAKE".to_string()),
        ];
        let mut body = b"{\"t\":\"FAKE\"}".to_vec();

        substitute(
            TokenPlacement::Bearer,
            &mut headers,
            &mut body,
            "FAKE",
            "REAL",
        );

        assert_eq!(headers[0].1, "Bearer REAL");
        assert_eq!(headers[1].1, "");
        assert_eq!(body, b"{\"t\":\"\"}");
    }

    #[test]
    fn join_token_is_swapped_in_the_body() {
        let mut headers = vec![];
        let mut body = br#"{"accessToken":"FAKE","selectedProfile":"x","serverId":"s"}"#.to_vec();

        substitute(
            TokenPlacement::JsonAccessToken,
            &mut headers,
            &mut body,
            "FAKE",
            "REAL",
        );

        assert_eq!(
            body,
            br#"{"accessToken":"REAL","selectedProfile":"x","serverId":"s"}"#
        );
    }

    #[test]
    fn realms_cookie_is_swapped() {
        let mut headers = vec![(
            "Cookie".to_string(),
            "sid=token:FAKE:abc;user=Steve".to_string(),
        )];
        substitute(
            TokenPlacement::RealmsCookie,
            &mut headers,
            &mut vec![],
            "FAKE",
            "REAL",
        );
        assert_eq!(headers[0].1, "sid=token:REAL:abc;user=Steve");
    }

    #[test]
    fn public_routes_never_carry_the_token() {
        let mut headers = vec![("Authorization".to_string(), "Bearer FAKE".to_string())];
        substitute(
            TokenPlacement::None,
            &mut headers,
            &mut vec![],
            "FAKE",
            "REAL",
        );
        assert_eq!(headers[0].1, "Bearer ");
    }

    #[test]
    fn joins_must_name_this_account() {
        let me = uuid::Uuid::from_u128(1);
        let body = format!(r#"{{"selectedProfile":"{}","serverId":"h"}}"#, me.simple());
        assert!(join_names_account(body.as_bytes(), &me));
        assert!(!join_names_account(
            br#"{"selectedProfile":"00000000000000000000000000000002"}"#,
            &me
        ));
        assert_eq!(join_server_hash(body.as_bytes()).as_deref(), Some("h"));
    }
}
