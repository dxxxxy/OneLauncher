//! What the game may do with the account
//!
//! The agent forwards every request it makes to a Mojang/Microsoft account
//! host. Each one is matched against this allowlist; only matches are sent on,
//! with the fake token swapped for the real one. Anything that would change
//! the account itself is refused and raises the rat alarm, because no game
//! feature ever needs it

use url::Url;

/// Hosts the agent routes through the broker instead of the network
pub const BROKERED_HOSTS: &[&str] = &[
    "sessionserver.mojang.com",
    "api.minecraftservices.com",
    "api.mojang.com",
    "authserver.mojang.com",
    "pc.realms.minecraft.net",
    "java.frontendlegacy.realms.minecraft-services.net",
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(Route),
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

pub fn decide(method: &str, url: &Url) -> Decision {
    if url.scheme() != "https" {
        return deny("account hosts are only reachable over HTTPS");
    }
    let Some(host) = url.host_str() else {
        return deny("no host");
    };
    let method = method.to_ascii_uppercase();
    let get = method == "GET" || method == "HEAD";
    let post = method == "POST";
    let path = url.path().trim_end_matches('/');

    use Route::{Join, Plain};
    use TokenPlacement::{Bearer, None as Public, RealmsCookie};

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
            "/publickeys" if get => Decision::Allow(Plain(Public)),
            "/minecraft/profile" if get => Decision::Allow(Plain(Bearer)),
            "/minecraft/profile/lookup/bulk/byname" if post => Decision::Allow(Plain(Public)),
            p if get && p.starts_with("/minecraft/profile/lookup/") => {
                Decision::Allow(Plain(Public))
            }
            // name, skin and cape changes, name availability probes,
            // entitlements: account management, never gameplay
            p if p.starts_with("/minecraft/profile") => {
                alarm("a mod tried to change your Minecraft profile")
            }
            p if p.starts_with("/entitlements") || p.starts_with("/productvoucher") => {
                alarm("a mod tried to read or redeem your purchases")
            }
            _ => deny("not an endpoint the game uses"),
        },
        "api.mojang.com" => match path {
            p if get && p.starts_with("/users/profiles/minecraft/") => {
                Decision::Allow(Plain(Public))
            }
            "/profiles/minecraft" if post => Decision::Allow(Plain(Public)),
            p if p.starts_with("/user") => alarm("a mod tried to reach your account settings"),
            _ => deny("not an endpoint the game uses"),
        },
        // legacy Yggdrasil: password logins and token refresh, the launcher's
        // job only
        "authserver.mojang.com" => alarm("a mod tried to sign in to or out of your account"),
        "pc.realms.minecraft.net" | "java.frontendlegacy.realms.minecraft-services.net" => {
            Decision::Allow(Plain(RealmsCookie))
        }
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

    if !contains(body, fake.as_bytes()) {
        return;
    }
    let replacement = if placement == TokenPlacement::JsonAccessToken {
        real
    } else {
        ""
    };
    *body = replace_bytes(body, fake.as_bytes(), replacement.as_bytes());
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
        assert_eq!(
            d("GET", "https://pc.realms.minecraft.net/worlds"),
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

    #[test]
    fn account_changes_raise_the_alarm() {
        for (method, url) in [
            (
                "PUT",
                "https://api.minecraftservices.com/minecraft/profile/name/Notch",
            ),
            (
                "POST",
                "https://api.minecraftservices.com/minecraft/profile/skins",
            ),
            (
                "DELETE",
                "https://api.minecraftservices.com/minecraft/profile/capes/active",
            ),
            (
                "GET",
                "https://api.minecraftservices.com/minecraft/profile/namechange",
            ),
            (
                "GET",
                "https://api.minecraftservices.com/entitlements/mcstore",
            ),
            ("POST", "https://authserver.mojang.com/authenticate"),
            ("GET", "https://api.mojang.com/user/security/location"),
        ] {
            assert!(
                matches!(d(method, url), Decision::Deny { alarm: true, .. }),
                "{method} {url}"
            );
        }
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
