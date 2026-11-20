use std::time::Duration;

use freya::query::{Query, QueryCapability, UseQuery, use_query};
use oneclient_core::LauncherError;
use oneclient_mc::{self as minecraft, PlayerProfileView};

const PROFILE_STALE: Duration = Duration::from_secs(30 * 60);
const PROFILE_CLEAN: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FetchPlayerProfileQuery;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlayerProfileQueryKeys {
    pub uuid: String,
}

impl QueryCapability for FetchPlayerProfileQuery {
    type Ok = PlayerProfileView;
    type Err = LauncherError;
    type Keys = PlayerProfileQueryKeys;

    async fn run(&self, keys: &Self::Keys) -> Result<Self::Ok, Self::Err> {
        let state = crate::launcher::state()?;
        let client = &state.services.requester;

        Ok(
            // public profile only: query keys are cached and printed, so they
            // must never carry a token
            minecraft::fetch_player_profile_view(client, &keys.uuid, None).await?,
        )
    }

    // TODO Cache
    // fn matches(&self, keys: &Self::Keys) -> bool {
    //     keys.uuid.as_deref().is_some_and(|id| !id.is_empty())
    // }
}

pub fn use_player_profile(uuid: impl Into<String>) -> UseQuery<FetchPlayerProfileQuery> {
    use_query(
        Query::new(
            PlayerProfileQueryKeys { uuid: uuid.into() },
            FetchPlayerProfileQuery,
        )
        .stale_time(PROFILE_STALE)
        .clean_time(PROFILE_CLEAN),
    )
}
