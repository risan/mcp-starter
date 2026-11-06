//! The contract of a `GrantStore`, on the state file and on Postgres.

mod support;

use mcp_starter::store::{Store, StoreOptions};
use support::ExampleState;

#[tokio::test]
async fn the_state_file_meets_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::<ExampleState>::open(dir.path(), StoreOptions::default()).unwrap();

    support::grant_store::contract(&store).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_meets_the_contract() {
    let Some(postgres) = support::postgres::Postgres::ready().await else {
        return;
    };

    support::grant_store::contract(&postgres.store()).await;
}
