use rstest::rstest;

use super::{config, roundtrip};

#[rstest]
#[ignore = "needs a live cloud Redis; set LITELLM_REDIS_GCP_LIVE_CONFIG and run with --ignored"]
#[tokio::test]
async fn credentials_authenticate_existing_and_fresh_connections() {
    roundtrip(config("LITELLM_REDIS_GCP_LIVE_CONFIG")).await;
}
