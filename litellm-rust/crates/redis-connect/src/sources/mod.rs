mod aws;
mod azure;
mod gcp;

pub(crate) use aws::ElastiCacheIam;
pub(crate) use azure::AzureAd;
pub(crate) use gcp::GcpIam;

use crate::SharedEnvironment;

fn sdk_environment(
    environment: SharedEnvironment,
    names: &'static [&'static str],
) -> SharedEnvironment {
    std::sync::Arc::new(move |name: &str| {
        names
            .contains(&name)
            .then(|| environment.get(name))
            .flatten()
    })
}
