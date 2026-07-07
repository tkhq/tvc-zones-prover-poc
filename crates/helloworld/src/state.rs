//! Shared server state.

use qos_nsm::NsmProvider;
use qos_p256::P256Pair;
use std::sync::Arc;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub(crate) ephemeral_key: Arc<P256Pair>,
    pub(crate) quorum_key: Arc<P256Pair>,
    pub(crate) nsm: Arc<dyn NsmProvider>,
    pub(crate) manifest_file: Arc<str>,
}

impl AppState {
    /// Create a new application state value.
    #[must_use]
    pub fn new(
        ephemeral_key: P256Pair,
        quorum_key: P256Pair,
        nsm: Arc<dyn NsmProvider>,
        manifest_file: &str,
    ) -> Self {
        Self {
            ephemeral_key: Arc::new(ephemeral_key),
            quorum_key: Arc::new(quorum_key),
            nsm,
            manifest_file: manifest_file.into(),
        }
    }
}
