use std::sync::Arc;

use ruint::aliases::U256;
use thiserror::Error;

use crate::pool::Pool;

#[async_trait::async_trait]
pub trait VerifierBackend: Send + Sync {
    async fn verify(&self, pool: &Pool, root: U256) -> Result<(), VerifierError>;
}

#[derive(Clone)]
pub struct Verifier(Arc<dyn VerifierBackend>);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifierError {
    #[error(
        "invalid root {root}; pool state does not match the local tree. Delete pool-sync-*.bin and the wallet's indexer-*.redb, then sync again"
    )]
    InvalidRoot { root: U256 },
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Verifier {
    pub fn new(verifier: impl VerifierBackend + 'static) -> Self {
        Self(Arc::new(verifier))
    }

    pub async fn verify(&self, pool: &Pool, root: U256) -> Result<(), VerifierError> {
        self.0.verify(pool, root).await
    }
}

impl VerifierError {
    pub fn other<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}
