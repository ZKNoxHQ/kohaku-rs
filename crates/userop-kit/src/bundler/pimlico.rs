
use alloy::{primitives::B256, rpc::types::state::StateOverride};
use reqwest::Url;
use serde::Deserialize;
use tracing::info;
use web_time::{Duration, Instant};

use crate::{
    bundler::{Bundler, BundlerError, rpc_client::RpcClient},
    signable_user_operation::SignableUserOperation,
    signed_user_operation::SignedUserOperation,
    user_operation::{UserOperationGasEstimate, UserOperationHash, UserOperationReceipt},
};

/// A bundler provider for Pimlico.
pub struct PimlicoBundler {
    client: RpcClient,
    wait_interval: Duration,
    timeout: Duration,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PimlicoUserOperationGasEstimate {
    #[serde(with = "alloy::serde::quantity")]
    pub call_gas_limit: u128,
    #[serde(with = "alloy::serde::quantity")]
    pub verification_gas_limit: u128,
    #[serde(with = "alloy::serde::quantity")]
    pub pre_verification_gas: u128,
    #[serde(default, with = "alloy::serde::quantity::opt")]
    pub paymaster_post_op_gas_limit: Option<u128>,
    #[serde(default, with = "alloy::serde::quantity::opt")]
    pub paymaster_verification_gas_limit: Option<u128>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PimlicoUserOperationGasPrice {
    pub slow: PimlicoSpeedGasEstimate,
    #[allow(dead_code)]
    pub standard: PimlicoSpeedGasEstimate,
    #[allow(dead_code)]
    pub fast: PimlicoSpeedGasEstimate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PimlicoSpeedGasEstimate {
    #[serde(with = "alloy::serde::quantity")]
    pub max_fee_per_gas: u128,
    #[serde(with = "alloy::serde::quantity")]
    pub max_priority_fee_per_gas: u128,
}

impl PimlicoBundler {
    pub fn new(bundler_url: Url) -> Self {
        Self {
            client: RpcClient::new(bundler_url),
            wait_interval: Duration::from_secs(6),
            timeout: Duration::from_secs(60),
        }
    }

    /// `client` is the transport. Callers that share a proxy or timeout pass their own.
    pub fn with_client(client: reqwest::Client, bundler_url: Url) -> Self {
        Self {
            client: RpcClient::with_client(client, bundler_url),
            wait_interval: Duration::from_secs(6),
            timeout: Duration::from_secs(60),
        }
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl Bundler for PimlicoBundler {
    async fn estimate_gas(
        &self,
        op: &SignableUserOperation,
        state_override: Option<&StateOverride>,
    ) -> Result<UserOperationGasEstimate, BundlerError> {
        info!("Requesting gas estimate from Pimlico...");

        //? The state override is an optional trailing param, so omit it rather
        //? than sending `null`.
        let params = match state_override {
            Some(state_override) => {
                serde_json::json!([&op.user_op, op.entry_point, state_override])
            }
            None => serde_json::json!([&op.user_op, op.entry_point]),
        };

        let (estimate, price): (
            PimlicoUserOperationGasEstimate,
            PimlicoUserOperationGasPrice,
        ) = futures::try_join!(
            self.client.request("eth_estimateUserOperationGas", params),
            self.client
                .request("pimlico_getUserOperationGasPrice", serde_json::json!([]))
        )
        .map_err(|e| BundlerError::Other(Box::new(e)))?;

        Ok(UserOperationGasEstimate {
            call_gas_limit: estimate.call_gas_limit,
            verification_gas_limit: estimate.verification_gas_limit,
            pre_verification_gas: estimate.pre_verification_gas,
            paymaster_post_op_gas_limit: estimate.paymaster_post_op_gas_limit,
            paymaster_verification_gas_limit: estimate.paymaster_verification_gas_limit,
            max_fee_per_gas: price.slow.max_fee_per_gas,
            max_priority_fee_per_gas: price.slow.max_priority_fee_per_gas,
        })
    }

    async fn send_user_operation(
        &self,
        op: &SignedUserOperation,
    ) -> Result<UserOperationHash, BundlerError> {
        info!("Sending user operation to Pimlico...");
        let hash: B256 = self
            .client
            .request("eth_sendUserOperation", (&op.user_op, op.entry_point))
            .await
            .map_err(|e| BundlerError::Other(Box::new(e)))?;

        Ok(UserOperationHash(hash))
    }

    async fn receipt(
        &self,
        hash: UserOperationHash,
    ) -> Result<Option<UserOperationReceipt>, BundlerError> {
        info!("Requesting user operation receipt from Pimlico...");
        let receipt: Option<UserOperationReceipt> = self
            .client
            .request("eth_getUserOperationReceipt", (hash.0,))
            .await
            .map_err(|e| BundlerError::Other(Box::new(e)))?;

        Ok(receipt)
    }

    async fn wait_for_receipt(
        &self,
        hash: UserOperationHash,
    ) -> Result<UserOperationReceipt, BundlerError> {
        info!("Waiting for user operation receipt from Pimlico...");

        let start = Instant::now();
        while start.elapsed() < self.timeout {
            if let Some(receipt) = self.receipt(hash).await? {
                return Ok(receipt);
            }

            info!("User operation not yet included, retrying...");
            sleep(self.wait_interval).await;
        }

        Err(BundlerError::Timeout)
    }
}

#[cfg(native)]
async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(wasm)]
async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await;
}
