use std::{str::FromStr, time::Duration};

use alloy::sol_types::SolValue;
use anyhow::Context;
use ethers::{
    abi::ParamType,
    providers::{Http, Middleware, Provider},
    types::{H256, U256},
};

use crate::ExecutePayload;

/// Takes a given "trusted" transaction (that should be an existing "ExecuteBatches" on-chain tx),
/// and extracts the Merkle path for the first priority operation in the first batch included in that
/// transaction.
pub async fn get_priority_op_merkle_path(
    eth_rpc_url: &str,
    tx: &str,
) -> anyhow::Result<(U256, Vec<H256>, Vec<H256>)> {
    let eth_provider = Provider::<Http>::try_from(eth_rpc_url)
        .context("Failed to create provider (ETH_RPC_URL)")?
        .interval(Duration::from_millis(200));

    // Get the calldata from SAMPLE_TX, and parse it as ExecuteBatches

    let tx_hash = H256::from_str(tx).context("Failed to parse tx hash")?;
    let transaction = eth_provider
        .get_transaction(tx_hash)
        .await
        .context("Failed to fetch transaction from ETH RPC")?
        .ok_or_else(|| anyhow::anyhow!("Transaction {} not found on ETH RPC", tx))?;
    let selector = &transaction.input.0[..4];
    let calldata = &transaction.input.0[4..];

    // executeBatchesSharedBridge(address,uint256,uint256,bytes)
    let selector_4param =
        &ethers::utils::keccak256(b"executeBatchesSharedBridge(address,uint256,uint256,bytes)")
            [..4];
    // executeBatchesSharedBridge(uint256,address,uint256,uint256,bytes)
    let selector_5param = &ethers::utils::keccak256(
        b"executeBatchesSharedBridge(uint256,address,uint256,uint256,bytes)",
    )[..4];

    let (first_batch, payload) = if selector == selector_4param {
        let decoded = ethers::abi::decode(
            &[
                ParamType::Address,
                ParamType::Uint(256),
                ParamType::Uint(256),
                ParamType::Bytes,
            ],
            calldata,
        )
        .context("Failed to decode 4-param executeBatchesSharedBridge calldata")?;
        (
            decoded[1].clone().into_uint().unwrap(),
            decoded[3].clone().into_bytes().unwrap(),
        )
    } else if selector == selector_5param {
        let decoded = ethers::abi::decode(
            &[
                ParamType::Uint(256),
                ParamType::Address,
                ParamType::Uint(256),
                ParamType::Uint(256),
                ParamType::Bytes,
            ],
            calldata,
        )
        .context("Failed to decode 5-param executeBatchesSharedBridge calldata")?;
        (
            decoded[2].clone().into_uint().unwrap(),
            decoded[4].clone().into_bytes().unwrap(),
        )
    } else {
        anyhow::bail!(
            "Unknown function selector {:?} in tx {}, expected executeBatchesSharedBridge",
            selector,
            tx
        );
    };
    // First element is a version.
    assert_eq!(payload[0], 1u8);

    // The 3-field `ExecutePayload` decode still recovers `priorityOpsData` from a v31 (7-field)
    // payload — ABI head offsets are absolute, so the extra trailing fields are simply ignored.
    let execute_payload = ExecutePayload::abi_decode_sequence(&payload[1..]).unwrap();

    let priority_ops = &execute_payload.priorityOpsData[0];

    let priority_ops_left = &priority_ops.leftPath;
    let priority_ops_right = &priority_ops.rightPath;

    Ok((
        first_batch,
        priority_ops_left
            .iter()
            .map(|h| H256::from_slice(h.as_slice()))
            .collect(),
        priority_ops_right
            .iter()
            .map(|h| H256::from_slice(h.as_slice()))
            .collect(),
    ))
}
