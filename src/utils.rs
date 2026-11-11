use std::{str::FromStr, time::Duration};

use alloy::sol_types::SolValue;
use anyhow::Context;
use ethers::{
    abi::ParamType,
    providers::{Http, Middleware, Provider},
    types::{H256, U256},
};

use crate::{ENCODING_VERSION_INTEROP, ENCODING_VERSION_V34, ExecutePayload, ExecutePayloadV34};

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

    let (priority_ops_left, priority_ops_right) = decode_first_priority_op_paths(&payload);

    Ok((first_batch, priority_ops_left, priority_ops_right))
}

/// Decodes an execute `batchData` payload (encoding-version byte followed by the ABI-encoded
/// data) and returns the left and right Merkle paths of its first priority-ops proof.
///
/// Panics on an encoding version it does not know: guessing the layout could seed the priority
/// tree from the wrong bytes.
pub(crate) fn decode_first_priority_op_paths(payload: &[u8]) -> (Vec<H256>, Vec<H256>) {
    let to_h256 = |hs: &[alloy::primitives::FixedBytes<32>]| {
        hs.iter()
            .map(|h| H256::from_slice(h.as_slice()))
            .collect::<Vec<_>>()
    };

    // The first byte is the encoding version. The payload's leading fields are decoded only; any
    // trailing v31+ fields (logs, messages, messageRoots, settlementFeePayer) are ignored, since
    // ABI head offsets are absolute.
    match payload[0] {
        // v29 - v33.
        ENCODING_VERSION_INTEROP => {
            let decoded = ExecutePayload::abi_decode_sequence(&payload[1..])
                .expect("execute payload (encoding version 1) must decode");
            let proof = &decoded.priorityOpsData[0];
            (to_h256(&proof.leftPath), to_h256(&proof.rightPath))
        }
        // v34+: `StoredBatchInfo` gained a trailing `airbenderCommitment`.
        ENCODING_VERSION_V34 => {
            let decoded = ExecutePayloadV34::abi_decode_sequence(&payload[1..])
                .expect("execute payload (encoding version 5) must decode");
            let proof = &decoded.priorityOpsData[0];
            (to_h256(&proof.leftPath), to_h256(&proof.rightPath))
        }
        other => panic!(
            "Unsupported execute payload encoding version {other}; en-2fa supports {ENCODING_VERSION_INTEROP} (v29-v33) and {ENCODING_VERSION_V34} (v34+)"
        ),
    }
}
