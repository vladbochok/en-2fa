use anyhow::{Context, Result, anyhow};
use clap::Parser;
use dotenvy::dotenv;
use ethers::abi::Token;
use ethers::prelude::*;
use ethers::types::{Address, Bytes, H256, U256};
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

mod db;
use alloy::sol;
use db::{BatchDb, PostgresBatchDb};
use sqlx::{PgPool, Row};
mod merkle;

use crate::merkle::{
    L1FetchConfig, MiniMerkleTree, initialize_merkle_tree, prepare_merkle_up_to_priority_op,
};
mod utils;

abigen!(
    ExecutionMultisigValidator,
    r#"[
        function approveHash(bytes32 _hash)
        function individualApprovals(address signer, bytes32 hash) view returns (bool)
        function executionMultisigMember(address signer) view returns (bool)
        function getApprovals(bytes32 hash) view returns (uint256)
        function threshold() view returns (uint256)
        function executeBatchesSharedBridge(address _chainAddress, uint256 _processBatchFrom, uint256 _processBatchTo, bytes calldata _batchData)
        function calculateHash(address _chainAddress, uint256 _processBatchFrom, uint256 _processBatchTo, bytes calldata _batchData) view returns (bytes32)
    ]"#
);

abigen!(
    ChainContract,
    r#"[
        function getPriorityTreeStartIndex() view returns (uint256)
    ]"#
);

sol! {
    #[derive(Debug)]
    struct StoredBatchInfoSol {
        uint64 batchNumber;
        bytes32 batchHash; // For ZKsync OS batches we'll store here full state commitment
        uint64 indexRepeatedStorageChanges; // For ZKsync OS not used, always set to 0
        uint256 numberOfLayer1Txs;
        bytes32 priorityOperationsHash;
        bytes32 dependencyRootsRollingHash;
        bytes32 l2LogsTreeRoot;
        uint256 timestamp; // For ZKsync OS not used, always set to 0
        bytes32 commitment; // For ZKsync OS batches we'll store batch output hash here
    }
    #[derive(Debug)]
    struct PriorityOpsBatchInfo {
        bytes32[] leftPath;
        bytes32[] rightPath;
        bytes32[] itemHashes;
    }
    #[derive(Debug)]
    struct InteropRootSol {
        uint256 chainId;
        uint256 blockOrBatchNumber;
        // We are double overloading this. The sides of the dynamic incremental merkle tree normally contains the root, as well as the sides of the tree.
        // Second overloading: if the length is 1, we are importing a chainBatchRoot/messageRoot instead of sides.
        bytes32[] sides;
    }

    #[derive(Debug)]
    struct ExecutePayload {
        StoredBatchInfoSol[] memory executeData;
        PriorityOpsBatchInfo[] memory priorityOpsData;
        InteropRootSol[][] memory dependencyRoots;

    }

    /// v34 `StoredBatchInfo`: the v29+ layout plus a trailing `airbenderCommitment`.
    #[derive(Debug)]
    struct StoredBatchInfoV34Sol {
        uint64 batchNumber;
        bytes32 batchHash;
        uint64 indexRepeatedStorageChanges;
        uint256 numberOfLayer1Txs;
        bytes32 priorityOperationsHash;
        bytes32 dependencyRootsRollingHash;
        bytes32 l2LogsTreeRoot;
        uint256 timestamp;
        bytes32 commitment;
        bytes32 airbenderCommitment;
    }

    /// Leading fields of a v34 (encoding version 5) execute payload. The trailing v31+ fields
    /// (logs, messages, messageRoots, settlementFeePayer) are not needed and are ignored.
    #[derive(Debug)]
    struct ExecutePayloadV34 {
        StoredBatchInfoV34Sol[] memory executeData;
        PriorityOpsBatchInfo[] memory priorityOpsData;
        InteropRootSol[][] memory dependencyRoots;
    }

}

#[derive(Parser, Debug)]
#[command(
    name = "en-approvehash",
    about = "Auto-approve zkSync batch execution hashes from EN DB (tx sent on Ethereum mainnet)"
)]
struct Args {
    /// Ethereum mainnet JSON-RPC URL (for contract calls + sending tx)
    #[arg(long, env = "ETH_RPC_URL")]
    eth_rpc_url: String,

    /// Postgres connection string
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Private key hex string (0x...)
    #[arg(long, env = "PK")]
    pk: String,

    /// Poll interval seconds
    #[arg(long, env = "POLL_INTERVAL_SECS", default_value_t = 3)]
    poll_interval_secs: u64,

    /// If true, do not send transactions
    #[arg(long, env = "DRY_RUN", default_value_t = 0)]
    dry_run: u8,

    /// L1 chain address used as `_chainAddress` in executeBatchesSharedBridge calldata
    #[arg(long, env = "CHAIN_ADDRESS")]
    chain_address: String,

    /// If not provided, default to the internal protocol version from the first batch.
    #[arg(long, env = "CHAIN_PROTOCOL_VERSION")]
    chain_protocol_version: Option<u16>,

    /// Address of the ExecutionMultisigValidator contract
    #[arg(long, env = "VALIDATOR_ADDRESS")]
    validator_address: String,

    /// Settlement fee payer — the trailing `settlementFeePayer` argument of the v31+
    /// `executeBatchesSharedBridge` calldata. It is a pure off-chain eth_sender config value with no
    /// DB or RPC representation, so set it to match the operator's eth_sender `settlement_fee_payer`
    /// config (which defaults to the operator's L1 sender account). Only consumed for protocol
    /// version >= 31; defaults to the zero address when not provided.
    #[arg(long, env = "SETTLEMENT_FEE_PAYER")]
    settlement_fee_payer: Option<String>,

    /// If set, run only one batch with this L1 batch number and exit.
    #[arg(long)]
    run_one_batch: Option<u64>,

    /// First L1 block to scan for `NewPriorityRequest` events when backfilling priority-op leaves
    /// that are missing from a snapshot-recovered DB. Set near the chain's L1 deployment block to
    /// keep the one-time backfill scan fast (default 0 = scan from genesis).
    #[arg(long, env = "L1_PRIORITY_SCAN_FROM_BLOCK", default_value_t = 0)]
    l1_priority_scan_from_block: u64,

    /// Number of L1 blocks per `eth_getLogs` request during the priority-op backfill scan.
    #[arg(long, env = "L1_LOG_SCAN_CHUNK", default_value_t = 10_000)]
    l1_log_scan_chunk: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::default().add_directive(LevelFilter::INFO.into())),
        )
        .init();

    let args = Args::parse();

    // --- Ethereum mainnet provider + wallet (ALL contract calls go here) ---
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?;
    let rpc_url = url::Url::parse(&args.eth_rpc_url).context("Bad ETH_RPC_URL")?;
    let http = ethers::providers::Http::new_with_client(rpc_url, http_client);
    let eth_provider = Provider::new(http).interval(Duration::from_millis(200));

    // Get the calldata from SAMPLE_TX, and parse it as ExecuteBatches

    let chain_id = eth_provider
        .get_chainid()
        .await
        .context("Failed to fetch Ethereum chain id")?
        .as_u64();

    let wallet: LocalWallet = args
        .pk
        .parse::<LocalWallet>()
        .context("Failed to parse PK as a local wallet")?
        .with_chain_id(chain_id);

    let signer_addr = wallet.address();
    info!(%chain_id, %signer_addr, "Ethereum signer ready");

    let client = Arc::new(SignerMiddleware::new(eth_provider.clone(), wallet));
    let validator_addr = parse_address(&args.validator_address).context("Bad VALIDATOR_ADDRESS")?;
    let contract = ExecutionMultisigValidator::new(validator_addr, client.clone());

    // --- Basic contract sanity checks (on Ethereum mainnet) ---
    let is_member = contract
        .execution_multisig_member(signer_addr)
        .call()
        .await
        .context("Failed to read executionMultisigMember")?;

    if !is_member {
        warn!(
            "Signer {} is NOT an executionMultisigMember; approveHash would revert NotSigner()",
            signer_addr
        );
        // TODO: restore after testing

        //     return Err(anyhow!(
        //         "Signer {} is not an executionMultisigMember; approveHash would revert NotSigner()",
        //         signer_addr
        //     ));
    }

    let threshold = contract.threshold().call().await.unwrap_or_default();
    info!(%threshold, "Contract threshold read");

    let chain_address = parse_address(&args.chain_address)?;

    // Parsed once here; only consumed by the v31+ encoding (see `encode_for_eth_tx`).
    let settlement_fee_payer = args
        .settlement_fee_payer
        .as_deref()
        .map(parse_address)
        .transpose()
        .context("Bad SETTLEMENT_FEE_PAYER")?;

    // Fetch PRIORITY_TREE_START_INDEX from the chain contract on-chain
    let chain_contract = ChainContract::new(chain_address, Arc::new(eth_provider.clone()));
    let priority_tree_start_index = chain_contract
        .get_priority_tree_start_index()
        .call()
        .await
        .context("Failed to read getPriorityTreeStartIndex from chain contract")?
        .as_u64() as usize;
    info!(%priority_tree_start_index, "Fetched priority tree start index from chain contract");

    // Config for backfilling priority-op leaves from L1 when the EN DB lacks them
    // (e.g. a snapshot-recovered node).
    let l1_fetch_cfg = L1FetchConfig {
        eth_rpc_url: args.eth_rpc_url.clone(),
        chain_address,
        scan_from_block: args.l1_priority_scan_from_block,
        scan_chunk: args.l1_log_scan_chunk,
    };

    // --- DB (External Node Postgres) ---
    let pool = PgPool::connect(&args.database_url)
        .await
        .context("Failed to connect to Postgres (DATABASE_URL)")?;
    let db = PostgresBatchDb::new(pool.clone());

    // Running just a single batch manually (mostly for testing).
    if let Some(run_one_batch) = args.run_one_batch {
        // Even in single-batch mode, verify the consistency checker has processed this batch.
        let last_verified = db
            .get_consistency_checker_last_verified_batch()
            .await?
            .unwrap_or(0);
        if (run_one_batch as i64) > last_verified {
            return Err(anyhow!(
                "Batch {} has not been verified by the consistency checker yet (last verified: {}). \
                 Refusing to approve.",
                run_one_batch, last_verified
            ));
        }

        info!(batch=%run_one_batch, "Running single batch as requested; exiting after");
        let mut initial_mini_merkle_tree =
            initialize_merkle_tree(pool.clone(), &l1_fetch_cfg, Some(run_one_batch - 1), priority_tree_start_index)
                .await?;

        run_single_batch(
            pool.clone(),
            run_one_batch as i64,
            chain_address,
            chain_id,
            &args,
            contract.clone(),
            signer_addr,
            &mut initial_mini_merkle_tree,
            settlement_fee_payer,
        )
        .await
        .with_context(|| format!("run_single_batch for L1 batch {}", run_one_batch))?;
        return Ok(());
    }

    // Automatic looping mode.
    let mut last_seen_batch: i64 = 0;
    let mut initial_mini_merkle_tree =
        initialize_merkle_tree(pool.clone(), &l1_fetch_cfg, None, priority_tree_start_index).await?;

    info!("Initialization complete; polling for new batches every {} seconds", args.poll_interval_secs);

    loop {
        match db.fetch_next_ready_execute_call(last_seen_batch).await? {
            None => {
                sleep(Duration::from_secs(args.poll_interval_secs)).await;
                continue;
            }
            Some(ready) => {
                info!(batch=%ready.l1_batch_number, "Found batch ready for execute; building calldata");

                run_single_batch(
                    pool.clone(),
                    ready.l1_batch_number,
                    chain_address,
                    chain_id,
                    &args,
                    contract.clone(),
                    signer_addr,
                    &mut initial_mini_merkle_tree,
                    settlement_fee_payer,
                )
                .await
                .with_context(|| {
                    format!("run_single_batch for L1 batch {}", ready.l1_batch_number)
                })?;

                last_seen_batch = ready.l1_batch_number;
            }
        }

        sleep(Duration::from_secs(args.poll_interval_secs)).await;
    }
}

async fn run_single_batch(
    pool: PgPool,
    l1_batch_number: i64,
    chain_address: Address,
    chain_id: u64,
    args: &Args,
    contract: ExecutionMultisigValidator<SignerMiddleware<Provider<Http>, LocalWallet>>,
    signer_addr: Address,
    initial_mini_merkle_tree: &mut MiniMerkleTree,
    settlement_fee_payer: Option<Address>,
) -> Result<()> {
    let (from_batch, to_batch, batch_data) = build_execute_batches_data(
        pool.clone(),
        l1_batch_number as u32,
        initial_mini_merkle_tree,
        args.chain_protocol_version,
        settlement_fee_payer,
    )
    .await
    .context("Failed to build executeBatchesSharedBridge data")?;

    // Print batch data as hex for debugging.
    /*println!(
        "Batch data (len={}): 0x{}",
        batch_data.0.len(),
        hex::encode(&batch_data.0)
    );*/

    let _calldata = build_execute_shared_bridge_calldata(
        chain_address,
        from_batch.as_u64(),
        to_batch.as_u64(),
        batch_data.clone(),
    );

    // EIP-712 typed data hash matching EraMultisigValidator._hashTypedDataV4
    let approved_hash =
        compute_eip712_hash(contract.address(), chain_id, chain_address, from_batch, to_batch, &batch_data);

    // check already signed (on Ethereum mainnet)
    let already = contract
        .individual_approvals(signer_addr, approved_hash.into())
        .call()
        .await
        .context("Failed to read individualApprovals")?;

    // Compare hashes - if this execute tx was already executed.
    'verify: {
        let db = PostgresBatchDb::new(pool.clone());

        if let Ok(Some(execute_tx)) = db
            .get_execution_tx_hash_for_batch(from_batch.as_u64() as i64)
            .await
        {
            warn!(
                "BATCH {} is already executed according to DB, checking hash on Ethereum mainnet...",
                from_batch
            );
            let execute_tx_hash = H256::from_str(&execute_tx)
                .context("Failed to parse execution tx hash from DB as H256")?;

            let transaction = match contract
                .client()
                .get_transaction(execute_tx_hash)
                .await
            {
                Ok(Some(tx)) => tx,
                Ok(None) => {
                    warn!("Execution transaction {} not found on Ethereum mainnet; skipping on-chain hash verification", execute_tx_hash);
                    // Skip verification — tx may have been sent via a different RPC or L1.
                    break 'verify;
                }
                Err(e) => {
                    warn!("Failed to fetch execution transaction {} from Ethereum mainnet: {}; skipping on-chain hash verification", execute_tx_hash, e);
                    break 'verify;
                }
            };

            let onchain_calldata = transaction.input.0;

            // Decode the calldata parameters (skip 4-byte selector) and recompute EIP-712 hash
            let decoded = ethers::abi::decode(
                &[
                    ethers::abi::ParamType::Address,
                    ethers::abi::ParamType::Uint(256),
                    ethers::abi::ParamType::Uint(256),
                    ethers::abi::ParamType::Bytes,
                ],
                &onchain_calldata[4..],
            )
            .context("Failed to decode on-chain calldata")?;

            let onchain_hash = compute_eip712_hash(
                contract.address(),
                chain_id,
                decoded[0].clone().into_address().unwrap(),
                decoded[1].clone().into_uint().unwrap(),
                decoded[2].clone().into_uint().unwrap(),
                &Bytes::from(decoded[3].clone().into_bytes().unwrap()),
            );

            if onchain_hash == approved_hash {
                info!(" ALL GOOD - hashes match")
            } else {
                panic!(
                    "WARNING !!!! Hash mismatch with already executed tx {:?}: expected {:?}, got {:?}",
                    execute_tx_hash, approved_hash, onchain_hash
                );
            }
        }
    }

    if already {
        info!(batch=%l1_batch_number, hash=%approved_hash, "Already approved; skipping");
        return Ok(());
    }

    info!(
        batch=%l1_batch_number,
        chain=%chain_address,
        from=%from_batch,
        to=%to_batch,
        hash=%approved_hash,
        data_len=batch_data.0.len(),
        "Approving hash (tx on Ethereum mainnet)"
    );

    if args.dry_run == 1 {
        warn!("DRY_RUN=1; not sending tx");
        return Ok(());
    }

    // avoid temporary-lifetime issue: bind call first
    let call = contract.approve_hash(approved_hash.into());

    // Estimate the gas and add a 50% buffer, so the tx does not run out of gas if the on-chain
    // state changes between estimation and inclusion.
    let estimated_gas = call
        .estimate_gas()
        .await
        .context("Failed to estimate gas for approveHash tx")?;
    let gas_limit = estimated_gas * 3 / 2;
    debug!(%estimated_gas, %gas_limit, "Gas limit for approveHash tx (1.5x estimate)");
    let call = call.gas(gas_limit);

    let pending = call.send().await.context("Failed to send approveHash tx")?;

    let receipt = pending
        .await
        .context("Failed while awaiting receipt")?
        .ok_or_else(|| anyhow!("Tx dropped from mempool / no receipt"))?;

    info!(
        tx=%receipt.transaction_hash,
        status=?receipt.status,
        batch=%l1_batch_number,
        "approveHash mined"
    );
    Ok(())
}

fn parse_address(s: &str) -> Result<Address> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("bad hex address")?;
    if bytes.len() != 20 {
        return Err(anyhow!("address must be 20 bytes"));
    }
    Ok(Address::from_slice(&bytes))
}

/// Build calldata for executeBatchesSharedBridge(address,uint256,uint256,bytes)
fn build_execute_shared_bridge_calldata(
    chain: Address,
    from: u64,
    to: u64,
    batch_data: Bytes,
) -> Vec<u8> {
    let selector =
        &ethers::utils::keccak256(b"executeBatchesSharedBridge(address,uint256,uint256,bytes)")
            [0..4];
    let encoded_args = ethers::abi::encode(&[
        Token::Address(chain),
        Token::Uint(U256::from(from)),
        Token::Uint(U256::from(to)),
        Token::Bytes(batch_data.to_vec()),
    ]);
    [selector.to_vec(), encoded_args].concat()
}

/// Compute EIP-712 typed data hash matching EraMultisigValidator._hashTypedDataV4.
///
/// Final hash = keccak256("\x19\x01" || domainSeparator || structHash)
///
/// Domain separator uses:
///   EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
///   name = "EraMultisigValidator", version = "1", chainId = 1
///
/// Struct hash uses:
///   ExecuteBatches(address chainAddress,uint256 processBatchFrom,uint256 processBatchTo,bytes batchData)
fn compute_eip712_hash(
    verifying_contract: Address,
    chain_id: u64,
    chain: Address,
    from: U256,
    to: U256,
    data: &Bytes,
) -> H256 {
    // EIP712Domain typehash
    let eip712domain_typehash = ethers::utils::keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );

    // Domain separator
    let name_hash = ethers::utils::keccak256(b"EraMultisigValidator");
    let version_hash = ethers::utils::keccak256(b"1");
    let domain_separator = ethers::utils::keccak256(ethers::abi::encode(&[
        Token::FixedBytes(eip712domain_typehash.to_vec()),
        Token::FixedBytes(name_hash.to_vec()),
        Token::FixedBytes(version_hash.to_vec()),
        Token::Uint(U256::from(chain_id)),
        Token::Address(verifying_contract),
    ]));

    // ExecuteBatches typehash
    let execute_batches_typehash = ethers::utils::keccak256(
        b"ExecuteBatches(address chainAddress,uint256 processBatchFrom,uint256 processBatchTo,bytes batchData)",
    );

    // Struct hash: keccak256(abi.encode(typehash, chain, from, to, keccak256(data)))
    let data_hash = ethers::utils::keccak256(data.as_ref());
    let struct_hash = ethers::utils::keccak256(ethers::abi::encode(&[
        Token::FixedBytes(execute_batches_typehash.to_vec()),
        Token::Address(chain),
        Token::Uint(from),
        Token::Uint(to),
        Token::FixedBytes(data_hash.to_vec()),
    ]));

    // Final EIP-712 hash: keccak256("\x19\x01" || domainSeparator || structHash)
    let mut digest_input = Vec::with_capacity(2 + 32 + 32);
    digest_input.push(0x19);
    digest_input.push(0x01);
    digest_input.extend_from_slice(&domain_separator);
    digest_input.extend_from_slice(&struct_hash);

    H256::from(ethers::utils::keccak256(digest_input))
}

async fn build_execute_batches_data(
    pool: PgPool,
    batch_number: u32,
    initial_mini_merkle_tree: &mut MiniMerkleTree,
    chain_protocol_version: Option<u16>,
    settlement_fee_payer: Option<Address>,
) -> Result<(U256, U256, Bytes)> {
    let batch = load_l1_batch_with_metadata(&pool, batch_number)
        .await
        .context("load_l1_batch_with_metadata")?;

    let l1_batches = vec![batch.clone()];

    let internal_pv = l1_batches[0].header.protocol_version.unwrap_or(0);
    let mut dependency_roots: Vec<Vec<InteropRoot>> = Vec::with_capacity(l1_batches.len());
    if is_pre_interop_fast_blocks(internal_pv) {
        dependency_roots.push(Vec::new());
    } else {
        for b in &l1_batches {
            let roots = get_interop_roots_batch(&pool, b.header.number)
                .await
                .context("get_interop_roots_batch")?;
            dependency_roots.push(roots);
        }
    }

    let priority_ops_proof =
        build_priority_ops_proofs(&pool, &batch, initial_mini_merkle_tree).await?;

    let execute = ExecuteBatches {
        l1_batches: vec![batch],
        priority_ops_proofs: vec![priority_ops_proof],
        dependency_roots,
    };

    let internal_pv = execute.l1_batches[0].header.protocol_version.unwrap_or(0);
    let chain_pv = chain_protocol_version.unwrap_or(internal_pv);

    let tokens = execute.encode_for_eth_tx(chain_pv, settlement_fee_payer);

    let (from_batch, to_batch, batch_data) = match tokens.as_slice() {
        [Token::Uint(f), Token::Uint(t), Token::Bytes(b)] => (*f, *t, Bytes::from(b.clone())),
        _ => {
            let batch_data = ethers::abi::encode(&tokens);
            let from = execute.l1_batches[0].header.number as u64;
            let to = execute.l1_batches.last().unwrap().header.number as u64;
            (U256::from(from), U256::from(to), Bytes::from(batch_data))
        }
    };

    Ok((from_batch, to_batch, batch_data))
}

async fn add_batch_tx_to_merkle(
    pool: &PgPool,
    l1_batch: &L1BatchWithMetadata,
    mini_merkle_tree: &mut MiniMerkleTree,
) -> Result<usize> {
    let batch_number = l1_batch.header.number;

    let first_priority_op_id = get_batch_first_priority_op_id(&pool.clone(), batch_number)
        .await
        .context("get_batch_first_priority_op_id")?;
    debug!(
        "First priority op id for batch {}: {:?}",
        batch_number, first_priority_op_id
    );

    match first_priority_op_id {
        None => {
            return Ok(0);
        }
        Some(first_priority_op_id) => {
            prepare_merkle_up_to_priority_op(pool, mini_merkle_tree, first_priority_op_id).await?;

            assert_eq!(first_priority_op_id, mini_merkle_tree.next_priority_op_id());

            // This is slow (as we are re-loading all L1 tx hashes from the DB), but simpler to implement.
            let priority_op_hashes = get_l1_transactions_hashes(pool, first_priority_op_id)
                .await
                .context("get_l1_transactions_hashes")?;

            let count = l1_batch.header.l1_tx_count as usize;

            // only take as many L1 tx as the batch contains.
            for h in priority_op_hashes.iter().take(count) {
                mini_merkle_tree.push_hash(*h);
            }

            Ok(count)
        }
    }
}

async fn build_priority_ops_proofs(
    pool: &PgPool,
    l1_batch: &L1BatchWithMetadata,
    mini_merkle_tree: &mut MiniMerkleTree,
) -> Result<PriorityOpsMerkleProof> {
    let count = add_batch_tx_to_merkle(pool, l1_batch, mini_merkle_tree)
        .await
        .context("add_batch_tx_to_merkle")?;

    if count == 0 {
        // No priority ops in this batch, so the proof is empty.
        return Ok(PriorityOpsMerkleProof::default());
    }

    let batch = l1_batch;

    info!("Building proof for batch {}", batch.header.number);

    let (_root, left, right) = mini_merkle_tree.merkle_root_and_paths_for_range(..count);
    let left_path: Vec<H256> = left.into_iter().map(Option::unwrap_or_default).collect();
    let right_path: Vec<H256> = right.into_iter().map(Option::unwrap_or_default).collect();
    let hashes = mini_merkle_tree.hashes_prefix(count);

    return Ok(PriorityOpsMerkleProof {
        left_path,
        right_path,
        hashes,
    });
}

#[derive(Debug, Clone)]
struct L1BatchWithMetadata {
    header: L1BatchHeader,
    metadata: L1BatchMetadata,
}

#[derive(Debug, Clone)]
struct L1BatchHeader {
    number: u32,
    timestamp: u64,
    l1_tx_count: u16,
    priority_ops_onchain_data: Vec<H256>,
    system_logs: Vec<Vec<u8>>,
    protocol_version: Option<u16>,
}

impl L1BatchHeader {
    fn priority_ops_onchain_data_hash(&self) -> H256 {
        let mut rolling = H256::from(ethers::utils::keccak256(&[]));
        for onchain_hash in &self.priority_ops_onchain_data {
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(rolling.as_bytes());
            preimage.extend_from_slice(onchain_hash.as_bytes());
            rolling = H256::from(ethers::utils::keccak256(preimage));
        }
        rolling
    }
}

#[derive(Debug, Clone)]
struct L1BatchMetadata {
    root_hash: H256,
    rollup_last_leaf_index: u64,
    l2_l1_merkle_root: H256,
    commitment: H256,
    /// From `airbender_batch_commitments`; loaded only for protocol version >= 34.
    airbender_commitment: Option<H256>,
}

#[derive(Debug, Clone)]
struct InteropRoot {
    chain_id: u64,
    block_number: u32,
    sides: Vec<H256>,
}

impl InteropRoot {
    fn into_token(self) -> Token {
        Token::Tuple(vec![
            Token::Uint(self.chain_id.into()),
            Token::Uint(self.block_number.into()),
            Token::Array(
                self.sides
                    .iter()
                    .map(|hash| Token::FixedBytes(hash.as_bytes().to_vec()))
                    .collect(),
            ),
        ])
    }
}

#[derive(Debug, Clone, Default)]
struct PriorityOpsMerkleProof {
    left_path: Vec<H256>,
    right_path: Vec<H256>,
    hashes: Vec<H256>,
}

impl PriorityOpsMerkleProof {
    fn into_token(&self) -> Token {
        let array_into_token = |array: &[H256]| {
            Token::Array(
                array
                    .iter()
                    .map(|hash| Token::FixedBytes(hash.as_bytes().to_vec()))
                    .collect(),
            )
        };
        Token::Tuple(vec![
            array_into_token(&self.left_path),
            array_into_token(&self.right_path),
            array_into_token(&self.hashes),
        ])
    }
}

#[derive(Debug, Clone)]
struct StoredBatchInfo {
    batch_number: u64,
    batch_hash: H256,
    index_repeated_storage_changes: u64,
    number_of_layer1_txs: U256,
    priority_operations_hash: H256,
    dependency_roots_rolling_hash: H256,
    l2_logs_tree_root: H256,
    timestamp: U256,
    commitment: H256,
    /// Only encoded for protocol version >= 34; zero for batches produced before v34.
    airbender_commitment: H256,
}

impl StoredBatchInfo {
    fn into_token_with_protocol_version(self, protocol_version: u16) -> Token {
        if is_pre_interop_fast_blocks(protocol_version) {
            Token::Tuple(vec![
                Token::Uint(self.batch_number.into()),
                Token::FixedBytes(self.batch_hash.as_bytes().to_vec()),
                Token::Uint(self.index_repeated_storage_changes.into()),
                Token::Uint(self.number_of_layer1_txs),
                Token::FixedBytes(self.priority_operations_hash.as_bytes().to_vec()),
                Token::FixedBytes(self.l2_logs_tree_root.as_bytes().to_vec()),
                Token::Uint(self.timestamp),
                Token::FixedBytes(self.commitment.as_bytes().to_vec()),
            ])
        } else {
            let mut tokens = vec![
                Token::Uint(self.batch_number.into()),
                Token::FixedBytes(self.batch_hash.as_bytes().to_vec()),
                Token::Uint(self.index_repeated_storage_changes.into()),
                Token::Uint(self.number_of_layer1_txs),
                Token::FixedBytes(self.priority_operations_hash.as_bytes().to_vec()),
                Token::FixedBytes(self.dependency_roots_rolling_hash.as_bytes().to_vec()),
                Token::FixedBytes(self.l2_logs_tree_root.as_bytes().to_vec()),
                Token::Uint(self.timestamp),
                Token::FixedBytes(self.commitment.as_bytes().to_vec()),
            ];
            if !is_pre_v34(protocol_version) {
                tokens.push(Token::FixedBytes(
                    self.airbender_commitment.as_bytes().to_vec(),
                ));
            }
            Token::Tuple(tokens)
        }
    }
}

#[derive(Debug, Clone)]
struct ExecuteBatches {
    l1_batches: Vec<L1BatchWithMetadata>,
    priority_ops_proofs: Vec<PriorityOpsMerkleProof>,
    dependency_roots: Vec<Vec<InteropRoot>>,
}

impl ExecuteBatches {
    // The encoding of `executeBatchesSharedBridge` calldata depends on the protocol version of both
    // the underlying chain and the batches being executed. This mirrors
    // `ExecuteBatches::encode_for_eth_tx` in zksync-era's `l1_contract_interface` crate.
    //
    // `settlement_fee_payer` is only consumed by the v31+ ("medium interop") encoding; pass `None`
    // for older protocol versions. When `None` is passed to the v31+ branch it defaults to the zero
    // address.
    fn encode_for_eth_tx(
        &self,
        chain_protocol_version: u16,
        settlement_fee_payer: Option<Address>,
    ) -> Vec<Token> {
        let internal_protocol_version = self.l1_batches[0].header.protocol_version.unwrap_or(0);

        // Token builders shared across the encoding variants below. `StoredBatchInfo`'s layout
        // depends on the protocol version it is encoded for.
        let stored_batch_infos = |protocol_version: u16| {
            Token::Array(
                self.l1_batches
                    .iter()
                    .map(|batch| {
                        StoredBatchInfo::from(batch)
                            .into_token_with_protocol_version(protocol_version)
                    })
                    .collect(),
            )
        };
        let priority_ops_proofs = || {
            Token::Array(
                self.priority_ops_proofs
                    .iter()
                    .map(|proof| proof.into_token())
                    .collect(),
            )
        };
        let dependency_roots = || {
            Token::Array(
                self.dependency_roots
                    .iter()
                    .map(|batch_roots| {
                        Token::Array(
                            batch_roots
                                .iter()
                                .cloned()
                                .map(InteropRoot::into_token)
                                .collect(),
                        )
                    })
                    .collect(),
            )
        };

        // Prefix the ABI-encoded payload with the encoding-version byte and wrap it in the
        // (processBatchFrom, processBatchTo, batchData) tuple expected by `executeBatchesSharedBridge`.
        let wrap = |encoding_version: u8, encoded_data: Vec<u8>| {
            let execute_data = [vec![encoding_version], encoded_data].concat();
            vec![
                Token::Uint(self.l1_batches[0].header.number.into()),
                Token::Uint(self.l1_batches.last().unwrap().header.number.into()),
                Token::Bytes(execute_data),
            ]
        };

        let tokens = if is_pre_gateway(internal_protocol_version)
            && is_pre_gateway(chain_protocol_version)
        {
            vec![stored_batch_infos(internal_protocol_version)]
        } else if is_pre_interop_fast_blocks(internal_protocol_version)
            && is_pre_interop_fast_blocks(chain_protocol_version)
        {
            wrap(
                get_encoding_version(internal_protocol_version),
                ethers::abi::encode(&[
                    stored_batch_infos(internal_protocol_version),
                    priority_ops_proofs(),
                ]),
            )
        } else if is_pre_medium_interop(internal_protocol_version)
            && is_pre_medium_interop(chain_protocol_version)
        {
            // v29 / v30 interop: executeData, priorityOpsData, dependencyRoots.
            wrap(
                get_encoding_version(internal_protocol_version),
                ethers::abi::encode(&[
                    stored_batch_infos(internal_protocol_version),
                    priority_ops_proofs(),
                    dependency_roots(),
                ]),
            )
        } else {
            // v31+ ("medium interop"): the calldata gained per-batch L2->L1 `logs`, `messages` and
            // `messageRoots`, plus a trailing `settlementFeePayer` address.
            //
            // Those three per-batch arrays are only populated when the chain settles on the Gateway;
            // on the EN's L1 (non-gateway) execute path — which is the only path this 2FA tool
            // approves, since `executeBatchesSharedBridge` is called on the L1 ExecutionMultisigValidator
            // — they are left empty and only `settlementFeePayer` carries data.
            //
            // Defaults to the zero address when not configured (see SETTLEMENT_FEE_PAYER).
            //
            // As in zksync-era (since v34), this branch takes the encoding version and the
            // `StoredBatchInfo` layout from the *chain* protocol version: a v34 chain expects
            // version 5 and the trailing `airbenderCommitment` even for batches produced before
            // the upgrade (their commitment is zero).
            let settlement_fee_payer = settlement_fee_payer.unwrap_or_default();
            wrap(
                get_encoding_version(chain_protocol_version),
                ethers::abi::encode(&[
                    stored_batch_infos(chain_protocol_version),
                    priority_ops_proofs(),
                    dependency_roots(),
                    Token::Array(vec![]), // logs (empty for L1 settlement)
                    Token::Array(vec![]), // messages (empty for L1 settlement)
                    Token::Array(vec![]), // messageRoots (empty for L1 settlement)
                    Token::Address(settlement_fee_payer),
                ]),
            )
        };

        tokens
    }
}

impl From<&L1BatchWithMetadata> for StoredBatchInfo {
    fn from(x: &L1BatchWithMetadata) -> Self {
        let pv = x.header.protocol_version.unwrap_or(0);
        let dependency_roots_rolling_hash = if is_pre_interop_fast_blocks(pv) {
            H256::zero()
        } else {
            extract_dependency_roots_rolling_hash(&x.header.system_logs).unwrap_or_else(H256::zero)
        };
        Self {
            batch_number: x.header.number as u64,
            batch_hash: x.metadata.root_hash,
            index_repeated_storage_changes: x.metadata.rollup_last_leaf_index,
            number_of_layer1_txs: x.header.l1_tx_count.into(),
            priority_operations_hash: x.header.priority_ops_onchain_data_hash(),
            dependency_roots_rolling_hash,
            l2_logs_tree_root: x.metadata.l2_l1_merkle_root,
            timestamp: x.header.timestamp.into(),
            commitment: x.metadata.commitment,
            // `load_l1_batch_with_metadata` errors out if a v34+ batch has no Airbender commitment.
            airbender_commitment: if is_pre_v34(pv) {
                H256::zero()
            } else {
                x.metadata
                    .airbender_commitment
                    .expect("v34+ batch loaded without an Airbender commitment")
            },
        }
    }
}

/// Execute payload encoding version before v29 (interop).
const ENCODING_VERSION_PRE_INTEROP: u8 = 0;
/// Execute payload encoding version for v29 - v33.
const ENCODING_VERSION_INTEROP: u8 = 1;
/// Execute payload encoding version from v34 on (`EncodingVersion::MultiProof` in zksync-era).
const ENCODING_VERSION_V34: u8 = 5;

/// Mirrors `get_encoding_version` in zksync-era's `l1_contract_interface` crate.
fn get_encoding_version(protocol_version: u16) -> u8 {
    if !is_pre_v34(protocol_version) {
        ENCODING_VERSION_V34
    } else if is_pre_interop_fast_blocks(protocol_version) {
        ENCODING_VERSION_PRE_INTEROP
    } else {
        ENCODING_VERSION_INTEROP
    }
}

fn is_pre_gateway(protocol_version: u16) -> bool {
    protocol_version < 26
}

fn is_pre_interop_fast_blocks(protocol_version: u16) -> bool {
    protocol_version < 29
}

fn is_pre_medium_interop(protocol_version: u16) -> bool {
    protocol_version < 31
}

fn is_pre_v34(protocol_version: u16) -> bool {
    protocol_version < 34
}

const MESSAGE_ROOT_ROLLING_HASH_KEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
];

fn extract_dependency_roots_rolling_hash(system_logs: &[Vec<u8>]) -> Option<H256> {
    for raw_log in system_logs {
        if raw_log.len() != 88 {
            continue;
        }
        let key = &raw_log[24..56];
        if key == MESSAGE_ROOT_ROLLING_HASH_KEY.as_slice() {
            let value = &raw_log[56..88];
            return Some(H256::from_slice(value));
        }
    }
    None
}

async fn load_l1_batch_with_metadata(
    pool: &PgPool,
    batch_number: u32,
) -> Result<L1BatchWithMetadata> {
    let row = sqlx::query(
        r#"
        SELECT
            number,
            timestamp,
            l1_tx_count,
            priority_ops_onchain_data,
            hash,
            rollup_last_leaf_index,
            l2_l1_merkle_root,
            commitment,
            system_logs,
            protocol_version
        FROM l1_batches
        WHERE number = $1
        "#,
    )
    .bind(batch_number as i64)
    .fetch_optional(pool)
    .await
    .context("load l1_batches row")?;

    let Some(row) = row else {
        return Err(anyhow!("L1 batch {} not found in DB", batch_number));
    };

    let number: i64 = row.try_get("number")?;
    let timestamp: i64 = row.try_get("timestamp")?;
    let l1_tx_count: i32 = row.try_get("l1_tx_count")?;
    let priority_ops_onchain_data: Vec<Vec<u8>> = row.try_get("priority_ops_onchain_data")?;
    let hash: Option<Vec<u8>> = row.try_get("hash")?;
    let rollup_last_leaf_index: Option<i64> = row.try_get("rollup_last_leaf_index")?;
    let l2_l1_merkle_root: Option<Vec<u8>> = row.try_get("l2_l1_merkle_root")?;
    let commitment: Option<Vec<u8>> = row.try_get("commitment")?;
    let system_logs: Vec<Vec<u8>> = row.try_get("system_logs")?;
    let protocol_version: Option<i32> = row.try_get("protocol_version")?;

    let mut priority_ops_hashes = Vec::with_capacity(priority_ops_onchain_data.len());
    for data in priority_ops_onchain_data {
        if data.len() != 64 {
            return Err(anyhow!(
                "priority_ops_onchain_data entry has bad length {}",
                data.len()
            ));
        }
        priority_ops_hashes.push(H256::from_slice(&data[32..64]));
    }

    let header = L1BatchHeader {
        number: number as u32,
        timestamp: timestamp as u64,
        l1_tx_count: l1_tx_count as u16,
        priority_ops_onchain_data: priority_ops_hashes,
        system_logs,
        protocol_version: protocol_version.map(|v| v as u16),
    };

    // Only v34+ batches carry an Airbender commitment. Querying the table only for them keeps
    // older EN DBs (without `airbender_batch_commitments`) working.
    let airbender_commitment = if is_pre_v34(header.protocol_version.unwrap_or(0)) {
        None
    } else {
        Some(
            get_airbender_batch_commitment(pool, batch_number)
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "missing Airbender commitment for v34+ L1 batch {}",
                        batch_number
                    )
                })?,
        )
    };

    let metadata = L1BatchMetadata {
        root_hash: H256::from_slice(&hash.ok_or_else(|| anyhow!("missing batch hash"))?),
        rollup_last_leaf_index: rollup_last_leaf_index
            .ok_or_else(|| anyhow!("missing rollup_last_leaf_index"))?
            as u64,
        l2_l1_merkle_root: H256::from_slice(
            &l2_l1_merkle_root.ok_or_else(|| anyhow!("missing l2_l1_merkle_root"))?,
        ),
        commitment: H256::from_slice(&commitment.ok_or_else(|| anyhow!("missing commitment"))?),
        airbender_commitment,
    };

    Ok(L1BatchWithMetadata { header, metadata })
}

async fn get_airbender_batch_commitment(pool: &PgPool, batch_number: u32) -> Result<Option<H256>> {
    let row = sqlx::query(
        r#"
        SELECT commitment
        FROM airbender_batch_commitments
        WHERE l1_batch_number = $1
        "#,
    )
    .bind(batch_number as i64)
    .fetch_optional(pool)
    .await
    .context("load airbender_batch_commitments row")?;

    let Some(row) = row else {
        return Ok(None);
    };
    let commitment: Vec<u8> = row.try_get("commitment")?;
    if commitment.len() != 32 {
        return Err(anyhow!(
            "Airbender commitment for L1 batch {} has bad length {}",
            batch_number,
            commitment.len()
        ));
    }
    Ok(Some(H256::from_slice(&commitment)))
}

async fn get_interop_roots_batch(pool: &PgPool, batch_number: u32) -> Result<Vec<InteropRoot>> {
    let rows = sqlx::query(
        r#"
        SELECT
            interop_roots.chain_id,
            interop_roots.dependency_block_number,
            interop_roots.interop_root_sides
        FROM interop_roots
        JOIN miniblocks
            ON interop_roots.processed_block_number = miniblocks.number
        WHERE l1_batch_number = $1
        ORDER BY chain_id, processed_block_number, dependency_block_number DESC
        "#,
    )
    .bind(batch_number as i64)
    .fetch_all(pool)
    .await
    .context("get interop_roots batch")?;

    let mut roots = Vec::with_capacity(rows.len());
    for row in rows {
        let chain_id: i64 = row.try_get("chain_id")?;
        let dependency_block_number: i64 = row.try_get("dependency_block_number")?;
        let sides_raw: Vec<Vec<u8>> = row.try_get("interop_root_sides")?;
        let sides = sides_raw
            .iter()
            .map(|side| H256::from_slice(side))
            .collect::<Vec<_>>();
        roots.push(InteropRoot {
            chain_id: chain_id as u64,
            block_number: dependency_block_number as u32,
            sides,
        });
    }
    Ok(roots)
}

async fn get_l1_transactions_hashes(pool: &PgPool, start_id: usize) -> Result<Vec<H256>> {
    let rows = sqlx::query(
        r#"
        SELECT hash
        FROM transactions
        WHERE priority_op_id >= $1
            AND is_priority = TRUE
        ORDER BY priority_op_id
        "#,
    )
    .bind(start_id as i64)
    .fetch_all(pool)
    .await
    .context("get_l1_transactions_hashes query")?;

    Ok(rows
        .into_iter()
        .map(|row| H256::from_slice(row.get::<Vec<u8>, _>("hash").as_slice()))
        .collect())
}

async fn get_batch_first_priority_op_id(pool: &PgPool, batch_number: u32) -> Result<Option<usize>> {
    let row = sqlx::query(
        r#"
        SELECT
            MIN(miniblocks.number) AS min_block,
            MAX(miniblocks.number) AS max_block
        FROM miniblocks
        WHERE l1_batch_number = $1
        "#,
    )
    .bind(batch_number as i64)
    .fetch_one(pool)
    .await
    .context("get l2 block range for l1 batch")?;

    let min_block: Option<i64> = row.try_get("min_block")?;
    let max_block: Option<i64> = row.try_get("max_block")?;

    let (Some(min_block), Some(max_block)) = (min_block, max_block) else {
        return Ok(None);
    };

    let row = sqlx::query(
        r#"
        SELECT MIN(priority_op_id) AS id
        FROM transactions
        WHERE miniblock_number BETWEEN $1 AND $2
            AND is_priority = TRUE
        "#,
    )
    .bind(min_block)
    .bind(max_block)
    .fetch_one(pool)
    .await
    .context("get_batch_first_priority_op_id")?;

    let id: Option<i64> = row.try_get("id")?;
    Ok(id.map(|v| v as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolValue;

    /// Builds the ABI-encoded `priorityOpsData` token for a single proof with the given paths,
    /// mirroring `PriorityOpsMerkleProof::into_token`.
    fn priority_ops_token(left: &[H256], right: &[H256], hashes: &[H256]) -> Token {
        let arr = |hs: &[H256]| {
            Token::Array(
                hs.iter()
                    .map(|h| Token::FixedBytes(h.as_bytes().to_vec()))
                    .collect(),
            )
        };
        Token::Array(vec![Token::Tuple(vec![arr(left), arr(right), arr(hashes)])])
    }

    /// A batch with one priority op, filled with distinct non-zero values.
    fn test_batch(number: u32, protocol_version: u16) -> L1BatchWithMetadata {
        L1BatchWithMetadata {
            header: L1BatchHeader {
                number,
                timestamp: 1_700_000_000,
                l1_tx_count: 1,
                priority_ops_onchain_data: vec![H256::from_low_u64_be(0x11)],
                system_logs: vec![],
                protocol_version: Some(protocol_version),
            },
            metadata: L1BatchMetadata {
                root_hash: H256::from_low_u64_be(0x22),
                rollup_last_leaf_index: 77,
                l2_l1_merkle_root: H256::from_low_u64_be(0x33),
                commitment: H256::from_low_u64_be(0x44),
                airbender_commitment: (!is_pre_v34(protocol_version))
                    .then(|| H256::from_low_u64_be(0x55)),
            },
        }
    }

    fn test_execute(batch: L1BatchWithMetadata) -> ExecuteBatches {
        ExecuteBatches {
            l1_batches: vec![batch],
            priority_ops_proofs: vec![PriorityOpsMerkleProof {
                left_path: vec![H256::from_low_u64_be(0xaa)],
                right_path: vec![H256::from_low_u64_be(0xbb)],
                hashes: vec![H256::from_low_u64_be(0xcc)],
            }],
            dependency_roots: vec![vec![]],
        }
    }

    /// Returns `batchData` from `encode_for_eth_tx`'s (from, to, batchData) tokens.
    fn batch_data(tokens: Vec<Token>) -> Vec<u8> {
        match tokens.as_slice() {
            [Token::Uint(_), Token::Uint(_), Token::Bytes(b)] => b.clone(),
            other => panic!("unexpected tokens: {other:?}"),
        }
    }

    /// The bootstrap path (`utils::get_priority_op_merkle_path`) decodes the `batchData` payload of
    /// a *previous* on-chain execute tx to recover the priority-op Merkle paths. This guards that
    /// the decoder recovers `priorityOpsData` from every layout seen on-chain: v29/v30 (3 fields),
    /// v31-v33 (7 fields), and v34 (encoding version 5, `StoredBatchInfo` + `airbenderCommitment`).
    #[test]
    fn test_decode_priority_ops_from_payloads() {
        let left = vec![H256::from_low_u64_be(0xaa)];
        let right = vec![H256::from_low_u64_be(0xbb)];
        let hashes = vec![H256::from_low_u64_be(0xcc)];

        let check = |payload: &[u8]| {
            let (got_left, got_right) = utils::decode_first_priority_op_paths(payload);
            assert_eq!(got_left, left);
            assert_eq!(got_right, right);
        };

        // v29 / v30 layout: executeData, priorityOpsData, dependencyRoots.
        let mut old_payload = vec![ENCODING_VERSION_INTEROP];
        old_payload.extend(ethers::abi::encode(&[
            Token::Array(vec![]),
            priority_ops_token(&left, &right, &hashes),
            Token::Array(vec![]),
        ]));
        check(&old_payload);

        // v31 layout: + logs, messages, messageRoots, settlementFeePayer.
        let mut v31_payload = vec![ENCODING_VERSION_INTEROP];
        v31_payload.extend(ethers::abi::encode(&[
            Token::Array(vec![]),
            priority_ops_token(&left, &right, &hashes),
            Token::Array(vec![]),
            Token::Array(vec![]),
            Token::Array(vec![]),
            Token::Array(vec![]),
            Token::Address(Address::from_low_u64_be(0x1234)),
        ]));
        check(&v31_payload);

        // v31-v33 and v34 payloads as `encode_for_eth_tx` builds them, with a non-empty
        // `executeData` so the `StoredBatchInfo` layout matters.
        for pv in [31, 33, 34] {
            let payload = batch_data(
                test_execute(test_batch(10, pv)).encode_for_eth_tx(pv, Some(Address::zero())),
            );
            check(&payload);
        }
    }

    /// Real v34 `batchData` from Sepolia execute tx
    /// 0xa5028b14debb4c42c3381c90c332b803e4d05d6d00f5f7502ab0838b52f4b587 (era stage, batch 108790),
    /// the kind of payload that made the v1-only bootstrap panic.
    #[test]
    fn test_decode_priority_ops_from_sepolia_v34_tx() {
        let hex_data = include_str!("testdata/sepolia_v34_execute_batch_data.hex").trim();
        let payload = hex::decode(hex_data.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(payload[0], ENCODING_VERSION_V34);

        let decoded = ExecutePayloadV34::abi_decode_sequence(&payload[1..]).unwrap();
        let info = &decoded.executeData[0];
        assert_eq!(info.batchNumber, 108790);
        assert_eq!(
            info.airbenderCommitment.to_string(),
            "0xcc998dfb867ed45a6f0107cff16abdb6ab1f4aa7291270f3b8214cc887e7e633"
        );

        let (left, right) = utils::decode_first_priority_op_paths(&payload);
        assert_eq!(left.len(), 14);
        assert_eq!(right.len(), 14);
        assert_eq!(
            left[2],
            H256::from_str("0x8aa1155133ce9b3642977dff3a627fbd0b8ca6d9880c91b3a43e29cf34a9e646")
                .unwrap()
        );
        assert_eq!(
            right[0],
            H256::from_str("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "Unsupported execute payload encoding version 2")]
    fn test_decode_rejects_unknown_encoding_version() {
        let mut payload = vec![2u8];
        payload.extend(ethers::abi::encode(&[
            Token::Array(vec![]),
            priority_ops_token(&[], &[], &[]),
            Token::Array(vec![]),
        ]));
        utils::decode_first_priority_op_paths(&payload);
    }

    #[test]
    fn test_get_encoding_version() {
        assert_eq!(get_encoding_version(28), 0);
        assert_eq!(get_encoding_version(29), 1);
        assert_eq!(get_encoding_version(33), 1);
        assert_eq!(get_encoding_version(34), 5);
        assert_eq!(get_encoding_version(35), 5);
    }

    /// v34 execute data: version byte 5, and each `StoredBatchInfo` carries the trailing
    /// `airbenderCommitment` (decoded here with the `IExecutor.sol` v34 struct layout).
    #[test]
    fn test_encode_execute_v34() {
        let fee_payer = Address::from_low_u64_be(0x1234);
        let payload = batch_data(
            test_execute(test_batch(10, 34)).encode_for_eth_tx(34, Some(fee_payer)),
        );
        assert_eq!(payload[0], ENCODING_VERSION_V34);

        // Full 7-field decode: nothing is missing or left over.
        alloy::sol! {
            struct L2Log {
                uint8 l2ShardId;
                bool isService;
                uint16 txNumberInBatch;
                address sender;
                bytes32 key;
                bytes32 value;
            }
        }
        type FullV34 = (
            Vec<StoredBatchInfoV34Sol>,
            Vec<PriorityOpsBatchInfo>,
            Vec<Vec<InteropRootSol>>,
            Vec<Vec<L2Log>>,
            Vec<Vec<alloy::primitives::Bytes>>,
            Vec<alloy::primitives::FixedBytes<32>>,
            alloy::primitives::Address,
        );
        let (infos, proofs, roots, logs, messages, message_roots, payer) =
            <FullV34 as SolValue>::abi_decode_params_validate(&payload[1..])
                .expect("v34 payload must match the IExecutor.sol layout");

        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert_eq!(info.batchNumber, 10);
        assert_eq!(info.batchHash.as_slice(), H256::from_low_u64_be(0x22).as_bytes());
        assert_eq!(info.indexRepeatedStorageChanges, 77);
        assert_eq!(info.commitment.as_slice(), H256::from_low_u64_be(0x44).as_bytes());
        assert_eq!(
            info.airbenderCommitment.as_slice(),
            H256::from_low_u64_be(0x55).as_bytes()
        );
        assert_eq!(proofs.len(), 1);
        assert!(roots.len() == 1 && roots[0].is_empty());
        assert!(logs.is_empty() && messages.is_empty() && message_roots.is_empty());
        assert_eq!(payer.as_slice(), fee_payer.as_bytes());
    }

    /// A batch produced before v34 but executed on a v34 chain uses the v34 encoding with a zero
    /// Airbender commitment, as zksync-era does.
    #[test]
    fn test_encode_execute_pre_v34_batch_on_v34_chain() {
        let payload = batch_data(
            test_execute(test_batch(10, 33)).encode_for_eth_tx(34, Some(Address::zero())),
        );
        assert_eq!(payload[0], ENCODING_VERSION_V34);
        let decoded = ExecutePayloadV34::abi_decode_sequence(&payload[1..]).unwrap();
        assert_eq!(decoded.executeData[0].batchNumber, 10);
        assert!(decoded.executeData[0].airbenderCommitment.is_zero());
    }

    /// v31-v33 encoding is unchanged: version byte 1 and the 9-field `StoredBatchInfo`.
    #[test]
    fn test_encode_execute_v33_unchanged() {
        let payload = batch_data(
            test_execute(test_batch(10, 33)).encode_for_eth_tx(33, Some(Address::zero())),
        );
        assert_eq!(payload[0], ENCODING_VERSION_INTEROP);
        let decoded = ExecutePayload::abi_decode_sequence(&payload[1..]).unwrap();
        assert_eq!(decoded.executeData[0].batchNumber, 10);
        assert_eq!(
            decoded.executeData[0].commitment.as_slice(),
            H256::from_low_u64_be(0x44).as_bytes()
        );
        // Offsets of the 7 head words, then `executeData` length (1) and one 9-word element,
        // followed directly by the `priorityOpsData` length word.
        let words = |i: usize| U256::from_big_endian(&payload[1 + 32 * i..1 + 32 * (i + 1)]);
        assert_eq!(words(0), U256::from(7 * 32));
        assert_eq!(words(7), U256::from(1));
        assert_eq!(words(1), U256::from((7 + 1 + 9) * 32));
    }

    #[test]
    fn test_compute_eip712_hash() {
        let verifying_contract =
            Address::from_str("0xE222D6354b49eaF8a7099fC4E7F9C0B4FE72d1E7").unwrap();
        let chain_id: u64 = 1;
        let chain_address =
            Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let from = U256::from(100);
        let to = U256::from(100);
        let data = Bytes::from(vec![0x12, 0x34]);

        // Step 1: domain separator
        let eip712domain_typehash = ethers::utils::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = ethers::utils::keccak256(b"EraMultisigValidator");
        let version_hash = ethers::utils::keccak256(b"1");
        let domain_separator = ethers::utils::keccak256(ethers::abi::encode(&[
            Token::FixedBytes(eip712domain_typehash.to_vec()),
            Token::FixedBytes(name_hash.to_vec()),
            Token::FixedBytes(version_hash.to_vec()),
            Token::Uint(U256::from(chain_id)),
            Token::Address(verifying_contract),
        ]));

        // Step 2: struct hash
        let execute_batches_typehash = ethers::utils::keccak256(
            b"ExecuteBatches(address chainAddress,uint256 processBatchFrom,uint256 processBatchTo,bytes batchData)",
        );
        let data_hash = ethers::utils::keccak256(data.as_ref());
        let struct_hash = ethers::utils::keccak256(ethers::abi::encode(&[
            Token::FixedBytes(execute_batches_typehash.to_vec()),
            Token::Address(chain_address),
            Token::Uint(from),
            Token::Uint(to),
            Token::FixedBytes(data_hash.to_vec()),
        ]));

        // Step 3: final EIP-712 hash
        let mut digest_input = Vec::with_capacity(2 + 32 + 32);
        digest_input.push(0x19);
        digest_input.push(0x01);
        digest_input.extend_from_slice(&domain_separator);
        digest_input.extend_from_slice(&struct_hash);
        let expected = H256::from(ethers::utils::keccak256(digest_input));

        let result = compute_eip712_hash(
            verifying_contract,
            chain_id,
            chain_address,
            from,
            to,
            &data,
        );

        assert_eq!(result, expected, "EIP-712 hash mismatch");

        // Hardcoded expected value (computed once, acts as a regression guard).
        // If the hashing logic changes, this will catch it.
        let hardcoded_expected = H256::from_str(
            "0x0fea9bd2e2dbeaae1846502ab98bed13f98d677e0616216cff17973dc00d134c",
        )
        .unwrap();
        assert_eq!(
            result, hardcoded_expected,
            "EIP-712 hash does not match hardcoded expected value"
        );
    }

    /// Verified against on-chain `calculateHash` on the Sepolia contract:
    /// cast call 0x7De650653744Aa36eB6de0b384073fc3Cfe03275 \
    ///   "calculateHash(address,uint256,uint256,bytes)(bytes32)" \
    ///   0x0000000000000000000000000000000000000001 100 100 0x1234 \
    ///   --rpc-url https://ethereum-sepolia-rpc.publicnode.com
    #[test]
    fn test_eip712_hash_matches_sepolia_contract() {
        let verifying_contract =
            Address::from_str("0x7De650653744Aa36eB6de0b384073fc3Cfe03275").unwrap();
        let chain_id: u64 = 11155111; // Sepolia
        let chain_address =
            Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let from = U256::from(100);
        let to = U256::from(100);
        let data = Bytes::from(vec![0x12, 0x34]);

        let result = compute_eip712_hash(
            verifying_contract,
            chain_id,
            chain_address,
            from,
            to,
            &data,
        );

        let expected_from_contract = H256::from_str(
            "0x232fd9f202c1b984028512b978de9d04b148742a4524056064ee268b00cb3b02",
        )
        .unwrap();

        assert_eq!(
            result, expected_from_contract,
            "EIP-712 hash must match Sepolia contract calculateHash output"
        );
    }
}
