//! Deploy / shield / unshield against an 8-field Hegota node.
//!
//! State lives in `crates/minimal-shield/.hegota-data/`.
//!
//! ```text
//! HEGOTA_RPC_URL=... HEGOTA_DEPLOYER_PK=... ALLOW_TESTBED_SETUP=1 hegota deploy
//! hegota shield --value 500000000000000000
//! hegota unshield --recipient 0x...
//! hegota deploy-accounts
//! hegota unshield-with-tail --owner-pk 0x... --to 0x...
//! hegota unshield-for-gas --owner-pk 0x... --to 0x...
//! ```

use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    str::FromStr,
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, B256, U256 as AlloyU256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use anyhow::{bail, Context, Result};
use kohaku_fork_kit::minimal_shield::{deploy_frame_account_factory, deploy_minimal_shield_pool};
use kohaku_frametx_kit::{
    recent_root_window_error, Frame, FrameSig, FrameTx, FrameTxClient, SimulateFrame,
    SimulateResult, APPROVE_EXECUTION_AND_PAYMENT, CREATE2_EXEC_FALLBACK, CREATE2_MEASURE_EXEC,
    CREATE2_MEASURE_STATE, CREATE2_STATE_FALLBACK, FRAME_MODE_SENDER, FRAME_MODE_VERIFY,
    SETTLE_FRAME_GAS, SHIELD_VERIFY_GAS,
};
use kohaku_kv_store::{file::FileStore, Store};
use kohaku_minimal_shield::{
    abis::{FrameAccountFactory, ShieldedPool},
    frame_account_salt,
    indexer::{rpc::RpcSyncer, syncer::Syncer, verifier::Verifier, Indexer},
    Call, Note, Pool, PoolProvider, UnshieldResult,
};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct DeployState {
    pool: Option<String>,
    logic: Option<String>,
    verifier: Option<String>,
    poseidon_t3: Option<String>,
    poseidon_t4: Option<String>,
    multicall3: Option<String>,
    frame_account_factory: Option<String>,
    entry_point: Option<String>,
    simple_account_factory: Option<String>,
    simple_account_impl: Option<String>,
    chain_id: Option<u64>,
    deployed_block: Option<u64>,
    root_slot: Option<u64>,
    create2_exec: Option<u64>,
    create2_state: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct NoteFile {
    notes: Vec<Note>,
}

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".hegota-data")
}

fn load_deploy() -> Result<DeployState> {
    let p = data_dir().join("deploy.json");
    if !p.exists() {
        return Ok(DeployState::default());
    }
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}

fn save_deploy(s: &DeployState) -> Result<()> {
    fs::create_dir_all(data_dir())?;
    fs::write(
        data_dir().join("deploy.json"),
        serde_json::to_vec_pretty(s)?,
    )?;
    Ok(())
}

fn load_notes() -> Result<Vec<Note>> {
    let p = data_dir().join("notes.json");
    if !p.exists() {
        return Ok(Vec::new());
    }
    let f: NoteFile = serde_json::from_slice(&fs::read(p)?)?;
    Ok(f.notes)
}

fn save_notes(notes: &[Note]) -> Result<()> {
    fs::create_dir_all(data_dir())?;
    fs::write(
        data_dir().join("notes.json"),
        serde_json::to_vec_pretty(&NoteFile {
            notes: notes.to_vec(),
        })?,
    )?;
    Ok(())
}

fn rpc_url() -> Result<reqwest::Url> {
    std::env::var("HEGOTA_RPC_URL")
        .context("HEGOTA_RPC_URL")?
        .parse()
        .context("rpc url")
}

fn deployer() -> Result<PrivateKeySigner> {
    let pk = std::env::var("HEGOTA_DEPLOYER_PK").context("HEGOTA_DEPLOYER_PK")?;
    pk.parse().context("deployer key")
}

fn parse_addr(s: &str) -> Result<Address> {
    s.parse().context("address")
}

fn require_addr(opt: Option<&str>, name: &str) -> Result<Address> {
    parse_addr(opt.with_context(|| format!("run deploy first ({name})"))?)
}

/// Unset used to mean 0 and made `indexer.sync` walk the entire Hegotá history.
const DEFAULT_DEPLOYED_BLOCK: u64 = 143_402;

fn deployed_block(st: &DeployState) -> u64 {
    st.deployed_block.unwrap_or(DEFAULT_DEPLOYED_BLOCK)
}

fn say(msg: impl AsRef<str>) {
    println!("{}", msg.as_ref());
    let _ = io::stdout().flush();
}

fn persist_note(note: &Note) -> Result<()> {
    let mut notes = load_notes()?;
    if notes.last() != Some(note) {
        notes.push(note.clone());
        save_notes(&notes)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    kohaku_minimal_shield_circuit::set_circuit_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.hegota-data/circuit"
    ));
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "deploy" => cmd_deploy().await,
        "deploy-accounts" => cmd_deploy_accounts().await,
        "shield" => cmd_shield(&mut args).await,
        "publish" => cmd_publish().await,
        "unshield" => cmd_unshield(&mut args).await,
        "unshield-with-tail" => cmd_unshield_with_tail(&mut args).await,
        "unshield-for-gas" => cmd_unshield_for_gas(&mut args).await,
        _ => {
            eprintln!(
                "usage: hegota deploy|deploy-accounts|shield|publish|unshield|unshield-with-tail|unshield-for-gas\n  \
                 shield --value <wei>\n  \
                 publish\n  \
                 unshield --recipient 0x...\n  \
                 unshield-with-tail --owner-pk 0x... [--to 0x...] [--amount <wei>]\n  \
                 unshield-for-gas --owner-pk 0x... [--to 0x...] [--amount <wei>]"
            );
            Ok(())
        }
    }
}

async fn cmd_deploy() -> Result<()> {
    if std::env::var("ALLOW_TESTBED_SETUP").ok().as_deref() != Some("1") {
        bail!("set ALLOW_TESTBED_SETUP=1 to deploy the testbed proving key");
    }
    let signer = deployer()?;
    println!("deployer {:#x}", signer.address());
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url()?);
    let bal = provider.get_balance(signer.address()).await?;
    println!("deployer balance {bal} wei");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let client = FrameTxClient::new(rpc_url()?);
    let d = deploy_minimal_shield_pool(provider, &client).await?;
    let st = DeployState {
        pool: Some(format!("{:#x}", d.pool)),
        logic: Some(format!("{:#x}", d.logic)),
        verifier: Some(format!("{:#x}", d.verifier)),
        poseidon_t3: Some(format!("{:#x}", d.poseidon_t3)),
        poseidon_t4: Some(format!("{:#x}", d.poseidon_t4)),
        multicall3: Some(format!("{:#x}", d.multicall3)),
        frame_account_factory: Some(format!("{:#x}", d.frame_account_factory)),
        entry_point: None,
        simple_account_factory: None,
        simple_account_impl: None,
        chain_id: Some(client.chain_id().await?),
        deployed_block: Some(d.deployed_block),
        root_slot: None,
        ..DeployState::default()
    };
    save_deploy(&st)?;
    if data_dir().join("indexer.redb").exists() {
        fs::remove_file(data_dir().join("indexer.redb"))?;
    }
    println!("pool {:#x}", d.pool);
    println!("multicall3 {:#x}", d.multicall3);
    println!("frameAccountFactory {:#x}", d.frame_account_factory);
    println!("wrote {}", data_dir().join("deploy.json").display());
    Ok(())
}

async fn cmd_deploy_accounts() -> Result<()> {
    let mut st = load_deploy()?;
    let _pool = require_addr(st.pool.as_deref(), "pool")?;
    let multicall3 = require_addr(st.multicall3.as_deref(), "multicall3")?;
    let factory = if let Some(existing) = st.frame_account_factory.as_deref() {
        say(format!("reusing FrameAccountFactory {existing}"));
        parse_addr(existing)?
    } else {
        say("deploying FrameAccountFactory…");
        let addr = deploy_frame_account_factory().await?;
        st.frame_account_factory = Some(format!("{addr:#x}"));
        addr
    };
    let (exec, state) = measure_create2(factory).await?;
    st.create2_exec = Some(exec);
    st.create2_state = Some(state);
    save_deploy(&st)?;
    println!("multicall3 {multicall3:#x}");
    println!("frameAccountFactory {factory:#x}");
    println!("create2_exec {exec} create2_state {state}");
    println!("wrote {}", data_dir().join("deploy.json").display());
    Ok(())
}

async fn cmd_shield(args: &mut impl Iterator<Item = String>) -> Result<()> {
    let mut value = U256::from(10u64.pow(17));
    while let Some(a) = args.next() {
        if a == "--value" {
            value = args.next().context("--value")?.parse()?;
        }
    }
    let mut st = load_deploy()?;
    let pool_addr = require_addr(st.pool.as_deref(), "pool")?;
    let factory = st
        .frame_account_factory
        .as_deref()
        .map(parse_addr)
        .transpose()?
        .unwrap_or(Address::ZERO);
    let signer = deployer()?;
    let client = FrameTxClient::new(rpc_url()?);
    let chain = client.chain_id().await?;
    let nonce = client.tx_count(signer.address()).await?;
    let (tip, max_fee) = client.fees().await?;
    let provider = http_provider()?;
    let pool = Pool {
        chain_id: chain,
        address: pool_addr,
        factory,
        deployed_block: deployed_block(&st),
    };
    let mut rng = rand::rng();
    let note = Note::random(value, chain, pool_addr, &mut rng);
    let msp = pool_provider(pool, provider.clone())?;
    let mut tx = msp.shield(&note, signer.address(), nonce, chain, tip, max_fee);
    tx.sign_secp256k1(0, &signer)?;
    say("simulate shield…");
    if let Err(e) = client.gate_spend(&tx).await {
        bail!("simulate: {e}");
    }
    say("simulate ok; sending");
    let hash = client.send_raw(&tx.raw()).await?;
    persist_note(&note)?;
    say(format!(
        "sent {hash:#x}; wrote {}",
        data_dir().join("notes.json").display()
    ));
    wait_inclusion(&client, hash).await?;
    say("shield mined");
    let epoch = ShieldedPool::new(pool_addr, &provider)
        .currentEpoch()
        .call()
        .await?;
    let slot = publish_root(&client, &msp, &signer, epoch, chain).await?;
    st.root_slot = Some(slot);
    save_deploy(&st)?;
    println!("shielded {value} -> {hash:#x}; published epoch {epoch} at slot {slot}");
    Ok(())
}

async fn cmd_publish() -> Result<()> {
    let mut st = load_deploy()?;
    let pool_addr = require_addr(st.pool.as_deref(), "pool")?;
    let factory = st
        .frame_account_factory
        .as_deref()
        .map(parse_addr)
        .transpose()?
        .unwrap_or(Address::ZERO);
    let signer = deployer()?;
    let client = FrameTxClient::new(rpc_url()?);
    let chain = client.chain_id().await?;
    let provider = http_provider()?;
    let pool = Pool {
        chain_id: chain,
        address: pool_addr,
        factory,
        deployed_block: deployed_block(&st),
    };
    let msp = pool_provider(pool, provider.clone())?;
    let epoch = ShieldedPool::new(pool_addr, &provider)
        .currentEpoch()
        .call()
        .await?;
    let slot = publish_root(&client, &msp, &signer, epoch, chain).await?;
    st.root_slot = Some(slot);
    save_deploy(&st)?;
    println!("published epoch {epoch} at slot {slot}");
    Ok(())
}

async fn cmd_unshield(args: &mut impl Iterator<Item = String>) -> Result<()> {
    let mut recipient = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--recipient" => recipient = Some(parse_addr(&args.next().context("--recipient")?)?),
            "--account" | "--calls" => {
                bail!("use unshield-with-tail for a FrameAccount tail");
            }
            other => bail!("unknown flag {other}"),
        }
    }
    let recipient = recipient.context("--recipient")?;
    let before = balance_of(recipient).await?;
    let parts = prepare_spend().await?;
    let dummy = dummy_for(&parts.note);
    let tail = parts.msp.claim_tail(recipient);
    let result = parts
        .msp
        .unshield(
            &parts.note,
            &dummy,
            recipient,
            Some(tail),
            None,
            &parts.signer,
            parts.root_slot,
            parts.epoch,
            parts.chain,
            parts.tip,
            parts.max_fee,
        )
        .await?;
    say(format!(
        "unshield fee={} publicAmount={}",
        result.fee, result.public_amount
    ));
    let hash = broadcast_unshield(&result, &parts.note).await?;
    let after = balance_of(recipient).await?;
    println!(
        "unshield {hash:#x} publicAmount={} recipient={recipient:#x} {before} -> {after} wei",
        result.public_amount
    );
    Ok(())
}

/// One ETH transfer from the FrameAccount after claim+CREATE2. 0.001 ether.
const FRAME_ACCOUNT_PAYOUT: u64 = 1_000_000_000_000_000;

async fn cmd_unshield_with_tail(args: &mut impl Iterator<Item = String>) -> Result<()> {
    let mut dest: Option<Address> = None;
    let mut amount: Option<AlloyU256> = None;
    let mut owner_pk: Option<PrivateKeySigner> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--to" => dest = Some(parse_addr(&args.next().context("--to")?)?),
            "--amount" => amount = Some(args.next().context("--amount")?.parse()?),
            "--owner-pk" => {
                owner_pk = Some(
                    args.next()
                        .context("--owner-pk")?
                        .parse()
                        .context("owner pk")?,
                );
            }
            other => bail!("unknown flag {other}"),
        }
    }
    let owner = owner_pk.context("--owner-pk is required")?;
    let dest = match dest {
        Some(d) => d,
        None => deployer()?.address(),
    };
    let send_amount = amount.unwrap_or(AlloyU256::from(FRAME_ACCOUNT_PAYOUT));
    if send_amount.is_zero() {
        bail!("--amount must be positive");
    }
    let calls = vec![Call {
        target: dest,
        value: send_amount,
        data: Bytes::new(),
    }];
    let parts = prepare_spend().await?;
    let dummy = dummy_for(&parts.note);
    say(format!("owner {:#x}", owner.address()));
    say(format!("executeBatch -> {dest:#x} value={send_amount}"));
    say("tail: createAccount, claimWithdrawal, executeBatch");
    let before_dest = balance_of(dest).await?;
    let result = parts
        .msp
        .unshield_with_tail(
            &parts.rpc,
            &parts.note,
            &dummy,
            &owner,
            &calls,
            parts.multicall3,
            parts.create2_exec,
            parts.create2_state,
            &parts.signer,
            parts.root_slot,
            parts.epoch,
            parts.chain,
            parts.tip,
            parts.max_fee,
            &parts.creation_code,
        )
        .await?;
    let account = result
        .account
        .context("account tail did not report an account")?;
    let public_amount = ruint_to_alloy(result.public_amount);
    if send_amount > public_amount {
        bail!("payout {send_amount} exceeds publicAmount {public_amount}");
    }
    say(format!(
        "fee={} publicAmount={} max_cost={} account={account:#x}",
        result.fee,
        result.public_amount,
        result.tx.max_cost()
    ));
    let before_account = balance_of(account).await?;
    let hash = broadcast_unshield(&result, &parts.note).await?;
    let after_dest = balance_of(dest).await?;
    let after_account = balance_of(account).await?;
    println!(
        "unshield-with-tail {hash:#x} publicAmount={} account={account:#x} dest={dest:#x}",
        result.public_amount
    );
    println!("  dest {before_dest} -> {after_dest} wei (wanted {send_amount})");
    println!("  account {before_account} -> {after_account} wei");
    Ok(())
}

async fn cmd_unshield_for_gas(args: &mut impl Iterator<Item = String>) -> Result<()> {
    let mut dest: Option<Address> = None;
    let mut amount: Option<AlloyU256> = None;
    let mut owner_pk: Option<PrivateKeySigner> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--to" => dest = Some(parse_addr(&args.next().context("--to")?)?),
            "--amount" => amount = Some(args.next().context("--amount")?.parse()?),
            "--owner-pk" => {
                owner_pk = Some(
                    args.next()
                        .context("--owner-pk")?
                        .parse()
                        .context("owner pk")?,
                );
            }
            other => bail!("unknown flag {other}"),
        }
    }
    let owner = owner_pk.context("--owner-pk is required")?;
    let dest = match dest {
        Some(d) => d,
        None => deployer()?.address(),
    };
    let send_amount = amount.unwrap_or(AlloyU256::from(FRAME_ACCOUNT_PAYOUT));
    let calls = vec![Call {
        target: dest,
        value: send_amount,
        data: Bytes::new(),
    }];
    let parts = prepare_spend().await?;
    let dummy = dummy_for(&parts.note);
    say(format!("owner {:#x}", owner.address()));
    say(format!(
        "gas-only publicAmount=0 executeBatch -> {dest:#x} value={send_amount}"
    ));
    let result = parts
        .msp
        .unshield_for_gas(
            &parts.rpc,
            &parts.note,
            &dummy,
            &owner,
            &calls,
            parts.multicall3,
            parts.create2_exec,
            parts.create2_state,
            &parts.signer,
            parts.root_slot,
            parts.epoch,
            parts.chain,
            parts.tip,
            parts.max_fee,
            &parts.creation_code,
        )
        .await?;
    let account = result
        .account
        .context("account tail did not report an account")?;
    say(format!(
        "fee={} publicAmount={} max_cost={} account={account:#x}",
        result.fee,
        result.public_amount,
        result.tx.max_cost()
    ));
    let hash = broadcast_unshield(&result, &parts.note).await?;
    println!("unshield-for-gas {hash:#x} account={account:#x} dest={dest:#x}");
    Ok(())
}

struct SpendParts<P> {
    msp: PoolProvider,
    rpc: P,
    note: Note,
    signer: PrivateKeySigner,
    chain: u64,
    tip: AlloyU256,
    max_fee: AlloyU256,
    epoch: u64,
    root_slot: u64,
    multicall3: Address,
    create2_exec: u64,
    create2_state: u64,
    creation_code: Vec<u8>,
}

async fn prepare_spend() -> Result<SpendParts<impl Provider + Clone + 'static>> {
    let st = load_deploy()?;
    let pool_addr = require_addr(st.pool.as_deref(), "pool")?;
    let factory = st
        .frame_account_factory
        .as_deref()
        .map(parse_addr)
        .transpose()?
        .unwrap_or(Address::ZERO);
    let multicall3 = require_addr(st.multicall3.as_deref(), "multicall3")?;
    let note = last_note()?;
    let signer = deployer()?;
    let client = FrameTxClient::new(rpc_url()?);
    let chain = client.chain_id().await?;
    let (tip, max_fee) = client.fees().await?;
    let rpc = http_provider()?;
    let pool = Pool {
        chain_id: chain,
        address: pool_addr,
        factory,
        deployed_block: deployed_block(&st),
    };
    let msp = pool_provider(pool, rpc.clone())?;
    say("syncing indexer…");
    msp.indexer.sync().await?;
    let epoch = ShieldedPool::new(pool_addr, &rpc)
        .currentEpoch()
        .call()
        .await?;
    let mut st = st;
    // Spend proves against the current tree. Reuse of an older publish slot
    // makes the 0x8272 VERIFY frame revert (validation prefix).
    let root_slot = publish_root(&client, &msp, &signer, epoch, chain).await?;
    st.root_slot = Some(root_slot);
    save_deploy(&st)?;
    if let Some(err) = recent_root_window_error(root_slot, client.slot_number().await?) {
        bail!("{err}");
    }
    Ok(SpendParts {
        msp,
        rpc,
        note,
        signer,
        chain,
        tip,
        max_fee,
        epoch,
        root_slot,
        multicall3,
        create2_exec: st.create2_exec.unwrap_or(0),
        create2_state: st.create2_state.unwrap_or(0),
        creation_code: frame_account_creation_code()?,
    })
}

fn frame_account_creation_code() -> Result<Vec<u8>> {
    let raw = std::env::var("HEGOTA_FRAME_ACCOUNT_CREATION_CODE")
        .context("set HEGOTA_FRAME_ACCOUNT_CREATION_CODE to the FrameAccount creation bytecode hex")?;
    let hex = raw.trim().trim_start_matches("0x");
    hex::decode(hex).context("HEGOTA_FRAME_ACCOUNT_CREATION_CODE hex")
}

async fn broadcast_unshield(result: &UnshieldResult, note: &Note) -> Result<B256> {
    let client = FrameTxClient::new(rpc_url()?);
    say("simulate unshield…");
    let sim = match client.gate_spend(&result.tx).await {
        Ok(s) => s,
        Err(e) => bail!("simulate: {e}"),
    };
    if let Some(tail) = result.tx.frames.get(3) {
        let used = sim
            .frames
            .as_ref()
            .and_then(|frames| frames.get(3))
            .and_then(sim_frame_exec);
        say(format!(
            "tail declared exec={} state={} simulated_gas_used={used:?}",
            tail.execution_gas, tail.state_gas
        ));
    }
    say("sending unshield");
    let hash = client.send_raw(&result.tx.raw()).await?;
    say(format!("sent {hash:#x}"));
    wait_inclusion(&client, hash).await?;
    let st = load_deploy()?;
    let pool_addr = require_addr(st.pool.as_deref(), "pool")?;
    let factory = st
        .frame_account_factory
        .as_deref()
        .map(parse_addr)
        .transpose()?
        .unwrap_or(Address::ZERO);
    let pool = Pool {
        chain_id: client.chain_id().await?,
        address: pool_addr,
        factory,
        deployed_block: deployed_block(&st),
    };
    let msp = pool_provider(pool, http_provider()?)?;
    msp.indexer.sync().await?;
    let mut notes = load_notes()?;
    notes.retain(|n| n != note);
    save_notes(&notes)?;
    Ok(hash)
}

async fn measure_create2(factory: Address) -> Result<(u64, u64)> {
    let signer = deployer()?;
    let client = FrameTxClient::new(rpc_url()?);
    let chain = client.chain_id().await?;
    let nonce = client.tx_count(signer.address()).await?;
    let (tip, max_fee) = client.fees().await?;
    let throwaway = PrivateKeySigner::random();
    let owner = throwaway.address();
    let salt = frame_account_salt(owner);
    let mut tx = create_account_measure_tx(
        factory,
        owner,
        salt,
        signer.address(),
        nonce,
        chain,
        tip,
        max_fee,
    );
    tx.sign_secp256k1(0, &signer)?;
    say(format!("simulate createAccount throwaway={owner:#x}"));
    let sim = client.gate_spend(&tx).await?;
    let (mut exec, mut state) = create2_from_sim(&sim);
    say("sending CREATE2 measure");
    let hash = client.send_raw(&tx.raw()).await?;
    let receipt = wait_inclusion(&client, hash).await?;
    if let Some((e, s)) = create2_from_receipt(&receipt) {
        exec = e;
        if s > 0 {
            state = s;
        }
    }
    if exec == 0 {
        say("CREATE2 exec gas not reported; using fallback");
        exec = CREATE2_EXEC_FALLBACK;
    }
    if state == 0 {
        say("CREATE2 state gas not reported; using fallback");
        state = CREATE2_STATE_FALLBACK;
    }
    Ok((exec, state))
}

fn create_account_measure_tx(
    factory: Address,
    owner: Address,
    salt: B256,
    sender: Address,
    nonce_seq: u64,
    chain_id: u64,
    max_priority_fee: AlloyU256,
    max_fee: AlloyU256,
) -> FrameTx {
    let data = Bytes::from(FrameAccountFactory::createAccountCall { owner, salt }.abi_encode());
    user_funded_sender(
        factory,
        data,
        CREATE2_MEASURE_EXEC.max(SETTLE_FRAME_GAS),
        CREATE2_MEASURE_STATE,
        sender,
        nonce_seq,
        chain_id,
        max_priority_fee,
        max_fee,
    )
}

fn user_funded_sender(
    target: Address,
    data: Bytes,
    execution_gas: u64,
    state_gas: u64,
    sender: Address,
    nonce_seq: u64,
    chain_id: u64,
    max_priority_fee: AlloyU256,
    max_fee: AlloyU256,
) -> FrameTx {
    FrameTx {
        chain_id,
        nonce_keys: vec![AlloyU256::ZERO],
        nonce_seq,
        sender,
        frames: vec![
            Frame {
                mode: FRAME_MODE_VERIFY,
                flags: APPROVE_EXECUTION_AND_PAYMENT,
                target: Some(sender),
                execution_gas: SHIELD_VERIFY_GAS,
                state_gas: 0,
                value: AlloyU256::ZERO,
                data: Bytes::new(),
            },
            Frame {
                mode: FRAME_MODE_SENDER,
                flags: 0,
                target: Some(target),
                execution_gas,
                state_gas,
                value: AlloyU256::ZERO,
                data,
            },
        ],
        signatures: vec![FrameSig::secp256k1(sender)],
        max_priority_fee,
        max_fee,
        max_blob_fee: AlloyU256::ZERO,
        blob_hashes: vec![],
    }
}

fn create2_from_sim(sim: &SimulateResult) -> (u64, u64) {
    let Some(frame) = sim.frames.as_ref().and_then(|f| f.get(1)) else {
        return (0, 0);
    };
    (
        sim_frame_exec(frame).unwrap_or(0),
        sim_frame_state(frame).unwrap_or(0),
    )
}

fn create2_from_receipt(rcpt: &serde_json::Value) -> Option<(u64, u64)> {
    let frames = rcpt.get("frameReceipts")?.as_array()?;
    let frame = frames.get(1)?;
    let exec = parse_qty(frame.get("gasUsed")?)?;
    let state = frame
        .get("stateGasUsed")
        .or_else(|| frame.get("stateGas"))
        .and_then(parse_qty)
        .unwrap_or(0);
    Some((exec, state))
}

fn sim_frame_exec(frame: &SimulateFrame) -> Option<u64> {
    frame
        .gas_used
        .as_ref()
        .and_then(|s| parse_qty(&serde_json::Value::String(s.clone())))
        .or_else(|| frame.extra.get("gasUsed").and_then(parse_qty))
}

fn sim_frame_state(frame: &SimulateFrame) -> Option<u64> {
    ["stateGasUsed", "stateGas", "state_gas", "stateUsed"]
        .iter()
        .find_map(|key| frame.extra.get(*key).and_then(parse_qty))
}

fn parse_qty(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse().ok()
            }
        }
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn ruint_to_alloy(v: U256) -> AlloyU256 {
    AlloyU256::from_be_bytes(v.to_be_bytes::<32>())
}

fn dummy_for(note: &Note) -> Note {
    let mut rng = rand::rng();
    Note::random(U256::ZERO, note.chain_id, note.pool, &mut rng)
}

fn last_note() -> Result<Note> {
    load_notes()?
        .pop()
        .context("no shielded notes; run shield first")
}

fn pool_provider(pool: Pool, provider: impl Provider + Clone + 'static) -> Result<PoolProvider> {
    fs::create_dir_all(data_dir())?;
    let store = Store::new(FileStore::open(data_dir().join("indexer.redb"))?);
    let rpc = RpcSyncer::new(provider);
    let indexer = Indexer::new(pool, store, Syncer::new(rpc.clone()), Verifier::new(rpc));
    Ok(PoolProvider::new(indexer))
}

fn http_provider() -> Result<impl Provider + Clone + 'static> {
    let signer = deployer()?;
    let wallet = EthereumWallet::from(signer);
    Ok(ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url()?))
}

async fn publish_root(
    client: &FrameTxClient,
    msp: &kohaku_minimal_shield::PoolProvider,
    signer: &PrivateKeySigner,
    epoch: u64,
    chain: u64,
) -> Result<u64> {
    let nonce = client.tx_count(signer.address()).await?;
    let (tip, max_fee) = client.fees().await?;
    let mut tx = msp.publish_epoch(signer.address(), nonce, chain, tip, max_fee, epoch);
    tx.sign_secp256k1(0, signer)?;
    say(format!("simulate publishEpochRoot({epoch})"));
    if let Err(e) = client.gate_spend(&tx).await {
        bail!("publish simulate: {e}");
    }
    say(format!("publishEpochRoot({epoch}) via frame tx"));
    let hash = client.send_raw(&tx.raw()).await?;
    say(format!("sent publish {hash:#x}"));
    let receipt = wait_inclusion(client, hash).await?;
    let block_hash = receipt
        .get("blockHash")
        .and_then(serde_json::Value::as_str)
        .context("publish receipt missing blockHash")?;
    let block_hash = B256::from_str(block_hash)?;
    let block_number = receipt
        .get("blockNumber")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
        .context("publish receipt missing blockNumber")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let head = client.block_number().await?;
        say(format!(
            "  confirmations: head={head} publish_block={block_number} (need +2)"
        ));
        if head >= block_number.saturating_add(2) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            bail!("timed out waiting for 2 blocks after publish at {block_number} (head {head})");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    client.slot_number_of(block_hash).await.map_err(Into::into)
}

async fn wait_inclusion(client: &FrameTxClient, hash: B256) -> Result<serde_json::Value> {
    say(format!("waiting for {hash:#x}"));
    let receipt = client.wait_receipt(hash, 360).await?;
    if !receipt_succeeded(&receipt) {
        bail!("tx {hash:#x} reverted (status {:?})", receipt.get("status"));
    }
    say(format!("mined {hash:#x}"));
    Ok(receipt)
}

fn receipt_succeeded(rcpt: &serde_json::Value) -> bool {
    if evm_status_ok(rcpt.get("status")) {
        return true;
    }
    let Some(frames) = rcpt
        .get("frameReceipts")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    !frames.is_empty() && frames.iter().all(frame_succeeded)
}

fn frame_succeeded(frame: &serde_json::Value) -> bool {
    if let Some(ok) = frame.get("succeeded").and_then(serde_json::Value::as_bool) {
        return ok;
    }
    evm_status_ok(frame.get("status"))
}

fn evm_status_ok(v: Option<&serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::String(s)) => {
            let s = s.trim();
            s == "0x1" || s == "1"
        }
        Some(serde_json::Value::Number(n)) => n.as_u64() == Some(1),
        _ => false,
    }
}

async fn balance_of(addr: Address) -> Result<AlloyU256> {
    Ok(http_provider()?.get_balance(addr).await?)
}
