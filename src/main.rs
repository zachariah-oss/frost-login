use clap::{ArgAction, Parser, Subcommand};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::time::{timeout, Instant};

const CONTRACT: TableDefinition<&str, &str> = TableDefinition::new("contract");
const EVENTS: TableDefinition<u64, &str> = TableDefinition::new("events");
const LOGIN_RESULTS: TableDefinition<&str, &str> = TableDefinition::new("login_results");
const UNIT: &str = env!("UNIT_NAME");
const IDENTITY: &str = env!("UNIT_IDENTITY");
const CONTRACT_JSON: &str = env!("UNIT_CONTRACT");
const SOURCE: &str = env!("UNIT_SOURCE");
const THEOREMS: &str = env!("UNIT_THEOREMS");
const AUTHENTICATION: &str = env!("UNIT_AUTHENTICATION");
const LIFECYCLE: &str = env!("UNIT_LIFECYCLE");
const INTERFACE: &str = env!("UNIT_INTERFACE");
const REPOSITORY: &str = env!("UNIT_REPOSITORY");
const RUNTIME: &str = env!("UNIT_RUNTIME");
const THEOREM_CHANNELS: Option<&str> = option_env!("UNIT_THEOREM_CHANNELS");
const GRAPH_NODES: Option<&str> = option_env!("UNIT_GRAPH_NODES");
const GRAPH_EDGES: Option<&str> = option_env!("UNIT_GRAPH_EDGES");
const ADAPTERS: Option<&str> = option_env!("UNIT_ADAPTERS");
const HYPOTHESES: Option<&str> = option_env!("UNIT_HYPOTHESES");
const OBLIGATIONS: Option<&str> = option_env!("UNIT_OBLIGATIONS");
const PROOF_OBLIGATIONS: Option<&str> = option_env!("UNIT_PROOF_OBLIGATIONS");
const EXECUTIONS: Option<&str> = option_env!("UNIT_EXECUTIONS");
const LIFECYCLE_LIMITS: Option<&str> = option_env!("UNIT_LIFECYCLE_LIMITS");
const AUTH_CAPABILITY_DEPENDENCIES: Option<&str> = option_env!("UNIT_AUTH_CAPABILITY_DEPENDENCIES");
const GENERATING_SET: Option<&str> = option_env!("UNIT_GENERATING_SET");
const DEFAULT_DEADLINE_MS: u64 = 5_000;
const DEFAULT_LEASE_MS: u64 = 1_000;
const MAX_DEADLINE_MS: u64 = 60_000;
const MAX_RETRIES: u32 = 7;
const MAX_LEASE_MS: u64 = 30_000;
const REQUIRED_COMPILE_ENVIRONMENT: [&str; 10] = [
    "UNIT_NAME",
    "UNIT_IDENTITY",
    "UNIT_CONTRACT",
    "UNIT_SOURCE",
    "UNIT_THEOREMS",
    "UNIT_AUTHENTICATION",
    "UNIT_LIFECYCLE",
    "UNIT_INTERFACE",
    "UNIT_REPOSITORY",
    "UNIT_RUNTIME",
];
const OPTIONAL_COMPILE_ENVIRONMENT: [&str; 10] = [
    "UNIT_THEOREM_CHANNELS",
    "UNIT_GRAPH_NODES",
    "UNIT_GRAPH_EDGES",
    "UNIT_ADAPTERS",
    "UNIT_HYPOTHESES",
    "UNIT_OBLIGATIONS",
    "UNIT_PROOF_OBLIGATIONS",
    "UNIT_EXECUTIONS",
    "UNIT_LIFECYCLE_LIMITS",
    "UNIT_AUTH_CAPABILITY_DEPENDENCIES",
];
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

type Fail = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
#[command(name = "frost-login", version = "3.0.0")]
struct Cli {
    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    Contract {
        #[command(subcommand)]
        action: Option<ContractAction>,
    },
    GeneratingSet,
    DrvClosure,
    MemoryReferences,
    ProofGenerators,
    Home {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Lifecycle {
        #[arg(long)]
        operation: String,
        #[arg(long, default_value_t = DEFAULT_DEADLINE_MS)]
        deadline_ms: u64,
        #[arg(long, default_value_t = 0)]
        retry_limit: u32,
        #[arg(long, default_value_t = DEFAULT_LEASE_MS)]
        lease_ms: u64,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        cleanup: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Report {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        derivation_output: bool,
    },
    Repo,
    Docs,
    Doctor,
    Inspect {
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "rust-cargo-inspector")]
        adapter: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Analyze {
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "rust-cargo-inspector")]
        adapter: String,
        #[arg(long)]
        hypotheses: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Elaborate {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        hypotheses: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Obligations {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Solve {
        #[arg(long)]
        id: String,
        #[arg(long = "evidence")]
        evidence: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Render {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        hypotheses: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Graph {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    #[command(alias = "run")]
    Execute {
        #[arg(long)]
        adapter: String,
        #[arg(long)]
        operation: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_LEASE_MS)]
        auth_lifetime_ms: u64,
        #[arg(long, default_value_t = DEFAULT_DEADLINE_MS)]
        deadline_ms: u64,
        #[arg(long, default_value_t = 0)]
        retry_limit: u32,
        #[arg(long, default_value_t = DEFAULT_LEASE_MS)]
        lease_ms: u64,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        cleanup: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    #[command(alias = "inventory")]
    Adapters {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    #[command(hide = true)]
    AdapterChild {
        #[arg(long)]
        adapter: String,
        #[arg(long)]
        operation: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long)]
        auth_lifetime_ms: u64,
    },
    Login {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        target_path_kind: String,
        #[arg(long)]
        target_path: String,
        #[arg(long = "arg")]
        provider_args: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_DEADLINE_MS)]
        deadline_ms: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    LoginStatus {
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    StsIdentity {
        #[arg(long)]
        target_path: String,
        #[arg(long)]
        expected_account: String,
        #[arg(long = "arg")]
        provider_args: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_DEADLINE_MS)]
        deadline_ms: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ContractAction {
    Show,
    Persist {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        derivation_output: bool,
    },
    Prove {
        #[arg(long)]
        plane: String,
        #[arg(long)]
        theorem: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        derivation_output: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Event {
    schema: String,
    timestamp_unix_ms: u128,
    unit: String,
    identity: String,
    operation: String,
    status: String,
    plane: Option<String>,
    theorem: Option<String>,
    evidence: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SourceFileInspection {
    path: String,
    kind: String,
    bytes: u64,
    lines: u64,
    functions: u64,
    tests: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SourceInspection {
    schema: String,
    adapter: String,
    root: String,
    package_name: String,
    package_version: String,
    edition: String,
    dependencies: BTreeMap<String, String>,
    lock_packages: u64,
    files: Vec<SourceFileInspection>,
    compile_source_contract: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Hypothesis {
    id: String,
    statement: String,
    status: String,
    provenance: Vec<String>,
    evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Obligation {
    id: String,
    statement: String,
    status: String,
    dependencies: Vec<String>,
    evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ProofObligation {
    name: String,
    plane: String,
    statement: String,
    phase: String,
    evaluator: String,
    evidence_policy: String,
    gate: String,
    dependencies: Vec<String>,
    identity: String,
}

fn canonical_proof_obligations() -> Vec<ProofObligation> {
    vec![
        ProofObligation { name: "authority-and-phase-totality".to_owned(), plane: "governance".to_owned(), statement: "Obligation intents, governing authorities, accountable owners, prerequisite questions, bounded proof searches, pinned authority decisions, and promoted obligations are closed and total; no unresolved statement-shaping question reaches theorem definition.".to_owned(), phase: "static".to_owned(), evaluator: "nix".to_owned(), evidence_policy: "typed-closure".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec![], identity: "70f213a1a04c29c19e8019ac7567e6b57b9a1fe6c1fe7b4bbe726f4c606400f3".to_owned() },
        ProofObligation { name: "rust-nix-obligation-bijection".to_owned(), plane: "contract".to_owned(), statement: "The Nix proof-obligation projection is a bijective mirror of the canonical Rust inventory.".to_owned(), phase: "static".to_owned(), evaluator: "rust".to_owned(), evidence_policy: "compiled-instrument".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec!["authority-and-phase-totality".to_owned()], identity: "5d8fa17ddf7de60bccc8aa3ae55d9ce6611c99d58d23c0ec6f67f006e0e92157".to_owned() },
        ProofObligation { name: "explicit-execution-environment".to_owned(), plane: "environment".to_owned(), statement: "Every execution environment is explicit, bounded, and projected without ambient inheritance.".to_owned(), phase: "static".to_owned(), evaluator: "nix".to_owned(), evidence_policy: "typed-closure".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec!["rust-nix-obligation-bijection".to_owned()], identity: "fcd7ff77cc5cdebf675dbd66b70443e31ddde6fab7bc426310cd23d3615b8abe".to_owned() },
        ProofObligation { name: "pure-rust-dispatch".to_owned(), plane: "interface".to_owned(), statement: "All behavioral dispatch and scripting is implemented by one compiled Rust CLI; the flake contains no authored shell program, phase, hook, or command body.".to_owned(), phase: "static".to_owned(), evaluator: "rust".to_owned(), evidence_policy: "compiled-instrument".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec!["rust-nix-obligation-bijection".to_owned(), "explicit-execution-environment".to_owned()], identity: "26dd0824b7350df72b0e8dce0f01f43956ddc2e9427038ace33bd194468b7bfb".to_owned() },
        ProofObligation { name: "minimal-source-layout".to_owned(), plane: "repository".to_owned(), statement: "The unit root is minimal and every admitted source or workspace lives below src.".to_owned(), phase: "static".to_owned(), evaluator: "nix".to_owned(), evidence_policy: "typed-closure".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec!["rust-nix-obligation-bijection".to_owned()], identity: "ec7ff2b56fd5d7d605796d3ca27adc052bd98bbeeebe7d1767b78e2b44f84bdc".to_owned() },
        ProofObligation { name: "native-projection-closure".to_owned(), plane: "delivery".to_owned(), statement: "The native Rust package and compatibility projections derive from the frozen root.".to_owned(), phase: "static".to_owned(), evaluator: "nix".to_owned(), evidence_policy: "typed-closure".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec!["rust-nix-obligation-bijection".to_owned(), "explicit-execution-environment".to_owned(), "pure-rust-dispatch".to_owned(), "minimal-source-layout".to_owned()], identity: "8729f8dbd7fc254db48a0a020ae599ae0db0c9f40f351733be04234ef10fd9a9".to_owned() },
        ProofObligation { name: "runtime-ai-absence".to_owned(), plane: "runtime".to_owned(), statement: "The frozen framework has no AI dependency and does not claim unobserved runtime evidence.".to_owned(), phase: "static".to_owned(), evaluator: "rust".to_owned(), evidence_policy: "compiled-instrument".to_owned(), gate: "static-freeze".to_owned(), dependencies: vec!["rust-nix-obligation-bijection".to_owned(), "explicit-execution-environment".to_owned(), "pure-rust-dispatch".to_owned(), "native-projection-closure".to_owned()], identity: "f90a19876748e1cf77a8c181d2fba5fed770a78e5da53116e58be0127d159b3a".to_owned() },
    ]
}

fn proof_obligations() -> Result<Vec<ProofObligation>, Fail> {
    let canonical = canonical_proof_obligations();
    if let Some(raw) = PROOF_OBLIGATIONS {
        let mirrored: Vec<ProofObligation> = serde_json::from_str(raw)?;
        if mirrored != canonical {
            return Err("Nix proofObligations does not exactly mirror src/main.rs".into());
        }
    }
    Ok(canonical)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AdapterContract {
    name: String,
    kind: String,
    operations: Vec<String>,
    scopes: Vec<String>,
    max_lifetime_ms: u64,
    max_deadline_ms: u64,
    max_retries: u32,
    fake: bool,
    metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct GraphNode {
    id: String,
    kind: String,
    plane: Option<String>,
    immutable_root: bool,
    runtime_witness: bool,
    nonleaf_check: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
struct GraphEdge {
    from: String,
    to: String,
    relation: Option<String>,
    proof: Option<String>,
}

fn derivation_output_path() -> Result<PathBuf, Fail> {
    env::var_os("out")
        .map(PathBuf::from)
        .ok_or_else(|| "direct Rust derivation requires the typed out environment path".into())
}

fn resolve_output(out: Option<PathBuf>, derivation_output: bool) -> Result<PathBuf, Fail> {
    match out {
        Some(path) => Ok(path),
        None if derivation_output => derivation_output_path(),
        None => Err("operation requires --out or --derivation-output".into()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CapabilityGraph {
    schema: String,
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LifecycleBounds {
    deadline_ms: u64,
    retry_limit: u32,
    lease_ms: u64,
    cleanup: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CleanupMetadata {
    requested: bool,
    lease_created: bool,
    lease_removed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExecutionResult {
    schema: String,
    adapter: String,
    operation: String,
    status: String,
    attempts: u32,
    bounds: LifecycleBounds,
    dependent_authentication: Value,
    cleanup: CleanupMetadata,
    evidence: Value,
}

fn generating_set() -> Result<Value, Fail> {
    let raw = GENERATING_SET.ok_or("generating-set contract is not projected into the compiled frost-login instrument")?;
    let value = parse_json(raw)?;
    let derivation_generators = value["derivationGenerators"].as_array().ok_or("derivationGenerators must be an array")?;
    let top_level = value["topLevelRoots"].as_array().ok_or("topLevelRoots must be an array")?;
    let runtime_generators = value["runtimeGenerators"].as_array().ok_or("runtimeGenerators must be an array")?;
    let memory_references = value["memoryReferences"].as_array().ok_or("memoryReferences must be an array")?;
    let covered = value["coveredProofObligations"].as_array().ok_or("coveredProofObligations must be an array")?;
    if derivation_generators.len() > 7 || top_level.len() > 7 || runtime_generators.len() > 7 || memory_references.len() > 7 || covered.len() > 7 {
        return Err("generating-set collections must remain Fin7-bounded".into());
    }
    let static_names = derivation_generators.iter().filter_map(|row| row["name"].as_str()).collect::<BTreeSet<_>>();
    let runtime_names = runtime_generators.iter().filter_map(|row| row["name"].as_str()).collect::<BTreeSet<_>>();
    let top_level_names = top_level.iter().map(|row| row.as_str().ok_or("top-level root name must be a string")).collect::<Result<BTreeSet<_>, _>>()?;
    if static_names.len() != derivation_generators.len() || runtime_names.len() != runtime_generators.len() || top_level_names.len() != top_level.len() {
        return Err("generator names must be unique within each generator class".into());
    }
    let mut dependency_names = BTreeSet::new();
    for row in derivation_generators {
        if row["kind"] != "static-drv" || row["phase"] != "static" || row["proofObligations"].as_array().map_or(true, |items| items.len() > 7) {
            return Err("static derivation generators must be bounded static-drv rows".into());
        }
        for dependency in row["dependencies"].as_array().ok_or("static generator dependencies must be arrays")? {
            let dependency = dependency.as_str().ok_or("generator dependency must be a string")?;
            if !static_names.contains(dependency) {
                return Err("static generator dependency escapes the static derivation generator set".into());
            }
            dependency_names.insert(dependency);
        }
    }
    let computed_top_level = static_names.difference(&dependency_names).copied().collect::<BTreeSet<_>>();
    if top_level_names != computed_top_level {
        return Err("topLevelRoots must equal the non-dependent roots of the static derivation DAG".into());
    }
    for row in runtime_generators {
        if row["kind"] != "runtime-command" || row["phase"] != "runtime" || row["proofObligations"].as_array().map_or(true, |items| items.len() > 7) {
            return Err("runtime generators must be bounded runtime-command rows".into());
        }
        for dependency in row["dependencies"].as_array().ok_or("runtime generator dependencies must be arrays")? {
            let dependency = dependency.as_str().ok_or("generator dependency must be a string")?;
            if !static_names.contains(dependency) && !runtime_names.contains(dependency) {
                return Err("runtime generator dependency is not declared".into());
            }
        }
    }
    let expected = proof_obligations()?.into_iter().map(|row| row.name).collect::<BTreeSet<_>>();
    let covered_names = covered.iter().map(|row| row.as_str().ok_or("covered proof obligation must be a string")).collect::<Result<BTreeSet<_>, _>>()?;
    if covered_names != expected.iter().map(String::as_str).collect::<BTreeSet<_>>() {
        return Err("generating set must cover the complete canonical proof-obligation inventory".into());
    }
    if !["PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE", "ERROR", "UNVERIFIED"].contains(&value["minimalityVerdict"].as_str().unwrap_or("")) {
        return Err("minimalityVerdict is not in the Frost verdict algebra".into());
    }
    Ok(value)
}

fn drv_closure() -> Result<Value, Fail> {
    let set = generating_set()?;
    let generators = set["derivationGenerators"].as_array().ok_or("derivationGenerators must be an array")?;
    let top_level_names = set["topLevelRoots"].as_array().ok_or("topLevelRoots must be an array")?;
    let mut by_name = BTreeMap::new();
    for row in generators {
        by_name.insert(row["name"].as_str().ok_or("derivation generator name must be a string")?.to_owned(), row);
    }
    let top_level_rows = top_level_names.iter().map(|name| by_name.get(name.as_str().ok_or("top-level root name must be a string")?).ok_or("top-level root is not a derivation generator").map(|row| (*row).clone())).collect::<Result<Vec<_>, _>>()?;
    let mut pending = top_level_names.iter().map(|name| name.as_str().unwrap_or_default().to_owned()).collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let row = by_name.get(&name).ok_or("derivation closure references an unknown generator")?;
        ordered.push(name);
        for dependency in row["dependencies"].as_array().ok_or("derivation dependencies must be arrays")? {
            pending.push(dependency.as_str().ok_or("derivation dependency must be a string")?.to_owned());
        }
    }
    Ok(json!({
        "schema":"frost-login-derivation-closure-v1",
        "topLevelDrvRoots":top_level_rows,
        "topLevelDrvRootCount":top_level_rows.len(),
        "transitiveDerivationClosure":ordered,
        "runtimeGeneratorsExcludedFromDrvClosure":set["runtimeGenerators"].clone(),
        "minimalityVerdict":set["minimalityVerdict"].clone(),
        "verdict":set["verdict"].clone(),
        "realized":false,
        "providerOrNetworkCalled":false
    }))
}

fn memory_references() -> Result<Value, Fail> {
    Ok(generating_set()?["memoryReferences"].clone())
}

fn proof_generators() -> Result<Value, Fail> {
    let set = generating_set()?;
    Ok(json!({
        "schema":"frost-login-proof-generators-v1",
        "derivationGenerators":set["derivationGenerators"].clone(),
        "topLevelRoots":set["topLevelRoots"].clone(),
        "runtimeGenerators":set["runtimeGenerators"].clone(),
        "coveredProofObligations":set["coveredProofObligations"].clone(),
        "minimalityRule":set["minimalityRule"].clone(),
        "minimalityVerdict":set["minimalityVerdict"].clone(),
        "verdict":set["verdict"].clone()
    }))
}

fn parse_json(value: &str) -> Result<Value, Fail> {
    Ok(serde_json::from_str(value)?)
}

fn parse_optional_json(value: Option<&str>, fallback: Value) -> Result<Value, Fail> {
    match value {
        Some(raw) => parse_json(raw),
        None => Ok(fallback),
    }
}

fn now() -> Result<u128, Fail> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

fn temporary_path(label: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!("{UNIT}-{label}-{}-{sequence}", std::process::id()))
}

const AWS_SSO_BINARY: Option<&str> = option_env!("UNIT_AWS_SSO_BINARY");
const LOGIN_PROVIDERS: [&str; 3] = ["ada-conduit", "aws-sso", "midway"];

fn provider_adapter_class(provider: &str) -> &'static str {
    match provider {
        "aws-sso" => "pinned-nix-derivation",
        "ada-conduit" | "midway" => "authorized-black-box",
        _ => "unregistered",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExecutionWitness {
    status: String,
    exit_code: String,
    observed_at: String,
    evidence_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    schema: String,
    request_id: String,
    provider: String,
    adapter_class: String,
    target_path_kind: String,
    target_path: String,
    witness: ExecutionWitness,
    obligation_discharged: bool,
}

fn validate_login_request(provider: &str, target_path_kind: &str, target_path: &str) -> Result<(), Fail> {
    if !LOGIN_PROVIDERS.contains(&provider) {
        return Err(format!("undeclared login provider: {provider}").into());
    }
    if target_path.is_empty() || target_path_kind.is_empty() {
        return Err("login requires nonempty target-path-kind and target-path".into());
    }
    if target_path.to_ascii_lowercase().contains("value")
        || target_path.to_ascii_lowercase().contains("token")
        || target_path.to_ascii_lowercase().contains("credential")
    {
        return Err("target-path must not contain a value-like term (value/token/credential)".into());
    }
    Ok(())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

async fn run_pinned_binary(binary: &str, args: &[String], deadline_ms: u64) -> Result<(String, i32), Fail> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_clear()
        .envs(child_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_millis(deadline_ms), command.output())
        .await
        .map_err(|_| "login execution deadline exceeded")??;
    let combined = [output.stdout, output.stderr].concat();
    let text = String::from_utf8_lossy(&combined).into_owned();
    Ok((text, output.status.code().unwrap_or(-1)))
}

async fn perform_login(
    provider: &str,
    target_path_kind: &str,
    target_path: &str,
    provider_args: &[String],
    deadline_ms: u64,
) -> Result<LoginResult, Fail> {
    validate_login_request(provider, target_path_kind, target_path)?;
    let adapter_class = provider_adapter_class(provider);
    let request_id = format!("{UNIT}-login-{}", now()?);
    let (evidence_text, exit_code) = match provider {
        "aws-sso" => {
            let binary = AWS_SSO_BINARY.ok_or("aws-sso provider requires the pinned UNIT_AWS_SSO_BINARY build-time path")?;
            let mut args = vec!["sso".to_owned(), "login".to_owned()];
            args.extend_from_slice(provider_args);
            run_pinned_binary(binary, &args, deadline_ms).await?
        }
        "ada-conduit" | "midway" => {
            return Err(format!(
                "provider {provider} is an authorized-black-box adapter and requires a typed AuthorizationRequest before this compiled binary may invoke it; direct invocation is forbidden"
            )
            .into());
        }
        _ => return Err(format!("undeclared login provider: {provider}").into()),
    };
    let witness = ExecutionWitness {
        status: "executed".to_owned(),
        exit_code: exit_code.to_string(),
        observed_at: now()?.to_string(),
        evidence_digest: digest_hex(evidence_text.as_bytes()),
    };
    Ok(LoginResult {
        schema: "store-login-result-v1".to_owned(),
        request_id,
        provider: provider.to_owned(),
        adapter_class: adapter_class.to_owned(),
        target_path_kind: target_path_kind.to_owned(),
        target_path: target_path.to_owned(),
        witness,
        obligation_discharged: exit_code == 0,
    })
}

fn persist_login_result(result: &LoginResult, directory: &Path) -> Result<(), Fail> {
    fs::create_dir_all(directory)?;
    let database = Database::create(directory.join("state.redb"))?;
    let write = database.begin_write()?;
    {
        let mut table = write.open_table(LOGIN_RESULTS)?;
        table.insert(
            result.request_id.as_str(),
            serde_json::to_string(&redact(&serde_json::to_value(result)?))?.as_str(),
        )?;
    }
    write.commit()?;
    fs::write(
        directory.join(format!("{}.json", result.request_id)),
        serde_json::to_vec_pretty(&redact(&serde_json::to_value(result)?))?,
    )?;
    Ok(())
}

fn read_login_status(request_id: &str, directory: &Path) -> Result<LoginResult, Fail> {
    let path = directory.join(format!("{request_id}.json"));
    if !path.exists() {
        return Err(format!("no login result record found: {request_id}").into());
    }
    let result: LoginResult = serde_json::from_slice(&fs::read(path)?)?;
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IdentityWitness {
    status: String,
    exit_code: String,
    observed_at: String,
    resolved_account_digest: String,
    account_matches_expectation: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IdentityVerificationResult {
    schema: String,
    target_path: String,
    expected_account: String,
    witness: IdentityWitness,
    identity_obligation_discharged: bool,
}

fn extract_account_from_identity_output(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    value.get("Account").and_then(Value::as_str).map(str::to_owned)
}

async fn perform_sts_identity_check(
    target_path: &str,
    expected_account: &str,
    provider_args: &[String],
    deadline_ms: u64,
) -> Result<IdentityVerificationResult, Fail> {
    if expected_account.is_empty() || target_path.is_empty() {
        return Err("sts-identity requires nonempty target-path and expected-account".into());
    }
    let binary = AWS_SSO_BINARY.ok_or("sts-identity requires the pinned UNIT_AWS_SSO_BINARY build-time path")?;
    let mut args = vec!["sts".to_owned(), "get-caller-identity".to_owned()];
    args.extend_from_slice(provider_args);
    let (evidence_text, exit_code) = run_pinned_binary(binary, &args, deadline_ms).await?;
    let resolved_account = extract_account_from_identity_output(&evidence_text);
    let account_matches_expectation = resolved_account.as_deref() == Some(expected_account);
    let witness = IdentityWitness {
        status: "executed".to_owned(),
        exit_code: exit_code.to_string(),
        observed_at: now()?.to_string(),
        resolved_account_digest: digest_hex(resolved_account.unwrap_or_default().as_bytes()),
        account_matches_expectation,
    };
    Ok(IdentityVerificationResult {
        schema: "store-identity-verification-result-v1".to_owned(),
        target_path: target_path.to_owned(),
        expected_account: expected_account.to_owned(),
        identity_obligation_discharged: exit_code == 0 && account_matches_expectation,
        witness,
    })
}

fn validate_boundary() -> Result<(), Fail> {
    if env::var("CONVERGENT_CLEAN_BOUNDARY").as_deref() != Ok("1") {
        return Err("compiled dispatch did not enter the clean environment boundary".into());
    }
    if env::var("LC_ALL").as_deref() != Ok("C") || env::var("TZ").as_deref() != Ok("UTC") {
        return Err("typed environment projection differs from the frozen contract".into());
    }
    if env::var_os("UNIT_UNDECLARED_SENTINEL").is_some() {
        return Err("undeclared environment sentinel crossed the clean boundary".into());
    }
    Ok(())
}

fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '_'], "");
    matches!(
        normalized.as_str(),
        "secret"
            | "secretvalue"
            | "token"
            | "tokenvalue"
            | "password"
            | "passwordvalue"
            | "credential"
            | "credentialvalue"
            | "cookie"
            | "cookievalue"
            | "privatekey"
            | "accesskey"
            | "sessionvalue"
    )
}

fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| !sensitive_key(key))
                .map(|(key, value)| (key.clone(), redact(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact).collect()),
        other => other.clone(),
    }
}

fn event(
    operation: &str,
    plane: Option<&str>,
    theorem: Option<&str>,
    timestamp_unix_ms: u128,
) -> Result<Event, Fail> {
    Ok(Event {
        schema: "store-event-v3".to_owned(),
        timestamp_unix_ms,
        unit: UNIT.to_owned(),
        identity: IDENTITY.to_owned(),
        operation: operation.to_owned(),
        status: "pass".to_owned(),
        plane: plane.map(str::to_owned),
        theorem: theorem.map(str::to_owned),
        evidence: redact(&json!({
            "authentication": parse_json(AUTHENTICATION)?,
            "interface": parse_json(INTERFACE)?,
            "repository": parse_json(REPOSITORY)?,
            "runtime": parse_json(RUNTIME)?,
            "contractDigest": parse_json(CONTRACT_JSON)?["contentHash"]
        })),
    })
}

fn theorem_exists(plane: &str, theorem: &str) -> Result<bool, Fail> {
    let catalog = parse_json(THEOREMS)?;
    Ok(catalog
        .get(plane)
        .and_then(Value::as_array)
        .map(|rows| rows.iter().any(|row| row.as_str() == Some(theorem)))
        .unwrap_or(false))
}

fn lifecycle_exists(operation: &str) -> Result<bool, Fail> {
    Ok(parse_json(LIFECYCLE)?
        .as_array()
        .map(|rows| rows.iter().any(|row| row["name"].as_str() == Some(operation)))
        .unwrap_or(false))
}

fn write_event(out: &Path, value: &Event) -> Result<(), Fail> {
    fs::create_dir_all(out)?;
    let safe = redact(&serde_json::to_value(value)?);
    let payload = serde_json::to_string(&safe)?;
    let database = Database::create(out.join("state.redb"))?;
    let write = database.begin_write()?;
    {
        let mut table = write.open_table(EVENTS)?;
        table.insert(value.timestamp_unix_ms as u64, payload.as_str())?;
    }
    write.commit()?;
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&safe)?)?;
    Ok(())
}

fn write_contract(out: &Path) -> Result<(), Fail> {
    fs::create_dir_all(out)?;
    let database = Database::create(out.join("contract.redb"))?;
    let write = database.begin_write()?;
    {
        let mut table = write.open_table(CONTRACT)?;
        table.insert("root", CONTRACT_JSON)?;
        table.insert("identity", IDENTITY)?;
    }
    write.commit()?;
    fs::write(
        out.join("contract.json"),
        serde_json::to_vec_pretty(&parse_json(CONTRACT_JSON)?)?,
    )?;
    Ok(())
}

fn emit(value: Value, out: Option<PathBuf>, operation: &str) -> Result<(), Fail> {
    let safe = redact(&value);
    if let Some(path) = out {
        let record = event(operation, None, None, now()?)?;
        write_event(&path, &record)?;
        fs::write(path.join("value.json"), serde_json::to_vec_pretty(&safe)?)?;
    } else {
        println!("{}", serde_json::to_string(&safe)?);
    }
    Ok(())
}

fn child_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("CONVERGENT_CLEAN_BOUNDARY".to_owned(), "1".to_owned()),
        ("LC_ALL".to_owned(), "C".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
    ])
}

async fn enter_clean_boundary() -> Result<Option<ExitCode>, Fail> {
    if env::var("CONVERGENT_CLEAN_BOUNDARY").as_deref() == Ok("1") {
        return Ok(None);
    }
    let mut command = Command::new(env::current_exe()?);
    command
        .args(env::args_os().skip(1))
        .env_clear()
        .envs(child_environment())
        .kill_on_drop(true);
    let status = command.status().await?;
    Ok(Some(ExitCode::from(status.code().unwrap_or(1) as u8)))
}

fn contract(action: Option<ContractAction>) -> Result<(), Fail> {
    match action.unwrap_or(ContractAction::Show) {
        ContractAction::Show => println!("{CONTRACT_JSON}"),
        ContractAction::Persist { out, derivation_output } => write_contract(&resolve_output(out, derivation_output)?)?,
        ContractAction::Prove {
            plane,
            theorem,
            out,
            derivation_output,
        } => {
            if !theorem_exists(&plane, &theorem)? {
                return Err(format!("unsolved or undeclared theorem: {plane}.{theorem}").into());
            }
            let value = event("prove", Some(&plane), Some(&theorem), 0)?;
            let path = resolve_output(out, derivation_output)?;
            write_event(&path, &value)?;
        }
    }
    Ok(())
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn cargo_fields(contents: &str) -> (String, String, String, BTreeMap<String, String>) {
    let mut section = String::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut edition = String::new();
    let mut dependencies = BTreeMap::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if section == "package" {
            match key {
                "name" => name = unquote(value),
                "version" => version = unquote(value),
                "edition" => edition = unquote(value),
                _ => {}
            }
        } else if section == "dependencies" {
            dependencies.insert(key.to_owned(), value.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    (name, version, edition, dependencies)
}

fn collect_rust_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<(), Fail> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("source inspector rejects symlink: {}", path.display()).into());
        }
        if metadata.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), ".git" | ".jj" | "target" | "build") {
                continue;
            }
            collect_rust_files(root, &path, files)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            let relative = path.strip_prefix(root)?.to_path_buf();
            files.push(relative);
        }
    }
    Ok(())
}

fn inspect_source(path: &Path, adapter_name: &str) -> Result<SourceInspection, Fail> {
    let adapter = find_adapter(adapter_name)?;
    if adapter.kind != "source-inspector" || !adapter.operations.iter().any(|value| value == "inspect") {
        return Err(format!("adapter does not support source inspection: {adapter_name}").into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("source inspection path must be an explicit non-symlink directory".into());
    }
    let cargo_path = path.join("Cargo.toml");
    let lock_path = path.join("Cargo.lock");
    if !cargo_path.is_file() || !lock_path.is_file() {
        return Err("source inspection requires Cargo.toml and Cargo.lock".into());
    }
    let cargo = fs::read_to_string(&cargo_path)?;
    let lock = fs::read_to_string(&lock_path)?;
    let (package_name, package_version, edition, dependencies) = cargo_fields(&cargo);
    if package_name.is_empty() || package_version.is_empty() || edition.is_empty() {
        return Err("Cargo package name, version, and edition are required".into());
    }
    let mut paths = Vec::new();
    collect_rust_files(path, path, &mut paths)?;
    paths.sort();
    let mut files = Vec::new();
    for relative in paths {
        let bytes = fs::read(path.join(&relative))?;
        let contents = String::from_utf8(bytes.clone())?;
        let functions = contents
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("fn ")
                    || line.starts_with("pub fn ")
                    || line.starts_with("async fn ")
                    || line.starts_with("pub async fn ")
            })
            .count() as u64;
        let tests = contents
            .lines()
            .filter(|line| matches!(line.trim(), "#[test]" | "#[tokio::test]"))
            .count() as u64;
        files.push(SourceFileInspection {
            path: relative.to_string_lossy().replace('\\', "/"),
            kind: "rust".to_owned(),
            bytes: bytes.len() as u64,
            lines: contents.lines().count() as u64,
            functions,
            tests,
        });
    }
    Ok(SourceInspection {
        schema: "store-source-inspection-v1".to_owned(),
        adapter: adapter.name,
        root: ".".to_owned(),
        package_name,
        package_version,
        edition,
        dependencies,
        lock_packages: lock.lines().filter(|line| *line == "[[package]]").count() as u64,
        files,
        compile_source_contract: parse_json(SOURCE)?,
    })
}

fn default_adapters() -> Vec<AdapterContract> {
    vec![
        AdapterContract {
            name: "deterministic-renderer".to_owned(),
            kind: "renderer".to_owned(),
            operations: vec!["elaborate", "graph", "obligations", "render", "solve"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            scopes: Vec::new(),
            max_lifetime_ms: 0,
            max_deadline_ms: DEFAULT_DEADLINE_MS,
            max_retries: 0,
            fake: false,
            metadata: Value::Null,
        },
        AdapterContract {
            name: "fake-dependent-auth".to_owned(),
            kind: "dependent-authentication".to_owned(),
            operations: vec![
                "materialize",
                "edit",
                "capture",
                "freeze",
                "build",
                "activate",
                "publish",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            scopes: vec!["read-contract".to_owned(), "run-fake".to_owned()],
            max_lifetime_ms: 5_000,
            max_deadline_ms: 10_000,
            max_retries: 2,
            fake: true,
            metadata: json!({"authority": "store-v3", "credentialMaterial": "forbidden"}),
        },
        AdapterContract {
            name: "rust-cargo-inspector".to_owned(),
            kind: "source-inspector".to_owned(),
            operations: vec!["analyze", "inspect"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            scopes: Vec::new(),
            max_lifetime_ms: 0,
            max_deadline_ms: DEFAULT_DEADLINE_MS,
            max_retries: 0,
            fake: false,
            metadata: Value::Null,
        },
    ]
}

fn adapters() -> Result<Vec<AdapterContract>, Fail> {
    let mut rows = default_adapters();
    if let Some(raw) = ADAPTERS {
        let value = parse_json(raw)?;
        let declared = value
            .get("adapters")
            .and_then(Value::as_array)
            .or_else(|| value.as_array())
            .ok_or("UNIT_ADAPTERS must be an array or contain adapters")?;
        for row in declared {
            let name = row.get("name").and_then(Value::as_str).unwrap_or_default();
            let class = row
                .get("class")
                .or_else(|| row.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let execution = row
                .get("execution")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name.is_empty() || class.is_empty() || execution.is_empty() {
                return Err("central adapters require name, class, and execution".into());
            }
            rows.push(AdapterContract {
                name: name.to_owned(),
                kind: format!("declared-{class}"),
                operations: vec![execution.to_owned()],
                scopes: Vec::new(),
                max_lifetime_ms: 0,
                max_deadline_ms: MAX_DEADLINE_MS,
                max_retries: 0,
                fake: false,
                metadata: redact(row),
            });
        }
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = BTreeSet::new();
    for row in &mut rows {
        row.operations.sort();
        row.operations.dedup();
        row.scopes.sort();
        row.scopes.dedup();
        if row.name.is_empty() || !names.insert(row.name.clone()) {
            return Err("adapter names must be nonempty and unique".into());
        }
    }
    Ok(rows)
}

fn find_adapter(name: &str) -> Result<AdapterContract, Fail> {
    adapters()?
        .into_iter()
        .find(|adapter| adapter.name == name)
        .ok_or_else(|| format!("unknown adapter rejected: {name}").into())
}

fn compile_environment_inventory() -> Value {
    let optional_values = [
        THEOREM_CHANNELS,
        GRAPH_NODES,
        GRAPH_EDGES,
        ADAPTERS,
        HYPOTHESES,
        OBLIGATIONS,
        EXECUTIONS,
        LIFECYCLE_LIMITS,
        AUTH_CAPABILITY_DEPENDENCIES,
    ];
    json!({
        "required": REQUIRED_COMPILE_ENVIRONMENT,
        "optional": OPTIONAL_COMPILE_ENVIRONMENT.iter().zip(optional_values).map(|(name, value)| json!({
            "name": name,
            "integrated": value.is_some()
        })).collect::<Vec<_>>()
    })
}

fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::Object(values)) => values
            .values()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn hypothesis_rows(value: Value, source: &str) -> Result<Vec<Hypothesis>, Fail> {
    let rows = value
        .get("hypotheses")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .ok_or("hypothesis contract must be an array or contain hypotheses")?;
    let mut result = Vec::new();
    for row in rows {
        let id = row
            .get("id")
            .or_else(|| row.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let statement = row
            .get("statement")
            .or_else(|| row.get("hypothesis"))
            .or_else(|| row.get("claim"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if id.is_empty() || statement.is_empty() {
            return Err("hypotheses require nonempty id and statement".into());
        }
        let mut provenance = strings(row.get("provenance"));
        provenance.extend(
            ["adapter", "obligation"]
                .into_iter()
                .filter_map(|key| row.get(key).and_then(Value::as_str))
                .map(|value| format!("contract:{value}")),
        );
        provenance.push(source.to_owned());
        provenance.sort();
        provenance.dedup();
        let mut evidence = strings(row.get("evidence"));
        evidence.extend(
            ["injectedBehavior", "discriminatingObservation"]
                .into_iter()
                .filter_map(|key| row.get(key).and_then(Value::as_str))
                .map(str::to_owned),
        );
        evidence.sort();
        evidence.dedup();
        result.push(Hypothesis {
            id: id.to_owned(),
            statement: statement.to_owned(),
            status: row
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unresolved")
                .to_owned(),
            provenance,
            evidence,
        });
    }
    Ok(result)
}

fn derived_hypotheses(inspection: &SourceInspection) -> Vec<Hypothesis> {
    let rust_files = inspection.files.len();
    let tests = inspection.files.iter().map(|file| file.tests).sum::<u64>();
    vec![
        Hypothesis {
            id: "cargo-contract-present".to_owned(),
            statement: "Cargo manifest and lock are present and parseable".to_owned(),
            status: "observed".to_owned(),
            provenance: vec!["rust-cargo-inspector:Cargo.toml".to_owned(), "rust-cargo-inspector:Cargo.lock".to_owned()],
            evidence: vec![format!("lock-packages={}", inspection.lock_packages)],
        },
        Hypothesis {
            id: "rust-source-present".to_owned(),
            statement: "Rust source files are present in the supplied inspection boundary".to_owned(),
            status: "observed".to_owned(),
            provenance: vec!["rust-cargo-inspector:rust-files".to_owned()],
            evidence: vec![format!("rust-files={rust_files}"), format!("tests={tests}")],
        },
    ]
}

fn merge_hypotheses(groups: Vec<Vec<Hypothesis>>) -> Result<Vec<Hypothesis>, Fail> {
    let mut merged: BTreeMap<String, Hypothesis> = BTreeMap::new();
    for group in groups {
        for row in group {
            if let Some(current) = merged.get_mut(&row.id) {
                if current.statement != row.statement {
                    return Err(format!("hypothesis statement conflict: {}", row.id).into());
                }
                current.provenance.extend(row.provenance);
                current.evidence.extend(row.evidence);
                current.provenance.sort();
                current.provenance.dedup();
                current.evidence.sort();
                current.evidence.dedup();
                if current.status != row.status {
                    current.status = "contested".to_owned();
                }
            } else {
                merged.insert(row.id.clone(), row);
            }
        }
    }
    Ok(merged.into_values().collect())
}

fn load_hypotheses(file: Option<&Path>, derived: Vec<Hypothesis>) -> Result<Vec<Hypothesis>, Fail> {
    let mut groups = vec![derived];
    if let Some(raw) = HYPOTHESES {
        groups.push(hypothesis_rows(parse_json(raw)?, "compile:UNIT_HYPOTHESES")?);
    }
    if let Some(path) = file {
        groups.push(hypothesis_rows(
            serde_json::from_slice(&fs::read(path)?)?,
            "request:hypotheses",
        )?);
    }
    merge_hypotheses(groups)
}

fn default_obligations() -> Vec<Obligation> {
    vec![
        Obligation {
            id: "adapter-known".to_owned(),
            statement: "Every requested adapter is declared".to_owned(),
            status: "satisfied".to_owned(),
            dependencies: Vec::new(),
            evidence: vec!["adapter-inventory".to_owned()],
        },
        Obligation {
            id: "dependent-auth-bounded".to_owned(),
            statement: "Dependent authentication scope and lifetime are bounded".to_owned(),
            status: "open".to_owned(),
            dependencies: vec!["adapter-known".to_owned()],
            evidence: Vec::new(),
        },
        Obligation {
            id: "runtime-graph-nonleaf-checked".to_owned(),
            statement: "Runtime nonleaf graph nodes declare checks".to_owned(),
            status: "open".to_owned(),
            dependencies: vec!["adapter-known".to_owned()],
            evidence: Vec::new(),
        },
    ]
}

fn obligations() -> Result<Vec<Obligation>, Fail> {
    let mut rows = default_obligations();
    if let Some(raw) = OBLIGATIONS {
        let value = parse_json(raw)?;
        let declared = value
            .get("obligations")
            .and_then(Value::as_array)
            .or_else(|| value.as_array())
            .ok_or("UNIT_OBLIGATIONS must be an array or contain obligations")?;
        for row in declared {
            let id = row
                .get("id")
                .or_else(|| row.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let statement = row.get("statement").and_then(Value::as_str).unwrap_or_default();
            if id.is_empty() || statement.is_empty() {
                return Err("central obligations require name and statement".into());
            }
            let static_verdict = row
                .pointer("/staticGate/verdict")
                .and_then(Value::as_str)
                .unwrap_or("UNVERIFIED");
            let runtime_policy = row
                .pointer("/runtimeGate/policy")
                .and_then(Value::as_str)
                .unwrap_or("required");
            let runtime_verdict = row
                .pointer("/runtimeGate/verdict")
                .and_then(Value::as_str)
                .unwrap_or("UNVERIFIED");
            let status = row
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    if static_verdict == "PASS"
                        && (runtime_policy == "not-required" || runtime_verdict == "PASS")
                    {
                        "satisfied".to_owned()
                    } else {
                        "open".to_owned()
                    }
                });
            let mut evidence = strings(row.get("evidence"));
            if let Some(plane) = row.get("plane").and_then(Value::as_str) {
                evidence.push(format!("plane:{plane}"));
            }
            if let Some(solver) = row.pointer("/solver/_tag").and_then(Value::as_str) {
                evidence.push(format!("solver:{solver}"));
            }
            rows.push(Obligation {
                id: id.to_owned(),
                statement: statement.to_owned(),
                status,
                dependencies: strings(row.get("dependencies")),
                evidence,
            });
        }
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let ids = rows.iter().map(|row| row.id.clone()).collect::<BTreeSet<_>>();
    if ids.len() != rows.len() || rows.iter().any(|row| row.id.is_empty() || row.statement.is_empty()) {
        return Err("obligations require unique nonempty ids and statements".into());
    }
    for row in &mut rows {
        row.dependencies.sort();
        row.dependencies.dedup();
        row.evidence.sort();
        row.evidence.dedup();
        if row.dependencies.iter().any(|dependency| !ids.contains(dependency)) {
            return Err(format!("obligation has unknown dependency: {}", row.id).into());
        }
    }
    Ok(rows)
}

fn solved_status(status: &str) -> bool {
    matches!(status.to_ascii_lowercase().as_str(), "pass" | "satisfied" | "solved")
}

fn solve_request(rows: &[Obligation], id: &str, mut evidence: Vec<String>) -> Result<Value, Fail> {
    let row = rows
        .iter()
        .find(|row| row.id == id)
        .ok_or_else(|| format!("unknown obligation: {id}"))?;
    let by_id = rows.iter().map(|row| (&row.id, row)).collect::<BTreeMap<_, _>>();
    let mut blockers = row
        .dependencies
        .iter()
        .filter(|dependency| {
            by_id
                .get(dependency)
                .map(|row| !solved_status(&row.status))
                .unwrap_or(true)
        })
        .cloned()
        .collect::<Vec<_>>();
    evidence.retain(|item| !item.trim().is_empty());
    evidence.sort();
    evidence.dedup();
    if evidence.is_empty() {
        blockers.push("evidence-required".to_owned());
    }
    blockers.sort();
    blockers.dedup();
    Ok(json!({
        "schema": "store-solve-request-v1",
        "obligation": id,
        "status": if blockers.is_empty() { "ready" } else { "blocked" },
        "blockers": blockers,
        "evidence": evidence
    }))
}

fn default_graph() -> CapabilityGraph {
    CapabilityGraph {
        schema: "store-capability-graph-v1".to_owned(),
        nodes: vec![
            GraphNode {
                id: "inspect".to_owned(),
                kind: "analysis".to_owned(),
                plane: Some("contract".to_owned()),
                immutable_root: false,
                runtime_witness: false,
                nonleaf_check: None,
            },
            GraphNode {
                id: "elaborate".to_owned(),
                kind: "analysis".to_owned(),
                plane: Some("contract".to_owned()),
                immutable_root: false,
                runtime_witness: false,
                nonleaf_check: None,
            },
            GraphNode {
                id: "solve".to_owned(),
                kind: "obligation".to_owned(),
                plane: Some("governance".to_owned()),
                immutable_root: false,
                runtime_witness: false,
                nonleaf_check: None,
            },
            GraphNode {
                id: "execute".to_owned(),
                kind: "runtime".to_owned(),
                plane: Some("runtime".to_owned()),
                immutable_root: false,
                runtime_witness: true,
                nonleaf_check: Some("bounded-runtime-children".to_owned()),
            },
            GraphNode {
                id: "evidence".to_owned(),
                kind: "artifact".to_owned(),
                plane: Some("runtime".to_owned()),
                immutable_root: false,
                runtime_witness: false,
                nonleaf_check: None,
            },
        ],
        edges: vec![
            GraphEdge { from: "inspect".to_owned(), to: "elaborate".to_owned(), relation: Some("derives".to_owned()), proof: Some("typed-inspection".to_owned()) },
            GraphEdge { from: "elaborate".to_owned(), to: "solve".to_owned(), relation: Some("generates".to_owned()), proof: Some("provenance-merge".to_owned()) },
            GraphEdge { from: "solve".to_owned(), to: "execute".to_owned(), relation: Some("gates".to_owned()), proof: Some("obligation-gating".to_owned()) },
            GraphEdge { from: "execute".to_owned(), to: "evidence".to_owned(), relation: Some("produces".to_owned()), proof: Some("bounded-runtime-children".to_owned()) },
        ],
    }
}

fn capability_graph() -> Result<CapabilityGraph, Fail> {
    let mut graph = match (GRAPH_NODES, GRAPH_EDGES) {
        (None, None) => default_graph(),
        (Some(node_raw), Some(edge_raw)) => {
            let node_groups = parse_json(node_raw)?;
            let edge_groups = parse_json(edge_raw)?;
            let node_groups = node_groups.as_array().ok_or("UNIT_GRAPH_NODES must be an array")?;
            let edge_groups = edge_groups.as_array().ok_or("UNIT_GRAPH_EDGES must be an array")?;
            let mut nodes = Vec::new();
            let mut edges = Vec::new();
            for group in node_groups {
                let members = group
                    .get("members")
                    .and_then(Value::as_array)
                    .ok_or("graph node groups require members")?;
                for row in members {
                    let id = row.get("name").and_then(Value::as_str).unwrap_or_default();
                    let kind = row.get("kind").and_then(Value::as_str).unwrap_or_default();
                    if id.is_empty() || kind.is_empty() {
                        return Err("graph nodes require name and kind".into());
                    }
                    nodes.push(GraphNode {
                        id: id.to_owned(),
                        kind: kind.to_owned(),
                        plane: row.get("plane").and_then(Value::as_str).map(str::to_owned),
                        immutable_root: row.get("immutableRoot").and_then(Value::as_bool).unwrap_or(false),
                        runtime_witness: row.get("runtimeWitness").and_then(Value::as_bool).unwrap_or(false),
                        nonleaf_check: None,
                    });
                }
            }
            for group in edge_groups {
                let members = group
                    .get("members")
                    .and_then(Value::as_array)
                    .ok_or("graph edge groups require members")?;
                for row in members {
                    let from = row.get("from").and_then(Value::as_str).unwrap_or_default();
                    let to = row.get("to").and_then(Value::as_str).unwrap_or_default();
                    if from.is_empty() || to.is_empty() {
                        return Err("graph edges require from and to".into());
                    }
                    edges.push(GraphEdge {
                        from: from.to_owned(),
                        to: to.to_owned(),
                        relation: row.get("relation").and_then(Value::as_str).map(str::to_owned),
                        proof: row.get("proof").and_then(Value::as_str).map(str::to_owned),
                    });
                }
            }
            for node in &mut nodes {
                if node.runtime_witness && edges.iter().any(|edge| edge.from == node.id) {
                    let proofs = edges
                        .iter()
                        .filter(|edge| edge.from == node.id)
                        .filter_map(|edge| edge.proof.clone())
                        .collect::<BTreeSet<_>>();
                    if !proofs.is_empty() {
                        node.nonleaf_check = Some(proofs.into_iter().collect::<Vec<_>>().join("+"));
                    }
                }
            }
            CapabilityGraph {
                schema: "store-capability-graph-v1".to_owned(),
                nodes,
                edges,
            }
        }
        _ => return Err("UNIT_GRAPH_NODES and UNIT_GRAPH_EDGES must be supplied together".into()),
    };
    graph.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    graph.edges.sort();
    graph.edges.dedup();
    validate_graph(&graph)?;
    Ok(graph)
}

fn validate_graph(graph: &CapabilityGraph) -> Result<(), Fail> {
    let ids = graph.nodes.iter().map(|node| node.id.clone()).collect::<BTreeSet<_>>();
    if ids.len() != graph.nodes.len() || graph.nodes.iter().any(|node| node.id.is_empty()) {
        return Err("graph node ids must be nonempty and unique".into());
    }
    for edge in &graph.edges {
        if !ids.contains(&edge.from) || !ids.contains(&edge.to) {
            return Err(format!("graph edge has unknown endpoint: {} -> {}", edge.from, edge.to).into());
        }
    }
    for node in &graph.nodes {
        let nonleaf = graph.edges.iter().any(|edge| edge.from == node.id);
        if node.runtime_witness && node.immutable_root {
            return Err(format!("runtime witness cannot be an immutable grounding root: {}", node.id).into());
        }
        if (node.kind == "runtime" || node.runtime_witness)
            && nonleaf
            && node.nonleaf_check.as_deref().map(str::is_empty).unwrap_or(true)
        {
            return Err(format!("runtime nonleaf lacks check: {}", node.id).into());
        }
    }
    Ok(())
}

fn validate_bounds(bounds: &LifecycleBounds) -> Result<(), Fail> {
    if bounds.deadline_ms == 0 || bounds.deadline_ms > MAX_DEADLINE_MS {
        return Err(format!("deadline must be within 1..={MAX_DEADLINE_MS} ms").into());
    }
    if bounds.retry_limit > MAX_RETRIES {
        return Err(format!("retry limit must be within 0..={MAX_RETRIES}").into());
    }
    if bounds.lease_ms == 0 || bounds.lease_ms > MAX_LEASE_MS || bounds.lease_ms > bounds.deadline_ms {
        return Err("lease must be nonzero, globally bounded, and no longer than the deadline".into());
    }
    Ok(())
}

fn validate_lifecycle_contract(operation: &str, bounds: &LifecycleBounds) -> Result<(), Fail> {
    validate_bounds(bounds)?;
    if let Some(raw) = LIFECYCLE_LIMITS {
        let rows = parse_json(raw)?;
        let rows = rows.as_array().ok_or("UNIT_LIFECYCLE_LIMITS must be an array")?;
        let row = rows
            .iter()
            .find(|row| row.get("lifecycle").and_then(Value::as_str) == Some(operation))
            .ok_or_else(|| format!("missing lifecycle limit contract: {operation}"))?;
        let timeout_seconds = row
            .pointer("/limits/timeoutSeconds")
            .and_then(Value::as_u64)
            .ok_or("lifecycle timeoutSeconds is required")?;
        let retries = row
            .pointer("/limits/retries")
            .and_then(Value::as_u64)
            .ok_or("lifecycle retries is required")?;
        if bounds.deadline_ms > timeout_seconds.saturating_mul(1_000) {
            return Err(format!("deadline exceeds lifecycle contract: {operation}").into());
        }
        if u64::from(bounds.retry_limit) > retries {
            return Err(format!("retry limit exceeds lifecycle contract: {operation}").into());
        }
    }
    Ok(())
}

fn validate_adapter_request(
    adapter: &AdapterContract,
    operation: &str,
    scopes: &[String],
    auth_lifetime_ms: u64,
    bounds: &LifecycleBounds,
) -> Result<(), Fail> {
    validate_bounds(bounds)?;
    if !adapter.operations.iter().any(|item| item == operation) {
        return Err(format!("adapter {} rejects operation {operation}", adapter.name).into());
    }

    if bounds.deadline_ms > adapter.max_deadline_ms || bounds.retry_limit > adapter.max_retries {
        return Err(format!("request exceeds adapter execution bounds: {}", adapter.name).into());
    }
    if adapter.kind == "dependent-authentication" {
        if !adapter.fake {
            return Err("only fake dependent authentication capabilities are executable".into());
        }
        if auth_lifetime_ms == 0
            || auth_lifetime_ms > adapter.max_lifetime_ms
            || auth_lifetime_ms > bounds.lease_ms
        {
            return Err("dependent authentication lifetime exceeds capability or lease bounds".into());
        }
        let allowed = adapter.scopes.iter().collect::<BTreeSet<_>>();
        if scopes.is_empty() || scopes.iter().any(|scope| !allowed.contains(scope)) {
            return Err("dependent authentication scope is empty or outside the adapter allow set".into());
        }
    } else if auth_lifetime_ms != 0 || !scopes.is_empty() {
        return Err("authentication parameters require a dependent-authentication adapter".into());
    }
    Ok(())
}

fn dependent_auth_capability(adapter: &AdapterContract, scopes: &[String], lifetime_ms: u64) -> Value {
    let mut scopes = scopes.to_vec();
    scopes.sort();
    scopes.dedup();
    json!({
        "schema": "store-fake-dependent-auth-v1",
        "adapter": adapter.name,
        "provider": "fake",
        "scopes": scopes,
        "lifetimeMs": lifetime_ms,
        "storage": "none",
        "credentialMaterial": false,
        "ambientSentinelPresent": env::var_os("UNIT_SECRET_SENTINEL").is_some()
    })
}

fn create_lease(directory: &Path, operation: &str, bounds: &LifecycleBounds) -> Result<PathBuf, Fail> {
    fs::create_dir_all(directory)?;
    let path = directory.join("lease.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "schema": "store-runtime-lease-v1",
            "operation": operation,
            "leaseMs": bounds.lease_ms,
            "deadlineMs": bounds.deadline_ms
        }))?,
    )?;
    Ok(path)
}

fn cleanup_lease(path: &Path, requested: bool) -> Result<bool, Fail> {
    if !requested {
        return Ok(false);
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(!path.exists())
}

async fn run_adapter_child(
    adapter: &AdapterContract,
    operation: &str,
    scopes: &[String],
    auth_lifetime_ms: u64,
    remaining: Duration,
) -> Result<Value, Fail> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("adapter-child")
        .arg("--adapter")
        .arg(&adapter.name)
        .arg("--operation")
        .arg(operation)
        .arg("--auth-lifetime-ms")
        .arg(auth_lifetime_ms.to_string())
        .env_clear()
        .envs(child_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for scope in scopes {
        command.arg("--scope").arg(scope);
    }
    let output = timeout(remaining, command.output())
        .await
        .map_err(|_| "adapter execution deadline exceeded")??;
    if !output.status.success() {
        return Err(format!(
            "adapter child failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(redact(&serde_json::from_slice(&output.stdout)?))
}

async fn execute_runtime(
    adapter_name: &str,
    operation: &str,
    scopes: Vec<String>,
    auth_lifetime_ms: u64,
    bounds: LifecycleBounds,
    out: Option<PathBuf>,
) -> Result<(), Fail> {
    let adapter = find_adapter(adapter_name)?;
    if adapter.kind != "dependent-authentication" || !adapter.fake {
        return Err(format!("adapter is inventory-only and not runtime-executable: {adapter_name}").into());
    }
    if !lifecycle_exists(operation)? {
        return Err(format!("undeclared lifecycle operation: {operation}").into());
    }
    validate_lifecycle_contract(operation, &bounds)?;
    validate_adapter_request(&adapter, operation, &scopes, auth_lifetime_ms, &bounds)?;
    let execution_contract = json!({
        "executions": parse_optional_json(EXECUTIONS, json!([]))?,
        "lifecycleLimits": parse_optional_json(LIFECYCLE_LIMITS, json!([]))?,
        "globalBounds": {
            "deadlineMaximumMs": MAX_DEADLINE_MS,
            "retryMaximum": MAX_RETRIES,
            "leaseMaximumMs": MAX_LEASE_MS
        }
    });
    let dependent_contract = parse_optional_json(AUTH_CAPABILITY_DEPENDENCIES, json!([{
        "capability": "fake-dependent-auth",
        "mode": "fake-only",
        "credentialPersistence": "forbidden"
    }]))?;
    let runtime_directory = out.clone().unwrap_or_else(|| temporary_path("runtime"));
    let lease = create_lease(&runtime_directory, operation, &bounds)?;
    let started = Instant::now();
    let deadline = Duration::from_millis(bounds.deadline_ms);
    let mut attempts = 0;
    let mut last_error = None;
    let mut evidence = None;
    while attempts <= bounds.retry_limit {
        attempts += 1;
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            last_error = Some("adapter execution deadline exceeded".to_owned());
            break;
        }
        match run_adapter_child(
            &adapter,
            operation,
            &scopes,
            auth_lifetime_ms,
            deadline - elapsed,
        )
        .await
        {
            Ok(value) => {
                evidence = Some(value);
                break;
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    let lease_removed = cleanup_lease(&lease, bounds.cleanup)?;
    let cleanup = CleanupMetadata {
        requested: bounds.cleanup,
        lease_created: true,
        lease_removed,
    };
    if evidence.is_none() {
        if out.is_none() && bounds.cleanup {
            let _ = fs::remove_dir_all(&runtime_directory);
        }
        return Err(last_error.unwrap_or_else(|| "adapter execution failed".to_owned()).into());
    }
    let result = ExecutionResult {
        schema: "store-bounded-execution-v1".to_owned(),
        adapter: adapter.name.clone(),
        operation: operation.to_owned(),
        status: "pass".to_owned(),
        attempts,
        bounds,
        dependent_authentication: redact(&json!({
            "capability": dependent_auth_capability(&adapter, &scopes, auth_lifetime_ms),
            "contract": dependent_contract
        })),
        cleanup,
        evidence: redact(&json!({
            "adapter": evidence,
            "executionContract": execution_contract
        })),
    };
    emit(serde_json::to_value(result)?, out.clone(), "execute")?;
    if out.is_none() {
        let _ = fs::remove_dir_all(&runtime_directory);
    }
    Ok(())
}

fn adapter_child(adapter_name: &str, operation: &str, scopes: &[String], auth_lifetime_ms: u64) -> Result<(), Fail> {
    let adapter = find_adapter(adapter_name)?;
    if adapter.kind != "dependent-authentication" || !adapter.fake {
        return Err("adapter child accepts only fake dependent-authentication adapters".into());
    }
    let bounds = LifecycleBounds {
        deadline_ms: adapter.max_deadline_ms,
        retry_limit: 0,
        lease_ms: auth_lifetime_ms,
        cleanup: true,
    };
    validate_adapter_request(&adapter, operation, scopes, auth_lifetime_ms, &bounds)?;
    println!(
        "{}",
        serde_json::to_string(&redact(&json!({
            "schema": "store-adapter-evidence-v1",
            "operation": operation,
            "capability": dependent_auth_capability(&adapter, scopes, auth_lifetime_ms),
            "environmentKeys": child_environment().keys().collect::<Vec<_>>()
        })))?
    );
    Ok(())
}

fn analysis(path: &Path, adapter: &str, hypotheses_file: Option<&Path>) -> Result<Value, Fail> {
    let inspection = inspect_source(path, adapter)?;
    let hypotheses = load_hypotheses(hypotheses_file, derived_hypotheses(&inspection))?;
    Ok(json!({
        "schema": "store-source-analysis-v1",
        "inspection": inspection,
        "hypotheses": hypotheses
    }))
}

fn elaborate(path: Option<&Path>, hypotheses_file: Option<&Path>) -> Result<Value, Fail> {
    let (inspection, derived) = if let Some(path) = path {
        let inspection = inspect_source(path, "rust-cargo-inspector")?;
        let derived = derived_hypotheses(&inspection);
        (Some(inspection), derived)
    } else {
        (None, Vec::new())
    };
    let hypotheses = load_hypotheses(hypotheses_file, derived)?;
    Ok(json!({
        "schema": "store-elaboration-v1",
        "inspection": inspection,
        "hypotheses": hypotheses
    }))
}

fn render_draft(path: Option<&Path>, hypotheses_file: Option<&Path>) -> Result<Value, Fail> {
    let elaboration = elaborate(path, hypotheses_file)?;
    Ok(json!({
        "schema": "store-deterministic-draft-v1",
        "identity": IDENTITY,
        "theoremChannels": parse_optional_json(THEOREM_CHANNELS, json!([]))?,
        "elaboration": elaboration,
        "obligations": obligations()?,
        "graph": capability_graph()?,
        "adapters": adapters()?.into_iter().map(|adapter| adapter.name).collect::<Vec<_>>()
    }))
}

async fn dispatch(action: Option<Action>) -> Result<(), Fail> {
    validate_boundary()?;
    match action.unwrap_or(Action::Contract { action: None }) {
        Action::Contract { action } => contract(action)?,
        Action::GeneratingSet => emit(proof_generators()?, None, "generating-set")?,
        Action::DrvClosure => emit(drv_closure()?, None, "drv-closure")?,
        Action::MemoryReferences => emit(memory_references()?, None, "memory-references")?,
        Action::ProofGenerators => emit(proof_generators()?, None, "proof-generators")?,
        Action::Home { out } => emit(
            json!({"schema": "store-home-v3", "identity": IDENTITY, "authentication": parse_json(AUTHENTICATION)?}),
            out,
            "home",
        )?,
        Action::Lifecycle {
            operation,
            deadline_ms,
            retry_limit,
            lease_ms,
            cleanup,
            out,
        } => {
            if !lifecycle_exists(&operation)? {
                return Err(format!("undeclared lifecycle operation: {operation}").into());
            }
            let bounds = LifecycleBounds { deadline_ms, retry_limit, lease_ms, cleanup };
            validate_lifecycle_contract(&operation, &bounds)?;
            emit(
                json!({
                    "schema": "store-lifecycle-v3",
                    "identity": IDENTITY,
                    "operation": operation,
                    "bounds": bounds,
                    "cleanup": {"requested": cleanup, "leaseCreated": false, "leaseRemoved": false}
                }),
                out,
                "lifecycle",
            )?;
        }
        Action::Report { out, derivation_output } => {
            let target = if out.is_some() || derivation_output { Some(resolve_output(out, derivation_output)?) } else { None };
            emit(
                json!({"schema": "store-report-v3", "identity": IDENTITY, "contract": parse_json(CONTRACT_JSON)?}),
                target,
                "report",
            )?
        },
        Action::Repo => emit(parse_json(REPOSITORY)?, None, "repo")?,
        Action::Docs => emit(parse_json(INTERFACE)?, None, "docs")?,
        Action::Doctor => emit(
            json!({"schema": "store-doctor-v3", "identity": IDENTITY, "boundary": "clean", "status": "pass", "proofGenerators": proof_generators()?}),
            None,
            "doctor",
        )?,
        Action::Inspect { path, adapter, out } => {
            emit(serde_json::to_value(inspect_source(&path, &adapter)?)?, out, "inspect")?
        }
        Action::Analyze { path, adapter, hypotheses, out } => {
            emit(analysis(&path, &adapter, hypotheses.as_deref())?, out, "analyze")?
        }
        Action::Elaborate { path, hypotheses, out } => {
            emit(elaborate(path.as_deref(), hypotheses.as_deref())?, out, "elaborate")?
        }
        Action::Obligations { id, status, out } => {
            let mut rows = obligations()?;
            if let Some(id) = id {
                rows.retain(|row| row.id == id);
            }
            if let Some(status) = status {
                rows.retain(|row| row.status == status);
            }
            emit(json!({"schema": "store-obligation-query-v1", "proofObligations": proof_obligations()?, "obligations": rows}), out, "obligations")?
        }
        Action::Solve { id, evidence, out } => {
            emit(solve_request(&obligations()?, &id, evidence)?, out, "solve")?
        }
        Action::Render { path, hypotheses, out } => {
            emit(render_draft(path.as_deref(), hypotheses.as_deref())?, out, "render")?
        }
        Action::Graph { out } => emit(serde_json::to_value(capability_graph()?)?, out, "graph")?,
        Action::Execute {
            adapter,
            operation,
            scopes,
            auth_lifetime_ms,
            deadline_ms,
            retry_limit,
            lease_ms,
            cleanup,
            out,
        } => {
            execute_runtime(
                &adapter,
                &operation,
                scopes,
                auth_lifetime_ms,
                LifecycleBounds { deadline_ms, retry_limit, lease_ms, cleanup },
                out,
            )
            .await?
        }
        Action::Adapters { out } => emit(
            json!({
                "schema": "store-adapter-inventory-v1",
                "adapters": adapters()?,
                "compileTimeEnvironment": compile_environment_inventory()
            }),
            out,
            "adapters",
        )?,
        Action::AdapterChild { adapter, operation, scopes, auth_lifetime_ms } => {
            adapter_child(&adapter, &operation, &scopes, auth_lifetime_ms)?
        }
        Action::Login { provider, target_path_kind, target_path, provider_args, deadline_ms, out } => {
            let directory = out.clone().unwrap_or_else(|| temporary_path("login"));
            let result = perform_login(&provider, &target_path_kind, &target_path, &provider_args, deadline_ms).await?;
            persist_login_result(&result, &directory)?;
            println!("{}", serde_json::to_string_pretty(&redact(&serde_json::to_value(&result)?))?);
        }
        Action::LoginStatus { request_id, directory, out: _ } => {
            let result = read_login_status(&request_id, &directory)?;
            println!("{}", serde_json::to_string_pretty(&redact(&serde_json::to_value(&result)?))?);
        }
        Action::StsIdentity { target_path, expected_account, provider_args, deadline_ms, out: _ } => {
            let result = perform_sts_identity_check(&target_path, &expected_account, &provider_args, deadline_ms).await?;
            println!("{}", serde_json::to_string_pretty(&redact(&serde_json::to_value(&result)?))?);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<ExitCode, Fail> {
    if let Some(code) = enter_clean_boundary().await? {
        return Ok(code);
    }
    dispatch(Cli::parse().action).await?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_adapter() -> AdapterContract {
        default_adapters()
            .into_iter()
            .find(|adapter| adapter.name == "fake-dependent-auth")
            .unwrap()
    }

    fn test_bounds() -> LifecycleBounds {
        LifecycleBounds {
            deadline_ms: 5_000,
            retry_limit: 1,
            lease_ms: 1_000,
            cleanup: true,
        }
    }

    #[test]
    fn generating_set_has_one_top_level_drv_root() {
        let set = generating_set().unwrap();
        assert_eq!(set["topLevelRoots"].as_array().unwrap().len(), 1);
        assert_eq!(set["topLevelRoots"][0], "frost-login-freeze.drv");
        let closure = drv_closure().unwrap();
        assert_eq!(closure["topLevelDrvRootCount"], 1);
        assert_eq!(closure["transitiveDerivationClosure"].as_array().unwrap().len(), 3);
        assert_eq!(closure["providerOrNetworkCalled"], false);
    }

    #[test]
    fn proof_obligation_inventory_is_canonical_and_bounded() {
        let rows = proof_obligations().unwrap();
        assert_eq!(rows.len(), 7);
        assert_eq!(rows[3].name, "pure-rust-dispatch");
        assert_eq!(rows.iter().map(|row| row.plane.as_str()).collect::<Vec<_>>(), ["governance", "contract", "environment", "interface", "repository", "delivery", "runtime"]);
    }

    fn fixture() -> PathBuf {
        let root = temporary_path("test-source");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"=1.0.229\"\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "version = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"1.0.0\"\n").unwrap();
        fs::write(root.join("main.rs"), "fn main() {}\n\n#[test]\nfn stable() {}\n").unwrap();
        root
    }

    #[test]
    fn deterministic_inspection_and_draft() {
        let root = fixture();
        let left = inspect_source(&root, "rust-cargo-inspector").unwrap();
        let right = inspect_source(&root, "rust-cargo-inspector").unwrap();
        assert_eq!(left, right);
        let left = render_draft(Some(&root), None).unwrap();
        let right = render_draft(Some(&root), None).unwrap();
        assert_eq!(left, right);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn login_provider_set_is_closed_and_generic() {
        assert!(validate_login_request("aws-sso", "aws-cli-profile", "profile/example").is_ok());
        assert!(validate_login_request("ada-conduit", "aws-account-role", "account/example/role/example").is_ok());
        assert!(validate_login_request("midway", "midway-cookie-jar", "midway/example").is_ok());
        assert!(validate_login_request("rogue-provider", "aws-cli-profile", "profile/example").is_err());
    }

    #[test]
    fn login_rejects_value_like_target_paths() {
        assert!(validate_login_request("aws-sso", "aws-cli-profile", "profile/token-value").is_err());
        assert!(validate_login_request("aws-sso", "aws-cli-profile", "").is_err());
    }

    #[test]
    fn provider_adapter_class_matches_pinnability() {
        assert_eq!(provider_adapter_class("aws-sso"), "pinned-nix-derivation");
        assert_eq!(provider_adapter_class("ada-conduit"), "authorized-black-box");
        assert_eq!(provider_adapter_class("midway"), "authorized-black-box");
        assert_eq!(provider_adapter_class("rogue-provider"), "unregistered");
    }

    #[tokio::test]
    async fn black_box_providers_are_rejected_by_the_compiled_binary() {
        let error = perform_login("ada-conduit", "aws-account-role", "account/example/role/example", &[], 1_000)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authorized-black-box"));
        let error = perform_login("midway", "midway-cookie-jar", "midway/example", &[], 1_000)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authorized-black-box"));
    }

    #[test]
    fn login_result_persistence_round_trips_without_credential_material() {
        let root = temporary_path("test-login");
        let result = LoginResult {
            schema: "store-login-result-v1".to_owned(),
            request_id: "frost-login-login-test".to_owned(),
            provider: "aws-sso".to_owned(),
            adapter_class: "pinned-nix-derivation".to_owned(),
            target_path_kind: "aws-cli-profile".to_owned(),
            target_path: "profile/example".to_owned(),
            witness: ExecutionWitness {
                status: "executed".to_owned(),
                exit_code: "0".to_owned(),
                observed_at: "1".to_owned(),
                evidence_digest: digest_hex(b"sentinel"),
            },
            obligation_discharged: true,
        };
        persist_login_result(&result, &root).unwrap();
        let read_back = read_login_status(&result.request_id, &root).unwrap();
        assert_eq!(read_back, result);
        let serialized = fs::read_to_string(root.join(format!("{}.json", result.request_id))).unwrap();
        assert!(!serialized.contains("sentinel"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extract_account_from_identity_output_parses_valid_json() {
        let output = r#"{"UserId":"AIDAEXAMPLE","Account":"589634480698","Arn":"arn:aws:iam::589634480698:role/example"}"#;
        assert_eq!(extract_account_from_identity_output(output), Some("589634480698".to_owned()));
    }

    #[test]
    fn extract_account_from_identity_output_rejects_malformed_or_missing_account() {
        assert_eq!(extract_account_from_identity_output("not json"), None);
        assert_eq!(extract_account_from_identity_output("{}"), None);
    }

    #[tokio::test]
    async fn sts_identity_check_rejects_empty_arguments() {
        let error = perform_sts_identity_check("", "589634480698", &[], 1_000).await.unwrap_err();
        assert!(error.to_string().contains("nonempty"));
        let error = perform_sts_identity_check("account/589634480698/role/unresolved", "", &[], 1_000).await.unwrap_err();
        assert!(error.to_string().contains("nonempty"));
    }

    #[test]
    fn unknown_adapters_fail_closed() {
        let error = find_adapter("undeclared-adapter").unwrap_err().to_string();
        assert!(error.contains("unknown adapter rejected"));
    }

    #[test]
    fn obligation_solving_is_gated() {
        let rows = vec![
            Obligation {
                id: "first".to_owned(),
                statement: "first".to_owned(),
                status: "open".to_owned(),
                dependencies: Vec::new(),
                evidence: Vec::new(),
            },
            Obligation {
                id: "second".to_owned(),
                statement: "second".to_owned(),
                status: "open".to_owned(),
                dependencies: vec!["first".to_owned()],
                evidence: Vec::new(),
            },
        ];
        let blocked = solve_request(&rows, "second", vec!["proof".to_owned()]).unwrap();
        assert_eq!(blocked["status"], "blocked");
        let mut solved = rows;
        solved[0].status = "satisfied".to_owned();
        let ready = solve_request(&solved, "second", vec!["proof".to_owned()]).unwrap();
        assert_eq!(ready["status"], "ready");
        let missing = solve_request(&solved, "second", Vec::new()).unwrap();
        assert_eq!(missing["status"], "blocked");
    }

    #[test]
    fn runtime_nonleaf_nodes_require_checks() {
        let mut graph = default_graph();
        graph
            .nodes
            .iter_mut()
            .find(|node| node.id == "execute")
            .unwrap()
            .nonleaf_check = None;
        assert!(validate_graph(&graph).unwrap_err().to_string().contains("runtime nonleaf"));
        graph
            .nodes
            .iter_mut()
            .find(|node| node.id == "execute")
            .unwrap()
            .nonleaf_check = Some("bounded-runtime-children".to_owned());
        validate_graph(&graph).unwrap();
    }

    #[test]
    fn lifecycle_bounds_are_enforced() {
        validate_bounds(&test_bounds()).unwrap();
        let mut invalid = test_bounds();
        invalid.deadline_ms = 0;
        assert!(validate_bounds(&invalid).is_err());
        let mut invalid = test_bounds();
        invalid.retry_limit = MAX_RETRIES + 1;
        assert!(validate_bounds(&invalid).is_err());
        let mut invalid = test_bounds();
        invalid.lease_ms = invalid.deadline_ms + 1;
        assert!(validate_bounds(&invalid).is_err());
    }

    #[test]
    fn dependent_authentication_scope_and_lifetime_are_bounded() {
        let adapter = test_adapter();
        validate_adapter_request(
            &adapter,
            "build",
            &["run-fake".to_owned()],
            500,
            &test_bounds(),
        )
        .unwrap();
        assert!(validate_adapter_request(
            &adapter,
            "build",
            &["admin".to_owned()],
            500,
            &test_bounds(),
        )
        .is_err());
        assert!(validate_adapter_request(
            &adapter,
            "build",
            &["run-fake".to_owned()],
            1_001,
            &test_bounds(),
        )
        .is_err());
    }

    #[test]
    fn runtime_lease_cleanup_removes_artifact() {
        let root = temporary_path("test-cleanup");
        let bounds = test_bounds();
        let lease = create_lease(&root, "build", &bounds).unwrap();
        assert!(lease.exists());
        assert!(cleanup_lease(&lease, true).unwrap());
        assert!(!lease.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn secret_sentinel_is_absent_from_child_environment_and_persistence() {
        let environment = child_environment();
        assert!(!environment.contains_key("UNIT_SECRET_SENTINEL"));
        assert!(!environment.contains_key("UNIT_UNDECLARED_SENTINEL"));
        let sentinel = "credential-sentinel-never-persist";
        let safe = redact(&json!({
            "credentialValue": sentinel,
            "token": sentinel,
            "nested": {"password": sentinel},
            "ambientSentinelPresent": false
        }));
        let serialized = serde_json::to_string(&safe).unwrap();
        assert!(!serialized.contains(sentinel));
        assert_eq!(safe["ambientSentinelPresent"], false);
    }
}
