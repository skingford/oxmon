use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use oxmon_common::proto::metric_service_client::MetricServiceClient;
use oxmon_common::proto::{MetricBatchProto, MetricDataPointProto, ReportResponse};
use std::collections::HashMap;
use std::env;
use tokio::time::{sleep, Duration};
use tonic::metadata::MetadataValue;
use tonic::{Code, Request, Status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Baseline,
    Threshold,
    Rate,
    Trend,
    Cert,
    Recovery,
    All,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "threshold" => Ok(Self::Threshold),
            "rate" => Ok(Self::Rate),
            "trend" => Ok(Self::Trend),
            "cert" => Ok(Self::Cert),
            "recovery" => Ok(Self::Recovery),
            "all" => Ok(Self::All),
            _ => bail!("unknown scenario: {value}"),
        }
    }

    fn names() -> &'static [&'static str] {
        &[
            "all",
            "baseline",
            "threshold",
            "rate",
            "trend",
            "cert",
            "recovery",
        ]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Threshold => "threshold",
            Self::Rate => "rate",
            Self::Trend => "trend",
            Self::Cert => "cert",
            Self::Recovery => "recovery",
            Self::All => "all",
        }
    }
}

#[derive(Debug)]
struct Config {
    server_endpoint: String,
    scenario: Scenario,
    agent_count: usize,
    agent_prefix: String,
    pause_ms: u64,
    auth_token: Option<String>,
    auth_token_file: Option<String>,
    print_payload: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_endpoint: "127.0.0.1:9090".to_string(),
            scenario: Scenario::All,
            agent_count: 5,
            agent_prefix: "mock".to_string(),
            pause_ms: 120,
            auth_token: None,
            auth_token_file: None,
            print_payload: false,
        }
    }
}

enum CliAction {
    Run(Config),
    Help,
    ListScenarios,
}

struct BatchPlan {
    scenario: Scenario,
    description: String,
    batch: MetricBatchProto,
}

struct TokenResolver {
    global_token: Option<String>,
    per_agent_tokens: HashMap<String, String>,
}

impl TokenResolver {
    fn build(config: &Config) -> Result<Self> {
        let per_agent_tokens = match &config.auth_token_file {
            Some(path) => load_token_map(path)?,
            None => HashMap::new(),
        };

        Ok(Self {
            global_token: config.auth_token.clone(),
            per_agent_tokens,
        })
    }

    fn token_for(&self, agent_id: &str) -> Option<&str> {
        self.per_agent_tokens
            .get(agent_id)
            .map(String::as_str)
            .or(self.global_token.as_deref())
    }
}

fn usage() {
    println!(
        "Usage:\n  oxmon-mock-report [options]\n\nOptions:\n  --server-endpoint <host:port>  gRPC endpoint (default: 127.0.0.1:9090)\n  --scenario <name>              all|baseline|threshold|rate|trend|cert|recovery (default: all)\n  --agent-count <n>              baseline agent count (default: 5)\n  --agent-prefix <prefix>        agent prefix (default: mock)\n  --pause-ms <n>                 pause between batches (default: 120)\n  --auth-token <token>           one token for all agents\n  --auth-token-file <path>       agent token map file: agent_id=token\n  --print-payload                print each batch payload summary\n  --list-scenarios               print supported scenarios\n  -h, --help                     show this help"
    );
}

fn parse_cli() -> Result<CliAction> {
    let mut config = Config::default();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--list-scenarios" => return Ok(CliAction::ListScenarios),
            "--server-endpoint" => {
                config.server_endpoint = next_value(&mut args, "--server-endpoint")?;
            }
            "--scenario" => {
                let value = next_value(&mut args, "--scenario")?;
                config.scenario = Scenario::parse(&value)?;
            }
            "--agent-count" => {
                let value = next_value(&mut args, "--agent-count")?;
                config.agent_count = parse_positive_usize(&value, "--agent-count")?;
            }
            "--agent-prefix" => {
                config.agent_prefix = next_value(&mut args, "--agent-prefix")?;
            }
            "--pause-ms" => {
                let value = next_value(&mut args, "--pause-ms")?;
                config.pause_ms = parse_u64(&value, "--pause-ms")?;
            }
            "--auth-token" => {
                config.auth_token = Some(next_value(&mut args, "--auth-token")?);
            }
            "--auth-token-file" => {
                config.auth_token_file = Some(next_value(&mut args, "--auth-token-file")?);
            }
            "--print-payload" => {
                config.print_payload = true;
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }

    if config.agent_count == 0 {
        bail!("--agent-count must be greater than 0");
    }

    Ok(CliAction::Run(config))
}

fn next_value<I>(args: &mut I, flag: &str) -> Result<String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| anyhow!("missing value for {flag}"))
}

fn parse_positive_usize(value: &str, flag: &str) -> Result<usize> {
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("invalid number for {flag}: {value}"))?;
    if parsed == 0 {
        bail!("{flag} must be greater than 0");
    }
    Ok(parsed)
}

fn parse_u64(value: &str, flag: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("invalid number for {flag}: {value}"))
}

fn normalize_endpoint(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}

fn load_token_map(path: &str) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read token file: {path}"))?;
    let mut map = HashMap::new();

    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (agent_id_raw, token_raw) = trimmed
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid token mapping at line {}", line_no + 1))?;

        let agent_id = agent_id_raw.trim();
        let token = token_raw.trim();
        if agent_id.is_empty() || token.is_empty() {
            bail!("empty agent_id or token at line {}", line_no + 1);
        }

        map.insert(agent_id.to_string(), token.to_string());
    }

    Ok(map)
}

fn labels(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn point(
    timestamp_ms: i64,
    agent_id: &str,
    metric_name: &str,
    value: f64,
    point_labels: HashMap<String, String>,
) -> MetricDataPointProto {
    MetricDataPointProto {
        timestamp_ms,
        agent_id: agent_id.to_string(),
        metric_name: metric_name.to_string(),
        value,
        labels: point_labels,
    }
}

fn build_batch(agent_id: &str, data_points: Vec<MetricDataPointProto>) -> MetricBatchProto {
    MetricBatchProto {
        agent_id: agent_id.to_string(),
        timestamp_ms: Utc::now().timestamp_millis(),
        data_points,
    }
}

/// Generates a realistic baseline batch matching real collector output.
///
/// Real agent collects:
///   CPU:     cpu.usage (global), cpu.core_usage * N cores
///   Memory:  memory.total, memory.used, memory.available, memory.used_percent,
///            memory.swap_total, memory.swap_used, memory.swap_percent
///   Load:    system.load_1, system.load_5, system.load_15, system.uptime
///   Disk:    disk.total, disk.used, disk.available, disk.used_percent  (per mount)
///   Network: network.bytes_recv, network.bytes_sent,
///            network.packets_recv, network.packets_sent  (per interface)
fn generate_baseline_batches(config: &Config, now_ms: i64) -> Vec<BatchPlan> {
    let width = config.agent_count.to_string().len().max(2);
    (1..=config.agent_count)
        .map(|index| {
            let agent_id = format!(
                "{}-normal-{index:0width$}",
                config.agent_prefix,
                width = width
            );
            let seed = index as f64;
            let mut points = Vec::new();

            // ── CPU ──
            let cpu_usage = 28.0 + (seed * 11.0) % 30.0;
            points.push(point(
                now_ms,
                &agent_id,
                "cpu.usage",
                cpu_usage,
                HashMap::new(),
            ));
            // 4 cores
            for core in 0..4u32 {
                let core_usage = cpu_usage + (core as f64 * 5.3 + seed * 3.7) % 20.0 - 10.0;
                points.push(point(
                    now_ms,
                    &agent_id,
                    "cpu.core_usage",
                    core_usage.clamp(0.0, 100.0),
                    labels(&[("core", &core.to_string())]),
                ));
            }

            // ── Memory ──
            let mem_total = 16_000_000_000.0; // 16 GB
            let mem_used_pct = 42.0 + (seed * 7.0) % 25.0;
            let mem_used = mem_total * mem_used_pct / 100.0;
            let mem_available = mem_total - mem_used;
            points.push(point(
                now_ms,
                &agent_id,
                "memory.total",
                mem_total,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "memory.used",
                mem_used,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "memory.available",
                mem_available,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "memory.used_percent",
                mem_used_pct,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "memory.swap_total",
                4_000_000_000.0,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "memory.swap_used",
                200_000_000.0 + seed * 50_000_000.0,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "memory.swap_percent",
                5.0 + seed * 1.25,
                HashMap::new(),
            ));

            // ── Load ──
            points.push(point(
                now_ms,
                &agent_id,
                "system.load_1",
                0.4 + (seed * 0.21) % 1.2,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "system.load_5",
                0.5 + (seed * 0.15) % 0.8,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "system.load_15",
                0.3 + (seed * 0.1) % 0.5,
                HashMap::new(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "system.uptime",
                86400.0 * (10.0 + seed),
                HashMap::new(),
            ));

            // ── Disk (two mounts: / and /data) ──
            let root_labels = labels(&[("mount", "/")]);
            let root_total = 100_000_000_000.0; // 100 GB
            let root_used_pct = 35.0 + (seed * 3.0) % 15.0;
            let root_used = root_total * root_used_pct / 100.0;
            points.push(point(
                now_ms,
                &agent_id,
                "disk.total",
                root_total,
                root_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "disk.used",
                root_used,
                root_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "disk.available",
                root_total - root_used,
                root_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "disk.used_percent",
                root_used_pct,
                root_labels,
            ));

            let data_labels = labels(&[("mount", "/data")]);
            let data_total = 500_000_000_000.0; // 500 GB
            let data_used_pct = 50.0 + (seed * 5.0) % 20.0;
            let data_used = data_total * data_used_pct / 100.0;
            points.push(point(
                now_ms,
                &agent_id,
                "disk.total",
                data_total,
                data_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "disk.used",
                data_used,
                data_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "disk.available",
                data_total - data_used,
                data_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "disk.used_percent",
                data_used_pct,
                data_labels,
            ));

            // ── Network (eth0) ──
            let eth0_labels = labels(&[("interface", "eth0")]);
            points.push(point(
                now_ms,
                &agent_id,
                "network.bytes_recv",
                12_000.0 + seed * 350.0,
                eth0_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "network.bytes_sent",
                8_500.0 + seed * 280.0,
                eth0_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "network.packets_recv",
                80.0 + seed * 12.0,
                eth0_labels.clone(),
            ));
            points.push(point(
                now_ms,
                &agent_id,
                "network.packets_sent",
                55.0 + seed * 9.0,
                eth0_labels,
            ));

            BatchPlan {
                scenario: Scenario::Baseline,
                description: format!("baseline metrics ({} points)", points.len()),
                batch: build_batch(&agent_id, points),
            }
        })
        .collect()
}

/// High CPU sustained above threshold.
fn generate_threshold_batch(config: &Config, now_ms: i64) -> Vec<BatchPlan> {
    let agent_id = format!("{}-threshold", config.agent_prefix);

    // CPU threshold (global)
    let cpu_points = vec![
        point(
            now_ms - 20_000,
            &agent_id,
            "cpu.usage",
            96.0,
            HashMap::new(),
        ),
        point(
            now_ms - 10_000,
            &agent_id,
            "cpu.usage",
            97.0,
            HashMap::new(),
        ),
        point(now_ms - 1_000, &agent_id, "cpu.usage", 95.0, HashMap::new()),
    ];

    // Disk threshold on /data mount
    let mount_labels = labels(&[("mount", "/data")]);
    let disk_points = vec![
        point(
            now_ms - 20_000,
            &agent_id,
            "disk.used_percent",
            92.0,
            mount_labels.clone(),
        ),
        point(
            now_ms - 10_000,
            &agent_id,
            "disk.used_percent",
            93.0,
            mount_labels.clone(),
        ),
        point(
            now_ms - 1_000,
            &agent_id,
            "disk.used_percent",
            94.0,
            mount_labels,
        ),
    ];

    vec![
        BatchPlan {
            scenario: Scenario::Threshold,
            description: "high cpu threshold (sustained > 90%)".to_string(),
            batch: build_batch(&agent_id, cpu_points),
        },
        BatchPlan {
            scenario: Scenario::Threshold,
            description: "high disk threshold on /data (sustained > 90%)".to_string(),
            batch: build_batch(&agent_id, disk_points),
        },
    ]
}

/// Memory spike: sudden jump triggers rate-of-change alert.
fn generate_rate_batch(config: &Config, now_ms: i64) -> BatchPlan {
    let agent_id = format!("{}-rate", config.agent_prefix);
    let points = vec![
        point(
            now_ms - 60_000,
            &agent_id,
            "memory.used_percent",
            38.0,
            HashMap::new(),
        ),
        point(
            now_ms,
            &agent_id,
            "memory.used_percent",
            82.0,
            HashMap::new(),
        ),
    ];

    BatchPlan {
        scenario: Scenario::Rate,
        description: "rate-of-change spike: memory 38% -> 82%".to_string(),
        batch: build_batch(&agent_id, points),
    }
}

/// Linearly increasing disk usage predicts breach.
fn generate_trend_batch(config: &Config, now_ms: i64) -> BatchPlan {
    let agent_id = format!("{}-trend", config.agent_prefix);
    let mount_labels = labels(&[("mount", "/data")]);
    let points: Vec<MetricDataPointProto> = (0..10)
        .map(|index| {
            let timestamp_ms = now_ms - 90_000 + (index as i64 * 10_000);
            let value = 68.0 + index as f64 * 1.8;
            point(
                timestamp_ms,
                &agent_id,
                "disk.used_percent",
                value,
                mount_labels.clone(),
            )
        })
        .collect();

    BatchPlan {
        scenario: Scenario::Trend,
        description: "trend prediction: /data disk 68% -> 84% over 90s".to_string(),
        batch: build_batch(&agent_id, points),
    }
}

/// Certificate expiration and invalid cert.
fn generate_cert_batch(now_ms: i64) -> BatchPlan {
    let agent_id = "cert-checker".to_string();
    let points = vec![
        point(
            now_ms,
            &agent_id,
            "certificate.days_until_expiry",
            5.0,
            labels(&[("domain", "expiring.example.com")]),
        ),
        point(
            now_ms,
            &agent_id,
            "certificate.days_until_expiry",
            25.0,
            labels(&[("domain", "warning.example.com")]),
        ),
        point(
            now_ms,
            &agent_id,
            "certificate.days_until_expiry",
            -3.0,
            labels(&[("domain", "expired.example.com")]),
        ),
        point(
            now_ms,
            &agent_id,
            "certificate.is_valid",
            0.0,
            labels(&[("domain", "invalid.example.com")]),
        ),
    ];

    BatchPlan {
        scenario: Scenario::Cert,
        description: "cert: expiring(5d) + warning(25d) + expired(-3d) + invalid".to_string(),
        batch: build_batch(&agent_id, points),
    }
}

/// Recovery scenario: first fires an alert, then sends normal data to trigger auto-recovery.
///
/// Batch 1: 3 consecutive high CPU points → triggers threshold alert
/// Batch 2-4: 3 consecutive normal CPU points → triggers auto-recovery
fn generate_recovery_batches(config: &Config, now_ms: i64) -> Vec<BatchPlan> {
    let agent_id = format!("{}-recovery", config.agent_prefix);

    // Batch 1: sustained high CPU → fires alert
    let fire_points = vec![
        point(
            now_ms - 30_000,
            &agent_id,
            "cpu.usage",
            96.0,
            HashMap::new(),
        ),
        point(
            now_ms - 20_000,
            &agent_id,
            "cpu.usage",
            97.0,
            HashMap::new(),
        ),
        point(
            now_ms - 10_000,
            &agent_id,
            "cpu.usage",
            95.0,
            HashMap::new(),
        ),
    ];

    // Batch 2-4: normal CPU (3 consecutive OKs → triggers recovery)
    let recovery_points: Vec<Vec<MetricDataPointProto>> = (1..=3)
        .map(|i| {
            vec![point(
                now_ms + (i * 10_000),
                &agent_id,
                "cpu.usage",
                35.0 + i as f64 * 2.0,
                HashMap::new(),
            )]
        })
        .collect();

    let mut plans = vec![BatchPlan {
        scenario: Scenario::Recovery,
        description: "recovery step 1/4: high cpu fires alert".to_string(),
        batch: build_batch(&agent_id, fire_points),
    }];

    for (i, pts) in recovery_points.into_iter().enumerate() {
        plans.push(BatchPlan {
            scenario: Scenario::Recovery,
            description: format!(
                "recovery step {}/4: normal cpu (consecutive ok {})",
                i + 2,
                i + 1
            ),
            batch: build_batch(&agent_id, pts),
        });
    }

    plans
}

fn generate_plans(config: &Config) -> Vec<BatchPlan> {
    let now_ms = Utc::now().timestamp_millis();
    match config.scenario {
        Scenario::Baseline => generate_baseline_batches(config, now_ms),
        Scenario::Threshold => generate_threshold_batch(config, now_ms),
        Scenario::Rate => vec![generate_rate_batch(config, now_ms)],
        Scenario::Trend => vec![generate_trend_batch(config, now_ms)],
        Scenario::Cert => vec![generate_cert_batch(now_ms)],
        Scenario::Recovery => generate_recovery_batches(config, now_ms),
        Scenario::All => {
            let mut plans = generate_baseline_batches(config, now_ms);
            plans.extend(generate_threshold_batch(config, now_ms));
            plans.push(generate_rate_batch(config, now_ms));
            plans.push(generate_trend_batch(config, now_ms));
            plans.push(generate_cert_batch(now_ms));
            plans.extend(generate_recovery_batches(config, now_ms));
            plans
        }
    }
}

fn attach_auth_metadata(request: &mut Request<MetricBatchProto>, token: &str) -> Result<()> {
    let auth_value = format!("Bearer {token}")
        .parse::<MetadataValue<_>>()
        .context("invalid authorization metadata value")?;
    let agent_value = request
        .get_ref()
        .agent_id
        .parse::<MetadataValue<_>>()
        .context("invalid agent-id metadata value")?;

    request.metadata_mut().insert("authorization", auth_value);
    request.metadata_mut().insert("agent-id", agent_value);
    Ok(())
}

async fn report_once(
    endpoint: &str,
    batch: MetricBatchProto,
    token: Option<&str>,
) -> std::result::Result<ReportResponse, Status> {
    let mut client = MetricServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| Status::unavailable(format!("connect failed: {e}")))?;
    let mut request = Request::new(batch);

    if let Some(token) = token {
        attach_auth_metadata(&mut request, token)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
    }

    client
        .report_metrics(request)
        .await
        .map(|resp| resp.into_inner())
}

fn is_retryable(code: Code) -> bool {
    matches!(
        code,
        Code::Unavailable | Code::DeadlineExceeded | Code::Unknown
    )
}

async fn report_with_retry(
    endpoint: &str,
    batch: MetricBatchProto,
    token: Option<&str>,
) -> Result<ReportResponse> {
    match report_once(endpoint, batch.clone(), token).await {
        Ok(response) => Ok(response),
        Err(status) if is_retryable(status.code()) => report_once(endpoint, batch, token)
            .await
            .map_err(|e| anyhow!("grpc report failed after retry: {e}")),
        Err(status) => Err(anyhow!("grpc report failed: {status}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match parse_cli()? {
        CliAction::Help => {
            usage();
            Ok(())
        }
        CliAction::ListScenarios => {
            println!("{}", Scenario::names().join("\n"));
            Ok(())
        }
        CliAction::Run(config) => run(config).await,
    }
}

async fn run(config: Config) -> Result<()> {
    let endpoint = normalize_endpoint(&config.server_endpoint);
    let token_resolver = TokenResolver::build(&config)?;
    let plans = generate_plans(&config);
    let total_points: usize = plans.iter().map(|plan| plan.batch.data_points.len()).sum();

    println!(
        "[mock-report] scenario={} batches={} points={} endpoint={}",
        config.scenario.as_str(),
        plans.len(),
        total_points,
        endpoint
    );

    let mut success_batches = 0usize;
    let mut failed_batches = 0usize;
    let mut success_points = 0usize;

    for plan in plans {
        let point_count = plan.batch.data_points.len();
        let agent_id = plan.batch.agent_id.clone();
        let token = token_resolver.token_for(&agent_id);

        if config.print_payload {
            println!(
                "[mock-report][payload] scenario={} agent={} points={} desc={}",
                plan.scenario.as_str(),
                agent_id,
                point_count,
                plan.description
            );
        }

        match report_with_retry(&endpoint, plan.batch, token).await {
            Ok(report) if report.success => {
                success_batches += 1;
                success_points += point_count;
                println!(
                    "[mock-report][ok] scenario={} agent={} points={} desc=\"{}\"",
                    plan.scenario.as_str(),
                    agent_id,
                    point_count,
                    plan.description
                );
            }
            Ok(report) => {
                failed_batches += 1;
                eprintln!(
                    "[mock-report][reject] scenario={} agent={} points={} message={}",
                    plan.scenario.as_str(),
                    agent_id,
                    point_count,
                    report.message
                );
            }
            Err(error) => {
                failed_batches += 1;
                eprintln!(
                    "[mock-report][fail] scenario={} agent={} points={} error={:#}",
                    plan.scenario.as_str(),
                    agent_id,
                    point_count,
                    error
                );
            }
        }

        if config.pause_ms > 0 {
            sleep(Duration::from_millis(config.pause_ms)).await;
        }
    }

    println!(
        "[mock-report] done success_batches={} failed_batches={} success_points={}",
        success_batches, failed_batches, success_points
    );

    if failed_batches > 0 {
        bail!("{} batch(es) failed", failed_batches);
    }

    Ok(())
}
