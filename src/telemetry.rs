use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tokio::net::TcpListener;

#[derive(Debug)]
pub struct Telemetry {
    ready: AtomicBool,
    process_start_unix_seconds: u64,
    last_poll_unix_seconds: AtomicU64,
    last_ready_batch: AtomicI64,
    batches_processed_total: AtomicU64,
    approvals_submitted_total: AtomicU64,
    approvals_skipped_already_approved_total: AtomicU64,
    approvals_skipped_dry_run_total: AtomicU64,
    batch_failures_total: AtomicU64,
}

impl Telemetry {
    pub fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            process_start_unix_seconds: unix_now(),
            last_poll_unix_seconds: AtomicU64::new(0),
            last_ready_batch: AtomicI64::new(0),
            batches_processed_total: AtomicU64::new(0),
            approvals_submitted_total: AtomicU64::new(0),
            approvals_skipped_already_approved_total: AtomicU64::new(0),
            approvals_skipped_dry_run_total: AtomicU64::new(0),
            batch_failures_total: AtomicU64::new(0),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    pub fn mark_poll(&self) {
        self.last_poll_unix_seconds
            .store(unix_now(), Ordering::Relaxed);
    }

    pub fn observe_batch_outcome(&self, batch: i64, outcome: BatchRunOutcome) {
        self.batches_processed_total.fetch_add(1, Ordering::Relaxed);
        self.last_ready_batch.store(batch, Ordering::Relaxed);
        match outcome {
            BatchRunOutcome::AlreadyApproved => {
                self.approvals_skipped_already_approved_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            BatchRunOutcome::DryRun => {
                self.approvals_skipped_dry_run_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            BatchRunOutcome::Submitted => {
                self.approvals_submitted_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn observe_batch_failure(&self) {
        self.batch_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    fn render_prometheus(&self) -> String {
        let ready = u8::from(self.ready.load(Ordering::Relaxed));
        format!(
            concat!(
                "# HELP en_2fa_ready Whether the worker has completed startup and is ready to process batches.\n",
                "# TYPE en_2fa_ready gauge\n",
                "en_2fa_ready {ready}\n",
                "# HELP en_2fa_process_start_time_seconds Unix timestamp when the process started.\n",
                "# TYPE en_2fa_process_start_time_seconds gauge\n",
                "en_2fa_process_start_time_seconds {process_start}\n",
                "# HELP en_2fa_last_poll_time_seconds Unix timestamp of the last polling attempt.\n",
                "# TYPE en_2fa_last_poll_time_seconds gauge\n",
                "en_2fa_last_poll_time_seconds {last_poll}\n",
                "# HELP en_2fa_last_ready_batch Last batch successfully processed or skipped.\n",
                "# TYPE en_2fa_last_ready_batch gauge\n",
                "en_2fa_last_ready_batch {last_batch}\n",
                "# HELP en_2fa_batches_processed_total Total batches processed without error.\n",
                "# TYPE en_2fa_batches_processed_total counter\n",
                "en_2fa_batches_processed_total {processed}\n",
                "# HELP en_2fa_approvals_submitted_total Total approveHash transactions submitted.\n",
                "# TYPE en_2fa_approvals_submitted_total counter\n",
                "en_2fa_approvals_submitted_total {submitted}\n",
                "# HELP en_2fa_approvals_skipped_already_approved_total Total batches skipped because the signer had already approved.\n",
                "# TYPE en_2fa_approvals_skipped_already_approved_total counter\n",
                "en_2fa_approvals_skipped_already_approved_total {already_approved}\n",
                "# HELP en_2fa_approvals_skipped_dry_run_total Total batches skipped because dry-run mode was enabled.\n",
                "# TYPE en_2fa_approvals_skipped_dry_run_total counter\n",
                "en_2fa_approvals_skipped_dry_run_total {dry_run}\n",
                "# HELP en_2fa_batch_failures_total Total batch processing failures observed before exit.\n",
                "# TYPE en_2fa_batch_failures_total counter\n",
                "en_2fa_batch_failures_total {failures}\n",
            ),
            ready = ready,
            process_start = self.process_start_unix_seconds,
            last_poll = self.last_poll_unix_seconds.load(Ordering::Relaxed),
            last_batch = self.last_ready_batch.load(Ordering::Relaxed),
            processed = self.batches_processed_total.load(Ordering::Relaxed),
            submitted = self.approvals_submitted_total.load(Ordering::Relaxed),
            already_approved = self
                .approvals_skipped_already_approved_total
                .load(Ordering::Relaxed),
            dry_run = self.approvals_skipped_dry_run_total.load(Ordering::Relaxed),
            failures = self.batch_failures_total.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BatchRunOutcome {
    AlreadyApproved,
    DryRun,
    Submitted,
}

pub async fn serve(listener: TcpListener, telemetry: Arc<Telemetry>) -> Result<()> {
    let app = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/healthz/live", get(livez))
        .route("/healthz/ready", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(telemetry);

    axum::serve(listener, app)
        .await
        .context("HTTP server failed")
}

pub fn bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
}

async fn livez() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn readyz(State(telemetry): State<Arc<Telemetry>>) -> impl IntoResponse {
    if telemetry.ready.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

async fn metrics(State(telemetry): State<Arc<Telemetry>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        telemetry.render_prometheus(),
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
