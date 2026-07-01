//! Remote attestation HTTP endpoint.
//!
//! Endpoints:
//!   GET  /attest          → cached compact UnifiedQuote
//!   POST /attest/full     → fresh full quote (accepts verifier challenge nonce)
//!   GET  /attest/value-x  → just Value X
//!   GET  /attest/integrity → runtime integrity status
//!   GET  /health          → liveness

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::integrity::SharedIntegrity;
use crate::quote::UnifiedQuote;

/// Callback type: takes an optional verifier-provided nonce, returns a quote.
/// If nonce is None, the prover generates one (self-attested, weaker).
/// If nonce is Some, the verifier provided it (challenge-response, stronger).
pub type RefreshFn = Box<dyn Fn(Option<[u8; 32]>) -> Result<UnifiedQuote, String> + Send + Sync>;

pub struct AttestState {
    pub current_quote: RwLock<Option<UnifiedQuote>>,
    pub refresh_fn: RefreshFn,
    full_quote_limiter: Mutex<RateLimiter>,
    read_limiter: Mutex<RateLimiter>,
    pub integrity: Option<SharedIntegrity>,
    pub eat_token_b64: RwLock<Option<String>>,
}

impl AttestState {
    pub fn new(initial_quote: Option<UnifiedQuote>, refresh_fn: RefreshFn) -> Self {
        Self {
            current_quote: RwLock::new(initial_quote),
            refresh_fn,
            full_quote_limiter: Mutex::new(RateLimiter::new(5, Duration::from_secs(60))),
            read_limiter: Mutex::new(RateLimiter::new(60, Duration::from_secs(60))),
            integrity: None,
            eat_token_b64: RwLock::new(None),
        }
    }

    pub fn with_integrity(mut self, integrity: SharedIntegrity) -> Self {
        self.integrity = Some(integrity);
        self
    }

    pub async fn set_eat_token(&self, b64: String) {
        let mut guard = self.eat_token_b64.write().await;
        *guard = Some(b64);
    }
}

pub fn attestation_router(state: Arc<AttestState>) -> Router {
    Router::new()
        .route("/attest", get(get_compact_quote))
        .route("/attest/full", post(get_full_quote))
        .route("/attest/value-x", get(get_value_x))
        .route("/attest/integrity", get(get_integrity))
        .route("/health", get(health))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            http_a_middleware,
        ))
        .with_state(state)
}

async fn http_a_middleware(
    State(state): State<Arc<AttestState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    if let Some(ref b64) = *state.eat_token_b64.read().await {
        if let Ok(val) = HeaderValue::from_str(b64) {
            response.headers_mut().insert("Attestation-Token", val);
        }
    }
    response
}

// --- Request/Response types ---

#[derive(Deserialize)]
struct FullQuoteRequest {
    /// Verifier-provided challenge nonce (hex-encoded, 32 bytes).
    /// If omitted, the prover generates one (weaker: no freshness proof to verifier).
    nonce: Option<String>,
}

#[derive(Serialize)]
struct ValueXResponse {
    value_x: String,
    platform: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// --- Handlers ---

async fn get_compact_quote(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.read_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited — max 60 req/min".into(),
            }),
        ));
    }

    let guard = state.current_quote.read().await;
    match guard.as_ref() {
        Some(q) => Ok(Json(
            serde_json::to_value(q.compact()).expect("UnifiedQuote serialization"),
        )),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "no attestation available — TEE not initialized".into(),
            }),
        )),
    }
}

async fn get_full_quote(
    State(state): State<Arc<AttestState>>,
    body: Option<Json<FullQuoteRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.full_quote_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited — max 5 fresh attestations/min".into(),
            }),
        ));
    }

    // Parse verifier-provided challenge nonce if present
    let challenge_nonce: Option<[u8; 32]> = body
        .and_then(|b| b.nonce.as_ref().and_then(|n| hex::decode(n).ok()))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

    let quote = (state.refresh_fn)(challenge_nonce).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("attestation failed: {e}"),
            }),
        )
    })?;

    // Update cached quote
    {
        let mut guard = state.current_quote.write().await;
        *guard = Some(quote.clone());
    }

    Ok(Json(
        serde_json::to_value(quote).expect("UnifiedQuote serialization"),
    ))
}

async fn get_value_x(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<ValueXResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.read_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited".into(),
            }),
        ));
    }

    let guard = state.current_quote.read().await;
    match guard.as_ref() {
        Some(q) => Ok(Json(ValueXResponse {
            value_x: hex::encode(q.value_x),
            platform: format!("{:?}", q.platform),
            timestamp: q.timestamp,
        })),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "no attestation available".into(),
            }),
        )),
    }
}

async fn get_integrity(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.read_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited".into(),
            }),
        ));
    }

    match &state.integrity {
        Some(integrity) => {
            let guard: tokio::sync::RwLockReadGuard<'_, crate::integrity::IntegrityStatus> =
                integrity.read().await;
            Ok(Json(serde_json::json!({
                "integrity_ok": guard.integrity_ok,
                "boot_value_x": hex::encode(guard.boot_value_x),
                "current_value_x": hex::encode(guard.current_value_x),
                "check_count": guard.check_count,
                "last_check": guard.last_check,
                "rtmr_extended": guard.rtmr_extended,
            })))
        }
        None => Ok(Json(serde_json::json!({
            "integrity_ok": true,
            "monitoring": false,
        }))),
    }
}

async fn health() -> &'static str {
    "ok"
}

struct RateLimiter {
    max_requests: usize,
    window: Duration,
    timestamps: Vec<Instant>,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            timestamps: Vec::with_capacity(max_requests),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.timestamps
            .retain(|&t| now.duration_since(t) < self.window);
        if self.timestamps.len() < self.max_requests {
            self.timestamps.push(now);
            true
        } else {
            false
        }
    }
}
