use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use sui_sdk::rpc_types::{SuiObjectDataOptions, SuiParsedData, SuiMoveStruct, SuiMoveValue};
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::ObjectID;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn, error};

#[derive(Clone)]
struct AppState {
    request_count: Arc<RwLock<u64>>,
    protocol_pp_cache: Arc<RwLock<Option<ProtocolPPCache>>>,
    sui_rpc_url: String,
    coordinator_id: String,
}

#[derive(Clone)]
struct ProtocolPPCache {
    protocol_pp: Vec<u8>,
    encryption_key_id: String,
    encryption_key_version: u64,
    fetched_at: Instant,
}

#[derive(Deserialize)]
struct SignRequest {
    #[serde(default)]
    protocol_pp: Option<String>,  // base64, optional - fetched from chain if not provided
    dkg_output: String,           // base64
    secret_share: String,         // base64
    presign: String,              // base64
    message: String,              // base64
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,  // base64
    duration_ms: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct StatusResponse {
    healthy: bool,
    protocol_pp_cached: bool,
    protocol_pp_size: Option<usize>,
    encryption_key_id: Option<String>,
    encryption_key_version: Option<u64>,
    cache_age_secs: Option<u64>,
}

async fn health() -> &'static str {
    "OK"
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let cache = state.protocol_pp_cache.read().await;
    match cache.as_ref() {
        Some(c) => Json(StatusResponse {
            healthy: true,
            protocol_pp_cached: true,
            protocol_pp_size: Some(c.protocol_pp.len()),
            encryption_key_id: Some(c.encryption_key_id.clone()),
            encryption_key_version: Some(c.encryption_key_version),
            cache_age_secs: Some(c.fetched_at.elapsed().as_secs()),
        }),
        None => Json(StatusResponse {
            healthy: true,
            protocol_pp_cached: false,
            protocol_pp_size: None,
            encryption_key_id: None,
            encryption_key_version: None,
            cache_age_secs: None,
        }),
    }
}

async fn refresh_cache(State(state): State<AppState>) -> impl IntoResponse {
    match fetch_and_cache_protocol_pp(&state).await {
        Ok(_) => (StatusCode::OK, "Cache refreshed").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: format!("Failed to refresh cache: {}", e) }),
        ).into_response(),
    }
}

fn extract_object_id(value: &SuiMoveValue) -> Option<String> {
    match value {
        SuiMoveValue::String(s) => Some(s.clone()),
        SuiMoveValue::Address(a) => Some(a.to_string()),
        SuiMoveValue::UID { id } => Some(id.to_string()),
        SuiMoveValue::Struct(s) => {
            match s {
                SuiMoveStruct::WithFields(f) => {
                    f.get("id").and_then(extract_object_id)
                }
                SuiMoveStruct::WithTypes { fields, .. } => {
                    fields.get("id").and_then(extract_object_id)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn extract_nested_id(value: &SuiMoveValue, path: &[&str]) -> Option<String> {
    if path.is_empty() {
        return extract_object_id(value);
    }

    match value {
        SuiMoveValue::UID { id } if path == ["id"] => Some(id.to_string()),
        SuiMoveValue::Struct(s) => {
            let fields = match s {
                SuiMoveStruct::WithFields(f) => f,
                SuiMoveStruct::WithTypes { fields, .. } => fields,
                _ => return None,
            };
            fields.get(path[0]).and_then(|v| extract_nested_id(v, &path[1..]))
        }
        _ => None,
    }
}

async fn fetch_and_cache_protocol_pp(state: &AppState) -> anyhow::Result<()> {
    info!("Fetching protocol public parameters from chain...");
    let t0 = Instant::now();

    let sui = SuiClientBuilder::default()
        .build(&state.sui_rpc_url)
        .await?;

    let coordinator_id: ObjectID = state.coordinator_id.parse()?;

    // Step 1: Get coordinator dynamic fields to find the "inner" field
    info!("Step 1: Fetching coordinator dynamic fields...");
    let coordinator_dfs = sui
        .read_api()
        .get_dynamic_fields(coordinator_id, None, None)
        .await?;

    if coordinator_dfs.data.is_empty() {
        return Err(anyhow::anyhow!("Coordinator has no dynamic fields"));
    }

    // The inner field is typically the last one (based on SDK code)
    let inner_df = coordinator_dfs.data.last()
        .ok_or_else(|| anyhow::anyhow!("No inner dynamic field found"))?;
    let inner_id = &inner_df.object_id;
    info!("  Found coordinator inner: {}", inner_id);

    // Step 2: Fetch the coordinator inner object to get encryption keys table ID
    info!("Step 2: Fetching coordinator inner...");
    let inner_obj = sui
        .read_api()
        .get_object_with_options(inner_id.clone(), SuiObjectDataOptions::new().with_content())
        .await?
        .data
        .ok_or_else(|| anyhow::anyhow!("Coordinator inner object not found"))?;

    let inner_content = inner_obj.content
        .ok_or_else(|| anyhow::anyhow!("Coordinator inner has no content"))?;

    let inner_fields = match &inner_content {
        SuiParsedData::MoveObject(obj) => {
            match &obj.fields {
                SuiMoveStruct::WithFields(f) => f,
                SuiMoveStruct::WithTypes { fields, .. } => fields,
                _ => return Err(anyhow::anyhow!("Unexpected inner struct format")),
            }
        }
        _ => return Err(anyhow::anyhow!("Expected MoveObject for inner")),
    };

    // The inner is wrapped in a DynamicField, so we need to get the "value" field first
    let value_fields = match inner_fields.get("value") {
        Some(SuiMoveValue::Struct(s)) => {
            match s {
                SuiMoveStruct::WithFields(f) => f,
                SuiMoveStruct::WithTypes { fields, .. } => fields,
                _ => return Err(anyhow::anyhow!("Unexpected value struct format")),
            }
        }
        _ => inner_fields,
    };

    // Get the encryption keys table ID: dwallet_network_encryption_keys.id (which is a UID)
    let enc_keys_field = value_fields.get("dwallet_network_encryption_keys")
        .ok_or_else(|| anyhow::anyhow!("dwallet_network_encryption_keys not found"))?;
    let encryption_keys_table_id = extract_nested_id(enc_keys_field, &["id"])
        .ok_or_else(|| anyhow::anyhow!("Failed to extract encryption keys table ID"))?;
    info!("  Found encryption keys table: {}", encryption_keys_table_id);

    // Step 3: Get encryption key dynamic fields
    info!("Step 3: Fetching encryption keys from table...");
    let encryption_keys_table_oid: ObjectID = encryption_keys_table_id.parse()?;
    let keys_dfs = sui
        .read_api()
        .get_dynamic_fields(encryption_keys_table_oid, None, None)
        .await?;

    if keys_dfs.data.is_empty() {
        return Err(anyhow::anyhow!("No encryption keys found"));
    }

    info!("  Found {} encryption key(s)", keys_dfs.data.len());

    // Use the first (or only) encryption key
    let key_df = keys_dfs.data.first()
        .ok_or_else(|| anyhow::anyhow!("No encryption key dynamic field"))?;
    let key_id = &key_df.object_id;
    info!("  Using encryption key: {}", key_id);

    // Step 4: Fetch the encryption key object
    info!("Step 4: Fetching encryption key object...");
    let key_obj = sui
        .read_api()
        .get_object_with_options(key_id.clone(), SuiObjectDataOptions::new().with_content())
        .await?
        .data
        .ok_or_else(|| anyhow::anyhow!("Encryption key object not found"))?;

    // Capture the encryption key ID and version for cache validation
    let encryption_key_id = key_id.to_string();
    let encryption_key_version = key_obj.version.value();
    info!("  Encryption key version: {}", encryption_key_version);

    let key_content = key_obj.content
        .ok_or_else(|| anyhow::anyhow!("Encryption key has no content"))?;

    let key_fields = match &key_content {
        SuiParsedData::MoveObject(obj) => {
            match &obj.fields {
                SuiMoveStruct::WithFields(f) => f,
                SuiMoveStruct::WithTypes { fields, .. } => fields,
                _ => return Err(anyhow::anyhow!("Unexpected key struct format")),
            }
        }
        _ => return Err(anyhow::anyhow!("Expected MoveObject for key")),
    };

    // The key is wrapped in a DynamicField
    let key_value_fields = match key_fields.get("value") {
        Some(SuiMoveValue::Struct(s)) => {
            match s {
                SuiMoveStruct::WithFields(f) => f,
                SuiMoveStruct::WithTypes { fields, .. } => fields,
                _ => return Err(anyhow::anyhow!("Unexpected key value struct format")),
            }
        }
        _ => key_fields,
    };

    // Get the network_dkg_public_output TableVec ID
    // TableVec structure: { contents: Table { id: UID } }
    let net_dkg_field = key_value_fields.get("network_dkg_public_output")
        .ok_or_else(|| anyhow::anyhow!("network_dkg_public_output not found"))?;
    let table_vec_id = extract_nested_id(net_dkg_field, &["contents", "id"])
        .or_else(|| extract_nested_id(net_dkg_field, &["id"]))
        .ok_or_else(|| anyhow::anyhow!("Failed to extract TableVec ID"))?;
    info!("  Found network_dkg_public_output TableVec: {}", table_vec_id);

    // Step 5: Read TableVec chunks
    // Note: The TableVec's contents.id is the table ID for dynamic field queries
    // We can't fetch it directly as an object, but we can query its dynamic fields
    info!("Step 5: Reading TableVec chunks...");
    let table_vec_oid: ObjectID = table_vec_id.parse()?;

    // List all dynamic fields (chunks)
    let mut all_chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut cursor = None;

    loop {
        let chunks_page = sui
            .read_api()
            .get_dynamic_fields(table_vec_oid, cursor, None)
            .await?;

        if chunks_page.data.is_empty() {
            break;
        }

        // Fetch all chunk objects
        let chunk_ids: Vec<ObjectID> = chunks_page.data.iter()
            .map(|df| df.object_id.clone())
            .collect();

        let chunk_objects = sui
            .read_api()
            .multi_get_object_with_options(chunk_ids, SuiObjectDataOptions::new().with_content())
            .await?;

        for (df, obj_response) in chunks_page.data.iter().zip(chunk_objects.iter()) {
            let obj = obj_response.data.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Chunk object not found"))?;

            // Parse the index from the dynamic field name
            let index: u64 = match &df.name.value {
                Value::String(s) => s.parse().unwrap_or(0),
                Value::Number(n) => n.as_u64().unwrap_or(0),
                _ => 0,
            };

            // Extract the byte data from the chunk
            let content = obj.content.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Chunk has no content"))?;

            let chunk_fields = match content {
                SuiParsedData::MoveObject(m) => {
                    match &m.fields {
                        SuiMoveStruct::WithFields(f) => f,
                        SuiMoveStruct::WithTypes { fields, .. } => fields,
                        _ => return Err(anyhow::anyhow!("Unexpected chunk struct format")),
                    }
                }
                _ => return Err(anyhow::anyhow!("Expected MoveObject for chunk")),
            };

            // The chunk data is in the "value" field
            let chunk_data = match chunk_fields.get("value") {
                Some(SuiMoveValue::Vector(v)) => {
                    v.iter().filter_map(|item| {
                        match item {
                            SuiMoveValue::Number(n) => Some(*n as u8),
                            _ => None,
                        }
                    }).collect::<Vec<u8>>()
                }
                Some(SuiMoveValue::String(s)) => {
                    // Sometimes returned as base64 or hex
                    if let Ok(bytes) = BASE64.decode(s) {
                        bytes
                    } else if let Ok(bytes) = hex::decode(s.trim_start_matches("0x")) {
                        bytes
                    } else {
                        s.as_bytes().to_vec()
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected chunk value format")),
            };

            all_chunks.push((index, chunk_data));
        }

        if !chunks_page.has_next_page {
            break;
        }
        cursor = chunks_page.next_cursor;
    }

    if all_chunks.is_empty() {
        return Err(anyhow::anyhow!("No chunks found in TableVec"));
    }

    // Sort by index and concatenate
    all_chunks.sort_by_key(|(idx, _)| *idx);
    let network_dkg_output: Vec<u8> = all_chunks.into_iter()
        .flat_map(|(_, data)| data)
        .collect();

    info!("  Collected {} bytes from TableVec", network_dkg_output.len());

    // Step 6: Convert to protocol public parameters
    info!("Step 6: Converting to protocol public parameters...");
    let t1 = Instant::now();
    let protocol_pp = tokio::task::spawn_blocking(move || {
        dwallet_mpc_centralized_party::network_dkg_public_output_to_protocol_pp_inner(
            0, // SECP256K1
            network_dkg_output,
        )
    })
    .await??;

    info!(
        "  Conversion took {}ms, result: {} bytes",
        t1.elapsed().as_millis(),
        protocol_pp.len()
    );

    // Cache the result
    let mut cache = state.protocol_pp_cache.write().await;
    *cache = Some(ProtocolPPCache {
        protocol_pp,
        encryption_key_id,
        encryption_key_version,
        fetched_at: Instant::now(),
    });

    info!("Protocol PP cached successfully (total: {}ms)", t0.elapsed().as_millis());
    Ok(())
}

async fn check_cache_validity(state: &AppState) -> anyhow::Result<bool> {
    let cache = state.protocol_pp_cache.read().await;
    let cached = match cache.as_ref() {
        Some(c) => c.clone(),
        None => return Ok(false),
    };
    drop(cache);

    let sui = SuiClientBuilder::default()
        .build(&state.sui_rpc_url)
        .await?;

    // Check if the encryption key object version has changed
    let key_id: ObjectID = cached.encryption_key_id.parse()?;
    let obj = sui
        .read_api()
        .get_object_with_options(key_id, SuiObjectDataOptions::default())
        .await?
        .data
        .ok_or_else(|| anyhow::anyhow!("Encryption key object not found"))?;

    let current_version = obj.version.value();

    if current_version != cached.encryption_key_version {
        info!("Cache invalid: encryption key version changed from {} to {}",
            cached.encryption_key_version, current_version);
        return Ok(false);
    }

    Ok(true)
}

async fn sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    let start = Instant::now();

    let req_num = {
        let mut count = state.request_count.write().await;
        *count += 1;
        *count
    };

    info!("[{}] Received sign request", req_num);

    // Get protocol_pp from request, cache, or fetch from chain
    let protocol_pp = if let Some(pp_b64) = &req.protocol_pp {
        match BASE64.decode(pp_b64) {
            Ok(v) => {
                info!("[{}] Using protocol_pp from request ({} bytes)", req_num, v.len());
                v
            }
            Err(e) => {
                error!("[{}] Failed to decode protocol_pp: {}", req_num, e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: format!("Invalid protocol_pp: {}", e) }),
                ).into_response();
            }
        }
    } else {
        // Check cache validity against chain
        match check_cache_validity(&state).await {
            Ok(true) => {
                let cache = state.protocol_pp_cache.read().await;
                if let Some(c) = cache.as_ref() {
                    info!("[{}] Using cached protocol_pp ({} bytes, key version {})",
                        req_num, c.protocol_pp.len(), c.encryption_key_version);
                    c.protocol_pp.clone()
                } else {
                    error!("[{}] Cache empty after validity check", req_num);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "Cache unexpectedly empty".into() }),
                    ).into_response();
                }
            }
            Ok(false) => {
                info!("[{}] Cache invalid, refreshing from chain...", req_num);
                if let Err(e) = fetch_and_cache_protocol_pp(&state).await {
                    error!("[{}] Failed to fetch protocol_pp: {}", req_num, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: format!("Failed to fetch protocol_pp: {}", e) }),
                    ).into_response();
                }
                let cache = state.protocol_pp_cache.read().await;
                cache.as_ref().unwrap().protocol_pp.clone()
            }
            Err(e) => {
                warn!("[{}] Cache validity check failed: {}, using existing cache", req_num, e);
                let cache = state.protocol_pp_cache.read().await;
                match cache.as_ref() {
                    Some(c) => c.protocol_pp.clone(),
                    None => {
                        error!("[{}] No cached protocol_pp available", req_num);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { error: "No protocol_pp available".into() }),
                        ).into_response();
                    }
                }
            }
        }
    };

    let dkg_output = match BASE64.decode(&req.dkg_output) {
        Ok(v) => v,
        Err(e) => {
            error!("[{}] Failed to decode dkg_output: {}", req_num, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid dkg_output: {}", e) }),
            ).into_response();
        }
    };

    let secret_share = match BASE64.decode(&req.secret_share) {
        Ok(v) => v,
        Err(e) => {
            error!("[{}] Failed to decode secret_share: {}", req_num, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid secret_share: {}", e) }),
            ).into_response();
        }
    };

    let presign = match BASE64.decode(&req.presign) {
        Ok(v) => v,
        Err(e) => {
            error!("[{}] Failed to decode presign: {}", req_num, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid presign: {}", e) }),
            ).into_response();
        }
    };

    let message = match BASE64.decode(&req.message) {
        Ok(v) => v,
        Err(e) => {
            error!("[{}] Failed to decode message: {}", req_num, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid message: {}", e) }),
            ).into_response();
        }
    };

    info!(
        "[{}] Input sizes: dkg_output={}, secret_share={}, presign={}, message={}",
        req_num,
        dkg_output.len(),
        secret_share.len(),
        presign.len(),
        message.len()
    );

    let sign_start = Instant::now();
    let curve = req.curve;
    let signature_algorithm = req.signature_algorithm;
    let hash_scheme = req.hash_scheme;

    info!(
        "[{}] Calling advance_centralized_sign_party with curve={}, sig_algo={}, hash={}",
        req_num, curve, signature_algorithm, hash_scheme
    );

    let result = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(|| {
            dwallet_mpc_centralized_party::advance_centralized_sign_party(
                protocol_pp,
                dkg_output,
                secret_share,
                presign,
                message,
                curve,
                signature_algorithm,
                hash_scheme,
            )
        })
    })
    .await;

    let sign_duration = sign_start.elapsed();

    match result {
        Ok(Ok(Ok(signature))) => {
            let total_duration = start.elapsed();
            info!(
                "[{}] Signing complete: {}ms (total: {}ms), signature: {} bytes",
                req_num,
                sign_duration.as_millis(),
                total_duration.as_millis(),
                signature.len()
            );

            (
                StatusCode::OK,
                Json(SignResponse {
                    signature: BASE64.encode(&signature),
                    duration_ms: sign_duration.as_millis() as u64,
                }),
            ).into_response()
        }
        Ok(Ok(Err(e))) => {
            error!("[{}] Signing failed: {}", req_num, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Signing failed: {}", e) }),
            ).into_response()
        }
        Ok(Err(panic_info)) => {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            error!("[{}] Signing panicked: {}", req_num, panic_msg);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Signing panicked: {}", panic_msg) }),
            ).into_response()
        }
        Err(e) => {
            error!("[{}] Task join error: {}", req_num, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Task join error: {}", e) }),
            ).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ika_signing_service=info".parse().unwrap())
        )
        .init();

    let sui_rpc_url = std::env::var("SUI_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
    let coordinator_id = std::env::var("IKA_COORDINATOR_ID")
        .unwrap_or_else(|_| {
            warn!("IKA_COORDINATOR_ID not set - protocol PP must be provided with requests");
            String::new()
        });

    let state = AppState {
        request_count: Arc::new(RwLock::new(0)),
        protocol_pp_cache: Arc::new(RwLock::new(None)),
        sui_rpc_url: sui_rpc_url.clone(),
        coordinator_id: coordinator_id.clone(),
    };

    // Pre-fetch protocol PP if coordinator ID is set
    if !coordinator_id.is_empty() {
        info!("Pre-fetching protocol public parameters from chain...");
        if let Err(e) = fetch_and_cache_protocol_pp(&state).await {
            error!("Failed to pre-fetch protocol PP: {}", e);
            error!("Service will start but will fetch on first request");
        }
    }

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/refresh", post(refresh_cache))
        .route("/sign", post(sign))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3100".to_string());
    let addr = format!("0.0.0.0:{}", port);

    info!("Starting Ika Signing Service on {}", addr);
    info!("Configuration:");
    info!("  SUI_RPC_URL: {}", sui_rpc_url);
    info!("  IKA_COORDINATOR_ID: {}", if coordinator_id.is_empty() { "(not set)" } else { &coordinator_id });
    info!("Endpoints:");
    info!("  GET  /health  - Health check");
    info!("  GET  /status  - Cache status");
    info!("  POST /refresh - Refresh protocol PP cache");
    info!("  POST /sign    - Sign message");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
