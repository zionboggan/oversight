use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum RegistryError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal: {0}")]
    Internal(String),
}

impl RegistryError {
    fn code_for_bad_request(message: &str) -> &'static str {
        if message.contains("signature") {
            return "signature_invalid";
        }
        if message.contains("beacons do not match") || message.contains("watermarks do not match") {
            return "sidecar_mismatch";
        }
        "missing_field"
    }

    fn envelope_code(&self, message: &str) -> &'static str {
        match self {
            RegistryError::BadRequest(_) => Self::code_for_bad_request(message),
            RegistryError::NotFound(_) => "not_found",
            RegistryError::Conflict(_) => "issuer_mismatch",
            RegistryError::Unauthorized(_) => "auth_required",
            RegistryError::RateLimited => "rate_limited",
            RegistryError::Database(_) | RegistryError::Internal(_) => "server_error",
        }
    }
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            RegistryError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            RegistryError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            RegistryError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            RegistryError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            RegistryError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into())
            }
            RegistryError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
            }
            RegistryError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        match status.as_u16() {
            400..=499 => tracing::debug!(%status, %message, "client error"),
            _ => tracing::error!(%status, %message, "server error"),
        }

        let code = self.envelope_code(&message);
        let body = serde_json::json!({
            "error": {
                "code": code,
                "message": message,
            },
        });
        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, RegistryError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_error_codes_match_v1_envelope() {
        assert_eq!(
            RegistryError::BadRequest("manifest signature invalid".into())
                .envelope_code("manifest signature invalid"),
            "signature_invalid"
        );
        assert_eq!(
            RegistryError::BadRequest("request beacons do not match signed manifest".into())
                .envelope_code("request beacons do not match signed manifest"),
            "sidecar_mismatch"
        );
        assert_eq!(
            RegistryError::Unauthorized("operator authentication required".into())
                .envelope_code("operator authentication required"),
            "auth_required"
        );
        assert_eq!(
            RegistryError::NotFound("unknown file_id".into()).envelope_code("unknown file_id"),
            "not_found"
        );
    }
}
