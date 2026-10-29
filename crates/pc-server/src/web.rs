//! Auslieferung der eingebetteten Web-Oberfläche (React-Build aus `web/dist`).

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "Unbekannter API-Pfad").into_response();
    }
    if let Some(resp) = serve(path) {
        return resp;
    }
    // SPA: alle anderen Pfade liefern index.html (Client-Routing)
    serve("index.html").unwrap_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "Web-Oberfläche nicht gebaut – im Ordner web/ `npm run build` ausführen.",
        )
            .into_response()
    })
}

fn serve(path: &str) -> Option<Response> {
    if path.is_empty() {
        return None;
    }
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    // Gehashte Assets dürfen lange gecacht werden, index.html nie
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    Some(
        (
            [
                (header::CONTENT_TYPE, mime.as_ref().to_string()),
                (header::CACHE_CONTROL, cache.to_string()),
            ],
            file.data.into_owned(),
        )
            .into_response(),
    )
}
