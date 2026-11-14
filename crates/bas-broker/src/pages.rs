//! Approval pages, published to the approver with `tailscale serve`. On Linux they listen on
//! a loopback port below 1024. On macOS they listen on a unix socket, mode 0600, in the
//! broker's runtime directory, which tailscaled reaches because it runs as root.
//!
//! - `GET /` lists pending requests.
//! - `GET /a/ID` shows one request. The broker writes all of the text from what it
//!   recorded and from the kernel's peer credentials.
//! - `POST /a/ID/begin` issues a WebAuthn challenge stored with request ID.
//! - `POST /a/ID/finish` takes `{"credential": <assertion>, "value": "..."}`. Without an
//!   assertion that verifies against one of that request's challenges, with user
//!   verification, it replies 403 and the request stays pending.
//! - `POST /a/ID/deny` denies the request. Denying grants nothing, so it needs no passkey.
//! - `GET /enroll/TOKEN`, `POST /enroll/TOKEN/begin`, `POST /enroll/TOKEN/finish` enroll a
//!   passkey through an enrollment link. `begin` takes `{"label": "..."}` and refuses a
//!   name that a passkey which stays enrolled already has.
//!
//! Every POST must carry the `Origin` of `approvals.origin`, so a page on another origin
//! cannot deny requests or start ceremonies from the approval page.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ORIGIN, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bas_core::Uuid;
use bas_core::credential::SecretText;
use serde::Deserialize;
use tokio::net::TcpListener;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};
use zeroize::Zeroizing;

use crate::approvals::{self, Kind, Outcome, View};
use crate::config::Listen;
use crate::files::bind_socket;
use crate::passkeys::Refused;
use crate::protocol::PasskeySummary;
use crate::state::Broker;
use crate::{Error, audit};

/// Longest secret value the page accepts, in bytes.
const MAX_VALUE: usize = 64 * 1024;

const SCRIPT: &str = include_str!("pages/bas.js");
const STYLE: &str = include_str!("pages/bas.css");

/// Binds the approval port or socket and returns the future that serves it.
pub async fn start(
    listen: &Listen,
    broker: Arc<Broker>,
) -> Result<impl Future<Output = Result<(), Error>>, Error> {
    let app = Router::new()
        .route("/", get(index))
        .route("/bas.js", get(script))
        .route("/bas.css", get(style))
        .route("/a/{id}", get(approval_page))
        .route("/a/{id}/begin", post(begin))
        .route("/a/{id}/finish", post(finish))
        .route("/a/{id}/deny", post(deny))
        .route("/enroll/{token}", get(enroll_page))
        .route("/enroll/{token}/begin", post(enroll_begin))
        .route("/enroll/{token}/finish", post(enroll_finish))
        .with_state(broker);
    let stopped = |err: std::io::Error| Error::new(format!("the approval pages stopped: {err}"));
    let served: std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> = match listen {
        Listen::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| Error::new(format!("could not listen on {addr}: {err}")))?;
            Box::pin(async move { axum::serve(listener, app).await.map_err(stopped) })
        }
        Listen::Unix(path) => {
            let listener = bind_socket(path, 0o600)?;
            Box::pin(async move { axum::serve(listener, app).await.map_err(stopped) })
        }
    };
    Ok(served)
}

/// Headers every reply carries: no caching, no framing, scripts from this origin only.
fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    let set = [
        (CACHE_CONTROL, "no-store"),
        (
            CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
        (REFERRER_POLICY, "no-referrer"),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
    ];
    for (name, value) in set {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

fn html(status: StatusCode, title: &str, body: &str, data: &[(&str, &str)]) -> Response {
    let mut attributes = String::new();
    for (key, value) in data {
        let _ = write!(attributes, " data-{key}=\"{}\"", escape(value));
    }
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><link rel=\"stylesheet\" href=\"/bas.css\"></head>\
         <body{attributes}><main><h1>{title}</h1>{body}</main>\
         <script src=\"/bas.js\"></script></body></html>",
        title = escape(title)
    );
    harden((status, [(CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response())
}

fn json_error(status: StatusCode, error: &str) -> Response {
    harden((status, Json(serde_json::json!({ "error": error }))).into_response())
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Whether a POST came from a page on the approval origin.
fn same_origin(broker: &Broker, headers: &HeaderMap) -> bool {
    let expected = broker
        .config
        .approvals_origin
        .origin()
        .ascii_serialization();
    headers
        .get(ORIGIN)
        .and_then(|origin| origin.to_str().ok())
        .is_some_and(|origin| origin == expected)
}

async fn script() -> Response {
    harden(([(CONTENT_TYPE, "text/javascript; charset=utf-8")], SCRIPT).into_response())
}

async fn style() -> Response {
    harden(([(CONTENT_TYPE, "text/css; charset=utf-8")], STYLE).into_response())
}

async fn index(State(broker): State<Arc<Broker>>) -> Response {
    let pending = broker.approvals.pending();
    let mut body = String::new();
    if broker.passkeys.count() == 0 {
        body.push_str(
            "<p class=\"warn\">No passkey is enrolled. Open the one-time link from \
             <code>enroll-url</code> in the broker's state directory.</p>",
        );
    }
    if pending.is_empty() {
        body.push_str("<p>Nothing waits for approval.</p>");
    } else {
        body.push_str("<ul class=\"list\">");
        for view in &pending {
            let id = view.id.hyphenated().to_string();
            let _ = write!(
                body,
                "<li><a href=\"/a/{id}\">{}</a> <span class=\"muted\">uid {} at {}</span></li>",
                escape(&title(&view.kind)),
                view.peer.uid,
                escape(&view.created_at)
            );
        }
        body.push_str("</ul>");
    }
    html(StatusCode::OK, "bas approvals", &body, &[])
}

fn title(kind: &Kind) -> String {
    match kind {
        Kind::AddSecret { name, .. } => format!("Add secret {name}"),
        Kind::Rotate { name, .. } => format!("Rotate secret {name}"),
        Kind::Policy { .. } => "Change the policy".to_owned(),
        Kind::Passkey { replace: false } => "Enroll another passkey".to_owned(),
        Kind::Passkey { replace: true } => "Replace all passkeys".to_owned(),
    }
}

fn state_label(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Pending => "pending",
        Outcome::Approved(_) => "approved",
        Outcome::Denied => "denied",
        Outcome::Expired => "expired",
        Outcome::Failed(_) => "failed",
    }
}

async fn approval_page(State(broker): State<Arc<Broker>>, Path(id): Path<String>) -> Response {
    let Some(view) = Uuid::parse_str(&id)
        .ok()
        .and_then(|id| broker.approvals.view(id))
    else {
        return html(
            StatusCode::NOT_FOUND,
            "No such request",
            "<p>The request does not exist, or it finished more than an hour ago.</p>",
            &[],
        );
    };
    let body = describe(&view, &broker.passkeys.list());
    let id = view.id.hyphenated().to_string();
    let value = if view.kind.needs_value() { "1" } else { "0" };
    let state = state_label(&view.outcome);
    html(
        StatusCode::OK,
        &title(&view.kind),
        &body,
        &[
            ("page", "approve"),
            ("id", &id),
            ("value", value),
            ("state", state),
        ],
    )
}

/// The approval page's text. `enrolled` names the passkeys a replace would remove.
fn describe(view: &View, enrolled: &[PasskeySummary]) -> String {
    let mut body = String::from("<dl>");
    let pid = view
        .peer
        .pid
        .map_or_else(|| "unknown".to_owned(), |pid| pid.to_string());
    let _ = write!(
        body,
        "<dt>Asked by</dt><dd>uid {}, pid {} <span class=\"muted\">(from the kernel)</span></dd>\
         <dt>Asked at</dt><dd>{}</dd><dt>State</dt><dd id=\"state\">{}</dd>",
        view.peer.uid,
        pid,
        escape(&view.created_at),
        state_label(&view.outcome)
    );
    if matches!(view.outcome, Outcome::Pending) {
        let _ = write!(
            body,
            "<dt>Expires in</dt><dd>{} min</dd>",
            view.expires_in.div_ceil(60)
        );
    }
    match &view.kind {
        Kind::AddSecret { name, entry } => {
            let _ = write!(
                body,
                "<dt>Name</dt><dd><code>{}</code></dd><dt>Delivery</dt><dd>{}</dd>\
                 <dt>Host</dt><dd><code>{}</code></dd><dt>Header</dt><dd><code>{}: {}</code></dd>\
                 <dt>Allowed requests</dt><dd><code>{}</code></dd></dl>",
                escape(name),
                escape(&entry.delivery),
                escape(entry.host.as_deref().unwrap_or("")),
                escape(entry.header.as_deref().unwrap_or("")),
                escape(entry.value.as_deref().unwrap_or("")),
                escape(&entry.allow.clone().unwrap_or_default().join(", "))
            );
            body.push_str(
                "<p>Approving creates the secret in Bitwarden with the value below and adds \
                 the entry to the active policy.</p>",
            );
        }
        Kind::Rotate { name, reference } => {
            let _ = write!(
                body,
                "<dt>Name</dt><dd><code>{}</code></dd><dt>Secret</dt><dd><code>{}</code></dd></dl>\
                 <p>Approving replaces the stored value with the value below.</p>",
                escape(name),
                escape(&reference.to_string())
            );
        }
        Kind::Policy { diff, .. } => {
            body.push_str(
                "</dl><p>Approving makes this the active policy.</p><pre class=\"diff\">",
            );
            for line in diff.lines() {
                let class = match line.as_bytes().first() {
                    Some(b'+') if !line.starts_with("+++") => "add",
                    Some(b'-') if !line.starts_with("---") => "del",
                    Some(b'@') => "hunk",
                    _ => "ctx",
                };
                let _ = writeln!(body, "<span class=\"{class}\">{}</span>", escape(line));
            }
            body.push_str("</pre>");
        }
        Kind::Passkey { replace: false } => {
            body.push_str(
                "</dl><p>Approving shows a one-time link, valid for 15 minutes, that enrolls \
                 one more passkey.</p>",
            );
        }
        Kind::Passkey { replace: true } => {
            body.push_str(
                "</dl><p>Approving shows a link, valid for 15 minutes, that enrolls one or \
                 more passkeys.</p><p class=\"warn\">This replaces all passkeys. The first \
                 passkey enrolled through the link removes every passkey that is enrolled \
                 when you approve. After that, only passkeys enrolled through the link can \
                 approve.</p>",
            );
            if matches!(view.outcome, Outcome::Pending) {
                body.push_str("<p>Enrolled now, and removed by the first enrollment:</p><ul>");
                for passkey in enrolled {
                    let _ = write!(
                        body,
                        "<li>{} <span class=\"muted\">added {}</span></li>",
                        escape(&passkey.label),
                        escape(&passkey.added)
                    );
                }
                body.push_str("</ul>");
            }
        }
    }
    if matches!(view.outcome, Outcome::Pending) {
        if view.kind.needs_value() {
            body.push_str(
                "<label for=\"value\">Value</label><input id=\"value\" type=\"password\" \
                 autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\">",
            );
        }
        body.push_str(
            "<div class=\"actions\"><button id=\"approve\">Approve with passkey</button>\
             <button id=\"deny\" class=\"secondary\">Deny</button></div>",
        );
    }
    body.push_str("<p id=\"status\" role=\"status\"></p>");
    body
}

fn approval_id(raw: &str) -> Option<Uuid> {
    Uuid::parse_str(raw).ok()
}

fn refused_step(err: &approvals::Refused) -> Response {
    match err {
        approvals::Refused::Unknown => json_error(StatusCode::NOT_FOUND, "no such request"),
        approvals::Refused::NotPending => {
            json_error(StatusCode::CONFLICT, "the request is no longer pending")
        }
        approvals::Refused::NoChallenge => json_error(
            StatusCode::FORBIDDEN,
            "no valid assertion: no challenge was issued for this request",
        ),
    }
}

async fn begin(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&broker, &headers) {
        return json_error(StatusCode::FORBIDDEN, "wrong origin");
    }
    let Some(id) = approval_id(&id) else {
        return json_error(StatusCode::NOT_FOUND, "no such request");
    };
    let (challenge, state) = match broker.passkeys.begin_assertion() {
        Ok(started) => started,
        Err(Refused::Ceremony(reason)) => return json_error(StatusCode::CONFLICT, &reason),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "could not start"),
    };
    if let Err(err) = broker.approvals.set_challenge(id, state) {
        return refused_step(&err);
    }
    harden(Json(challenge).into_response())
}

#[derive(Deserialize)]
struct Answer {
    credential: PublicKeyCredential,
    value: Option<String>,
}

async fn finish(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !same_origin(&broker, &headers) {
        return json_error(StatusCode::FORBIDDEN, "wrong origin");
    }
    let Some(id) = approval_id(&id) else {
        return json_error(StatusCode::NOT_FOUND, "no such request");
    };
    let id_text = id.hyphenated().to_string();
    let (kind, challenges) = match broker.approvals.challenges(id) {
        Ok(found) => found,
        Err(err) => {
            if let Some(view) = broker.approvals.view(id) {
                audit::deny_approval(
                    &id_text,
                    view.kind.label(),
                    &view.kind.subject(),
                    "an answer without a challenge",
                );
            }
            return refused_step(&err);
        }
    };
    let Ok(answer) = serde_json::from_slice::<Answer>(&body) else {
        audit::deny_approval(&id_text, kind.label(), &kind.subject(), "no assertion");
        return json_error(StatusCode::FORBIDDEN, "no valid assertion");
    };
    let value = match (kind.needs_value(), answer.value) {
        (true, Some(value)) if !value.is_empty() && value.len() <= MAX_VALUE => {
            Some(SecretText::new(value))
        }
        (true, value) => {
            drop(value.map(Zeroizing::new));
            return json_error(
                StatusCode::BAD_REQUEST,
                "type a value of at most 64 KiB before approving",
            );
        }
        (false, _) => None,
    };
    let mut verified = None;
    let mut reason = String::from("no challenge matched");
    for challenge in &challenges {
        match broker
            .passkeys
            .finish_assertion(&answer.credential, challenge)
        {
            Ok(label) => {
                verified = Some(label);
                break;
            }
            Err(Refused::Ceremony(why)) => reason = why,
            Err(Refused::Storage(err)) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            Err(Refused::NoLink) => {}
        }
    }
    let Some(label) = verified else {
        audit::deny_approval(&id_text, kind.label(), &kind.subject(), &reason);
        return json_error(StatusCode::FORBIDDEN, "no valid assertion");
    };
    if let Err(err) = broker.approvals.start_applying(id) {
        return refused_step(&err);
    }
    audit::approve(
        &id_text,
        kind.label(),
        &format!("{} by {label}", kind.subject()),
    );
    // A spawned task finishes the request even when the client hangs up mid-apply.
    let applying = tokio::spawn(async move {
        let applied = broker.apply(id, &kind, value).await;
        let reply = match &applied.outcome {
            Outcome::Approved(result) => serde_json::json!({
                "state": "approved",
                "result": result,
                "enroll_url": applied.enroll_url,
            }),
            Outcome::Failed(error) => serde_json::json!({ "state": "failed", "error": error }),
            other => serde_json::json!({ "state": state_label(other) }),
        };
        broker.approvals.finish(id, applied.outcome);
        reply
    });
    match applying.await {
        Ok(reply) => harden(Json(reply).into_response()),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

async fn deny(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&broker, &headers) {
        return json_error(StatusCode::FORBIDDEN, "wrong origin");
    }
    let Some(id) = approval_id(&id) else {
        return json_error(StatusCode::NOT_FOUND, "no such request");
    };
    match broker.approvals.deny(id) {
        Ok(kind) => {
            audit::deny_approval(
                &id.hyphenated().to_string(),
                kind.label(),
                &kind.subject(),
                "denied on the approval page",
            );
            harden(Json(serde_json::json!({ "state": "denied" })).into_response())
        }
        Err(err) => refused_step(&err),
    }
}

async fn enroll_page(State(broker): State<Arc<Broker>>, Path(token): Path<String>) -> Response {
    let Some(replaces) = broker.passkeys.link_replaces(&token) else {
        return html(
            StatusCode::NOT_FOUND,
            "Link not valid",
            "<p>This enrollment link was used, expired, or never existed.</p>",
            &[],
        );
    };
    let mut body = String::from(
        "<p>This enrolls a passkey that approves bas requests. It can live in a password \
         manager, on this device, or on a security key. Each approval asks it to verify \
         you.</p>",
    );
    if replaces {
        body.push_str(
            "<p class=\"warn\">This link replaces all passkeys. The first passkey you enroll \
             here removes every passkey enrolled before the link was made. You can enroll \
             more passkeys here until the link expires.</p>",
        );
    }
    body.push_str(
        "<label for=\"label\">Name for this passkey</label>\
         <input id=\"label\" type=\"text\" autocomplete=\"off\" maxlength=\"64\">\
         <div class=\"actions\"><button id=\"enroll\">Create passkey</button></div>\
         <p id=\"status\" role=\"status\"></p>",
    );
    html(
        StatusCode::OK,
        "Enroll a passkey",
        &body,
        &[
            ("page", "enroll"),
            ("token", &token),
            ("again", if replaces { "1" } else { "0" }),
        ],
    )
}

async fn enroll_begin(
    State(broker): State<Arc<Broker>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !same_origin(&broker, &headers) {
        return json_error(StatusCode::FORBIDDEN, "wrong origin");
    }
    let Ok(start) = serde_json::from_slice::<EnrollStart>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "send the passkey's name as JSON");
    };
    match broker.passkeys.begin_enroll(&token, &start.label) {
        Ok(challenge) => harden(Json(challenge).into_response()),
        Err(err) => enroll_refused(&err),
    }
}

#[derive(Deserialize)]
struct EnrollStart {
    #[serde(default)]
    label: String,
}

#[derive(Deserialize)]
struct Enrollment {
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: String,
}

async fn enroll_finish(
    State(broker): State<Arc<Broker>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !same_origin(&broker, &headers) {
        return json_error(StatusCode::FORBIDDEN, "wrong origin");
    }
    let Ok(enrollment) = serde_json::from_slice::<Enrollment>(&body) else {
        return json_error(StatusCode::FORBIDDEN, "no valid passkey");
    };
    match broker
        .passkeys
        .finish_enroll(&token, &enrollment.credential, &enrollment.label)
    {
        Ok(removed) => harden(
            Json(serde_json::json!({ "state": "enrolled", "removed": removed })).into_response(),
        ),
        Err(err) => enroll_refused(&err),
    }
}

fn enroll_refused(err: &Refused) -> Response {
    match err {
        Refused::NoLink => json_error(StatusCode::NOT_FOUND, "the link is not valid"),
        Refused::Ceremony(reason) => json_error(StatusCode::FORBIDDEN, reason),
        Refused::Storage(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}
