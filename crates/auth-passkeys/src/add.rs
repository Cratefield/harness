//! The hosted "Add a passkey" page: `GET /v1/auth-passkeys/add`.
//!
//! An account that signed in some other way — a magic link, an imported
//! account — has no passkey, and a passkey can only be created on a page
//! served from the relying party's own origin: a consuming app on its own
//! domain cannot run the ceremony for this RP id, whatever code it ships.
//! So the service renders the page, the way the login chooser does, and
//! hands the person back to the app afterwards.
//!
//! **Where the person goes back to.** `return_to` is honoured only when it
//! is an absolute `https` URL on the origin of a redirect URI registered
//! for an active client of this instance. Anything else is dropped, and
//! the page ends with a link to this service's own root: the page is never
//! an open redirect. The app learns the result from the URL *fragment*
//! (`#cf_passkey=<credential id>&cf_aaguid=<uuid>&cf_prf=1|0`, or
//! `#cf_passkey_error=cancelled`), which never reaches any server.
//!
//! **Signed out.** The page offers this deployment's link-shaped sign-in
//! methods, each carrying this very page as its `return_to`, so a person
//! comes back here once they are in.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{OriginalUri, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use cratefield_auth_core::page::{HostedPage, escape};
use cratefield_auth_core::{
    Brand, STATUS_ACTIVE, cookie_value, list_clients, redirect_uris_for_client, sign_in_links,
    validate,
};
use cratefield_core::{Database, Problem};
use http::HeaderMap;
use serde::Deserialize;

use crate::ModuleState;

/// Longer than any redirect a client registers, short enough that a page
/// echoing it stays small.
const MAX_RETURN_TO: usize = 2048;

/// Where a person goes when there is no app to go back to.
const SERVICE_ROOT: &str = "/";

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new().route("/add", get(page))
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AddQuery {
    return_to: Option<String>,
}

/// The origin `candidate` may be sent back to, or `None`.
///
/// Pure, so the rule is testable without a database: `registered` is every
/// redirect URI of every active client.
pub(crate) fn allowed_return_to(candidate: &str, registered: &[String]) -> Option<String> {
    let candidate = candidate.trim();
    if candidate.is_empty()
        || candidate.len() > MAX_RETURN_TO
        || candidate.chars().any(char::is_control)
    {
        return None;
    }
    let mut url = url::Url::parse(candidate).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    let known = registered.iter().any(|uri| {
        url::Url::parse(uri).is_ok_and(|uri| {
            uri.scheme() == "https" && uri.origin().ascii_serialization() == origin
        })
    });
    if !known {
        return None;
    }
    // The page writes its own fragment; one the caller brought would be
    // read as part of it.
    url.set_fragment(None);
    Some(url.to_string())
}

/// Every redirect URI registered for an active client.
async fn registered_redirects(db: &dyn Database) -> Result<Vec<String>, Problem> {
    let clients = list_clients(db).await.map_err(|err| {
        tracing::error!(error = %err, "could not list clients");
        Problem::internal()
    })?;
    let mut uris = Vec::new();
    for client in clients.iter().filter(|c| c.status == STATUS_ACTIVE) {
        let rows = redirect_uris_for_client(db, &client.id)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "could not read redirect uris");
                Problem::internal()
            })?;
        uris.extend(rows.into_iter().map(|row| row.uri));
    }
    Ok(uris)
}

async fn page(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
    Query(query): Query<AddQuery>,
) -> Response {
    match render(&state, &headers, &original_uri, &query).await {
        Ok(response) => response,
        Err(problem) => problem.into_response(),
    }
}

async fn render(
    state: &ModuleState,
    headers: &HeaderMap,
    original_uri: &http::Uri,
    query: &AddQuery,
) -> Result<Response, Problem> {
    let brand = Brand::from_config(&*state.ctx.config, &state.ctx.venture);
    let Some(db) = state.ctx.ports.db.as_deref() else {
        return Err(Problem::not_ready("the passkeys module needs db"));
    };
    let Some(clock) = state.ctx.ports.clock.as_deref() else {
        return Err(Problem::not_ready("the passkeys module needs a clock"));
    };

    let return_to = match query.return_to.as_deref() {
        Some(candidate) => allowed_return_to(candidate, &registered_redirects(db).await?),
        None => None,
    };

    let session = match cookie_value(headers) {
        Some(value) => validate(db, clock, &value).await.map_err(|err| {
            tracing::error!(error = %err, "session validation failed");
            Problem::internal()
        })?,
        None => None,
    };

    let body = if session.is_some() {
        signed_in_body(&brand, return_to.as_deref())
    } else {
        // Path and query, never the absolute URI a Worker sees: every
        // provider's `safe_return_to` refuses anything not starting with `/`.
        let here = original_uri
            .path_and_query()
            .map_or("/v1/auth-passkeys/add", |pq| pq.as_str());
        signed_out_body(&brand, &sign_in_links(&*state.ctx.config, here))
    };
    let title = if session.is_some() {
        "Add a passkey"
    } else {
        "Sign in first"
    };
    Ok(HostedPage::new(title).body(body).render(&brand))
}

fn signed_out_body(brand: &Brand, links: &[(String, String)]) -> String {
    let mut body = format!(
        "<h1>Sign in first</h1><p class=\"sub\">A passkey is added to an account you are \
         signed in to. Sign in to {name}, and you will come back here.</p>",
        name = escape(&brand.name),
    );
    if links.is_empty() {
        body.push_str("<p class=\"none\">Sign in from the app, then open this page again.</p>");
    } else {
        body.push_str("<ul class=\"methods\">");
        for (label, href) in links {
            let _ = write!(
                body,
                "<li><a class=\"method\" href=\"{href}\">{label}</a></li>",
                href = escape(href),
                label = escape(label),
            );
        }
        body.push_str("</ul>");
    }
    body
}

fn signed_in_body(brand: &Brand, return_to: Option<&str>) -> String {
    let back = return_to.map_or_else(
        || {
            format!(
                "<p><a class=\"method\" href=\"{SERVICE_ROOT}\">Done, you can close this tab</a></p>"
            )
        },
        |url| {
            format!(
                "<p><a class=\"method\" id=\"cf-back\" href=\"{href}\">Not now, back to the app</a></p>",
                href = escape(&format!("{url}#cf_passkey_error=cancelled")),
            )
        },
    );
    format!(
        "<h1>Add a passkey</h1>\
<p class=\"sub\">Create a passkey for {name} on this device. You will use it to sign in, \
and your device unlocks it with your face, fingerprint or screen lock.</p>\
<div id=\"cf-add\" data-return-to=\"{return_to}\">\
<button class=\"cf-primary\" type=\"button\" id=\"cf-add-passkey\" hidden>Add a passkey</button>\
<p class=\"none\" id=\"cf-no-webauthn\">This browser cannot create passkeys. Try another browser \
or device.</p>\
<p class=\"sub\" id=\"cf-added\" role=\"status\" hidden>Passkey added.</p>\
</div>{back}{script}",
        name = escape(&brand.name),
        return_to = escape(return_to.unwrap_or("")),
        script = SCRIPT,
    )
}

/// The ceremony. `return_to` is read from a data attribute, never
/// interpolated into the script: the attribute is HTML-escaped and nothing
/// would escape a script body.
const SCRIPT: &str = r##"<script>
(function () {
  "use strict";
  var root = document.getElementById("cf-add");
  var button = document.getElementById("cf-add-passkey");
  var unsupported = document.getElementById("cf-no-webauthn");
  var added = document.getElementById("cf-added");
  var back = document.getElementById("cf-back");
  if (!root || !button) return;
  if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) return;
  unsupported.hidden = true;
  button.hidden = false;
  var RETURN_TO = root.getAttribute("data-return-to") || "";

  function fromBase64Url(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var raw = atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function toBase64Url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function withoutNulls(object) {
    var out = {};
    Object.keys(object).forEach(function (key) {
      if (object[key] !== null && object[key] !== undefined) out[key] = object[key];
    });
    return out;
  }

  function toCreationOptions(json) {
    var options = withoutNulls(json);
    if (options.authenticatorSelection) options.authenticatorSelection = withoutNulls(options.authenticatorSelection);
    // PRF, so the passkey can later unlock what the app seals with it.
    options.extensions = Object.assign({}, options.extensions || {}, { prf: {} });
    if (PublicKeyCredential.parseCreationOptionsFromJSON) {
      return PublicKeyCredential.parseCreationOptionsFromJSON(options);
    }
    options.challenge = fromBase64Url(json.challenge);
    options.user = Object.assign({}, json.user, { id: fromBase64Url(json.user.id) });
    options.excludeCredentials = (json.excludeCredentials || []).map(function (item) {
      return withoutNulls(Object.assign({}, item, { id: fromBase64Url(item.id) }));
    });
    return options;
  }

  function toJson(credential) {
    var response = credential.response;
    // Redacted: the PRF output ("results") is never sent to the server —
    // only whether the passkey supports the extension at all.
    var client = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
    var prf = client && client.prf ? { prf: { enabled: client.prf.enabled === true } } : {};
    return {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: credential.type,
      clientExtensionResults: prf,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        attestationObject: toBase64Url(response.attestationObject),
        transports: response.getTransports ? response.getTransports() : []
      }
    };
  }

  function uuid(hex) {
    if (!hex || hex.length !== 32) return "00000000-0000-0000-0000-000000000000";
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  function notify(title, text) {
    var toasts = document.querySelector(".cf-toasts");
    if (!toasts) return;
    var toast = document.createElement("div");
    toast.className = "cf-toast cf-toast-error";
    toast.setAttribute("role", "alert");
    var heading = document.createElement("span");
    heading.className = "cf-toast-title";
    heading.textContent = title;
    var body = document.createElement("span");
    body.className = "cf-toast-text";
    body.textContent = text;
    toast.appendChild(heading);
    toast.appendChild(body);
    toasts.insertBefore(toast, toasts.firstChild);
  }

  button.addEventListener("click", function () {
    button.disabled = true;
    var created;
    var prf = false;
    post("/v1/auth-passkeys/register/options", {})
      .then(function (response) {
        if (!response.ok) throw new Error("options");
        return response.json();
      })
      .then(function (options) {
        return navigator.credentials.create({
          publicKey: toCreationOptions(options.publicKey || options)
        });
      })
      .then(function (credential) {
        if (!credential) throw new Error("cancelled");
        created = credential;
        var results = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
        prf = !!(results && results.prf && results.prf.enabled === true);
        return post("/v1/auth-passkeys/register/verify", { credential: toJson(credential) });
      })
      .then(function (response) {
        if (!response.ok) throw new Error("verify");
        return response.json();
      })
      .then(function (stored) {
        if (!RETURN_TO) {
          button.hidden = true;
          if (added) added.hidden = false;
          return;
        }
        window.location.assign(RETURN_TO +
          "#cf_passkey=" + encodeURIComponent(toBase64Url(created.rawId)) +
          "&cf_aaguid=" + uuid(stored && stored.aaguid) +
          "&cf_prf=" + (prf ? "1" : "0"));
      })
      .catch(function (reason) {
        button.disabled = false;
        if (reason && reason.name === "InvalidStateError") {
          notify("Already added", "This device already has a passkey for this account.");
        } else if (reason && reason.name === "NotAllowedError") {
          notify("Passkey not added", "That was cancelled. Try again, or go back to the app.");
        } else {
          notify("Passkey not added", "That did not work. Try again, or go back to the app.");
        }
        if (back) back.hidden = false;
      });
  });
})();
</script>"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn registered() -> Vec<String> {
        vec![
            "https://app.example/auth/callback".to_owned(),
            "http://localhost:5173/auth/callback".to_owned(),
        ]
    }

    #[test]
    fn a_registered_origin_is_accepted_with_its_fragment_dropped() {
        assert_eq!(
            allowed_return_to("https://app.example/home?x=1#old", &registered()).as_deref(),
            Some("https://app.example/home?x=1")
        );
    }

    #[test]
    fn anything_else_is_refused() {
        for candidate in [
            "https://evil.example/",
            "https://app.example.evil.example/",
            "http://app.example/",
            "http://localhost:5173/",
            "//app.example/",
            "/relative",
            "javascript:alert(1)",
            "https://user@app.example/",
            "https://app.example:8443/",
            "",
        ] {
            assert_eq!(
                allowed_return_to(candidate, &registered()),
                None,
                "{candidate}"
            );
        }
    }
}
