//! The browser half of "add a passkey": one script, shared by the hosted
//! "Add a passkey" page ([`crate::add`]) and the sign-in passkey offer
//! ([`crate::offer`]), so both run the same registration ceremony against
//! `register/options` and `register/verify`, and both are gated by the same
//! enrolment check on the server.
//!
//! The script publishes `window.cfPasskey` with three members:
//!
//! - `supported()`: whether this browser can create a passkey at all.
//! - `add()`: runs the ceremony and resolves to `{ rawId, aaguid, prf }`, or
//!   rejects with the reason (a `DOMException` name, or `options` when the
//!   server refused to start a ceremony, for instance on a stale session).
//! - `explain(reason)`: a `{ title, text }` a page can show for a rejection.
//!
//! The PRF output is never sent to the server; only whether the passkey can
//! evaluate the extension at all is (see the comment in `toJson`).

/// The ceremony, without its `<script>` tags: wrap it with [`script`].
pub(crate) const CEREMONY_JS: &str = r#"(function () {
  "use strict";

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

  window.cfPasskey = {
    supported: function () {
      return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    },
    add: function () {
      var created;
      var prf = false;
      return post("/v1/auth-passkeys/register/options", {})
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
          return {
            rawId: toBase64Url(created.rawId),
            aaguid: uuid(stored && stored.aaguid),
            prf: prf
          };
        });
    },
    explain: function (reason) {
      if (reason && reason.name === "InvalidStateError") {
        return { title: "Already added", text: "This device already has a passkey for this account." };
      }
      if (reason && reason.name === "NotAllowedError") {
        return { title: "Passkey not added", text: "That was cancelled. Try again." };
      }
      if (reason && reason.message === "options") {
        return { title: "Passkey not added", text: "Your sign-in is too old to add a passkey. Continue, and add one later." };
      }
      return { title: "Passkey not added", text: "That did not work. Try again." };
    }
  };
})();"#;

/// Wraps a script body in a `<script>` element.
pub(crate) fn script(body: &str) -> String {
    format!("<script>{body}</script>")
}
