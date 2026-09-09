//! `HttpClient` over `reqwest` (rustls, ring provider, webpki roots —
//! no OpenSSL, no native-tls): the native counterpart of
//! `worker::Fetch`. Adapters (Resend, Turnstile) run unchanged over
//! either.
//!
//! This is the runtime that opens real sockets, so it is where the port's
//! outbound bounds (issue #136) are enforced for real: the response cap is
//! applied while streaming (an oversized body is refused before its last
//! bytes are allocated), the deadline runs against the whole exchange,
//! every destination is vetted — scheme, userinfo, IP literal or every
//! address a name resolves to — and redirects are followed by the manual
//! loop below, re-vetting each hop. `reqwest`'s own redirect policy is
//! disabled because it would chase an attacker-chosen `Location` before
//! any of this module saw it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    HttpClient, HttpError, HttpPolicy, MAX_CONCURRENT_REQUESTS, declared_content_length,
};
use http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, LOCATION, PROXY_AUTHORIZATION,
};
use reqwest::Url;
use tokio::sync::Semaphore;

/// Redirect hops followed before the request is failed — the bound
/// `reqwest`'s default policy carries.
const MAX_REDIRECTS: usize = 10;

/// Marker the [`GuardResolver`] puts in its errors so `send` can tell a
/// policy refusal from transport noise (reqwest boxes resolver errors).
const GUARD_TAG: &str = "blocked-by-outbound-policy";

/// Name suffixes that are metadata/private-service aliases wherever they
/// appear (`.internal` is Google's; `.local` is mDNS's).
const BLOCKED_HOST_SUFFIXES: [&str; 3] = [".internal", ".internal.", ".local"];

/// Exact hostnames that name a metadata endpoint on the major clouds.
/// Refused by name before any resolver is consulted, because the danger
/// is what they resolve *to* on a VM.
const BLOCKED_HOSTS: [&str; 3] = ["metadata", "metadata.google", "metadata.google.internal"];

/// Outbound hardening knobs for [`ReqwestClient`]. The defaults are the
/// hardened ones: a deployment loosens them field by field, deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundOptions {
    /// Allow destinations whose address is loopback. Off by default: the
    /// native process must not be pointed at services on its own host.
    /// A self-hosted deployment that *intends* to call a local sidecar
    /// turns this on; private ranges and metadata stay blocked either
    /// way.
    pub allow_loopback: bool,
    /// Concurrent outbound requests this process may have in flight —
    /// the per-tenant budget (one native process serves one venture).
    /// Past it, requests are refused, not queued.
    pub max_concurrent: usize,
}

impl Default for OutboundOptions {
    fn default() -> Self {
        Self {
            allow_loopback: false,
            max_concurrent: MAX_CONCURRENT_REQUESTS,
        }
    }
}

/// A shared reqwest client. Built once per process (the connection pool
/// is the `Client`); cheap to `Arc`, clone-free on the hot path.
pub struct ReqwestClient {
    client: reqwest::Client,
    budget: Arc<Semaphore>,
    allow_loopback: bool,
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestClient {
    /// The hardened client: loopback, private and metadata destinations
    /// refused, default concurrency budget.
    ///
    /// # Panics
    ///
    /// Only if the rustls backend cannot initialize, which a static
    /// webpki-roots configuration cannot do at runtime — a startup-time
    /// invariant, the same class as core's `HmacSigner::new` panic.
    #[must_use]
    pub fn new() -> Self {
        Self::with_options(OutboundOptions::default())
    }

    /// The client with explicit hardening knobs — see [`OutboundOptions`].
    /// Zero permits are clamped to one: a never-serving client is a
    /// misconfiguration, not a mode.
    ///
    /// # Panics
    ///
    /// As [`ReqwestClient::new`].
    #[must_use]
    pub fn with_options(options: OutboundOptions) -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                // Re-vet every name the pool dials. The checks in `send`
                // run first; this closes the check-then-connect window
                // (a rebinding server answers the two lookups
                // differently only if we let it).
                .dns_resolver(Arc::new(GuardResolver {
                    allow_loopback: options.allow_loopback,
                }))
                .build()
                .expect("reqwest initializes: rustls with webpki roots is static"),
            budget: Arc::new(Semaphore::new(options.max_concurrent.max(1))),
            allow_loopback: options.allow_loopback,
        }
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let policy = HttpPolicy::of_request(&request);
        let permit = Arc::clone(&self.budget).try_acquire_owned().map_err(|_| {
            HttpError::Transport("outbound concurrency budget exhausted".to_owned())
        })?;
        let start = tokio::time::Instant::now();

        let (parts, mut body) = request.into_parts();
        let mut method = parts.method;
        let mut headers = parts.headers;
        let mut url = Url::parse(&parts.uri.to_string())
            .map_err(|err| HttpError::Transport(format!("invalid request uri: {err}")))?;
        vet_static(&url, self.allow_loopback)?;
        vet_resolved_host(&url, self.allow_loopback).await?;

        let response = self
            .exchange_until_final(
                policy,
                &mut method,
                &mut headers,
                &mut body,
                &mut url,
                start,
            )
            .await?;

        if let Some(declared) = declared_content_length(response.headers())
            && declared > policy.max_response_bytes
        {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }
        let status = response.status();
        let headers_out = response.headers().clone();
        let bytes = read_capped(response, policy.max_response_bytes).await?;
        // The permit lives to here: the budget covers the whole exchange,
        // not just the connect.
        drop(permit);
        let mut builder = http::Response::builder().status(status);
        if let Some(target) = builder.headers_mut() {
            *target = headers_out;
        }
        builder
            .body(bytes)
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

impl ReqwestClient {
    /// Sends, following vetted redirects until a non-3xx answer (or a
    /// 3xx without a usable `Location`) comes back.
    async fn exchange_until_final(
        &self,
        policy: HttpPolicy,
        method: &mut http::Method,
        headers: &mut http::HeaderMap,
        body: &mut Bytes,
        url: &mut Url,
        start: tokio::time::Instant,
    ) -> Result<reqwest::Response, HttpError> {
        for hop in 0.. {
            let remaining = policy.timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(HttpError::DeadlineExceeded {
                    after: policy.timeout,
                });
            }
            let mut builder = self
                .client
                .request(method.clone(), url.clone())
                .timeout(remaining);
            for (name, value) in headers.iter() {
                builder = builder.header(name.clone(), value.clone());
            }
            if !body.is_empty() {
                builder = builder.body(body.clone());
            }
            let response = match builder.send().await {
                Ok(response) => response,
                Err(err) if err.is_timeout() => {
                    return Err(HttpError::DeadlineExceeded {
                        after: policy.timeout,
                    });
                }
                Err(err) if err.is_connect() && err.to_string().contains(GUARD_TAG) => {
                    return Err(HttpError::BlockedDestination(err.to_string()));
                }
                Err(err) => return Err(HttpError::Transport(err.to_string())),
            };
            let status = response.status();
            if !is_redirect(status) {
                return Ok(response);
            }
            let Some(next) = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| url.join(value).ok())
            else {
                // A 3xx without a usable Location is the answer.
                return Ok(response);
            };
            if hop == MAX_REDIRECTS {
                return Err(HttpError::Transport(format!(
                    "redirect limit ({MAX_REDIRECTS}) exceeded"
                )));
            }
            vet_static(&next, self.allow_loopback)?;
            vet_resolved_host(&next, self.allow_loopback).await?;
            if next.authority() != url.authority() {
                // Cross-origin hop: credentials were for the host we were
                // told to call, never for one it redirects to.
                headers.remove(AUTHORIZATION);
                headers.remove(COOKIE);
                headers.remove(PROXY_AUTHORIZATION);
            }
            if redirect_changes_method(status, method) {
                *method = http::Method::GET;
                *body = Bytes::new();
                headers.remove(CONTENT_TYPE);
                headers.remove(CONTENT_LENGTH);
            }
            *url = next;
        }
        unreachable!("bounded by the MAX_REDIRECTS return")
    }
}

fn is_redirect(status: http::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn redirect_changes_method(status: http::StatusCode, method: &http::Method) -> bool {
    match status.as_u16() {
        303 => *method != http::Method::GET && *method != http::Method::HEAD,
        301 | 302 => *method == http::Method::POST,
        _ => false,
    }
}

/// Reads the body chunk by chunk, refusing the moment the accumulated
/// size would cross `limit` — an oversized response is rejected before
/// its last bytes are ever allocated (issue #136).
async fn read_capped(mut response: reqwest::Response, limit: usize) -> Result<Bytes, HttpError> {
    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| HttpError::Transport(err.to_string()))?
    {
        if buffer.len() + chunk.len() > limit {
            return Err(HttpError::ResponseTooLarge { limit });
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buffer))
}

/// Every check that needs no network: scheme, userinfo, and the host —
/// as an IP literal it is vetted directly (the `url` crate has already
/// normalized decimal/octal/hex encodings into a real address), as a
/// name only against the metadata/loopback names.
fn vet_static(url: &Url, allow_loopback: bool) -> Result<(), HttpError> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(HttpError::BlockedDestination(format!(
            "scheme `{}` is not allowed",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpError::BlockedDestination(
            "userinfo in a request uri is not allowed".to_owned(),
        ));
    }
    let Some(raw) = url.host_str() else {
        return Err(HttpError::BlockedDestination("url has no host".to_owned()));
    };
    if let Some(v6) = raw
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
    {
        return vet_ip_with(IpAddr::V6(v6), allow_loopback);
    }
    if let Ok(v4) = raw.parse::<Ipv4Addr>() {
        return vet_ip_with(IpAddr::V4(v4), allow_loopback);
    }
    vet_domain(raw)
}

/// The checks a name must pass *before* a resolver is consulted.
/// Everything else about a name is judged by its addresses, in
/// [`vet_resolved_host`] and [`GuardResolver`].
fn vet_domain(name: &str) -> Result<(), HttpError> {
    let lower = name.to_ascii_lowercase();
    let trimmed = lower.strip_suffix('.').unwrap_or(&lower);
    let refused = |what: &str| Err(HttpError::BlockedDestination(format!("`{name}` {what}")));
    if trimmed == "localhost" || trimmed.ends_with(".localhost") {
        // Loopback under another name — refused by name here so the
        // answer never depends on whether /etc/hosts or DNS resolves it.
        return refused("is a loopback name");
    }
    if BLOCKED_HOSTS.contains(&trimmed)
        || BLOCKED_HOST_SUFFIXES
            .iter()
            .any(|suffix| trimmed.ends_with(suffix))
    {
        return refused("names a private or metadata service");
    }
    Ok(())
}

/// Async half of host vetting: a domain host is resolved and *every*
/// address it answers is vetted. Fail closed — a name nothing resolves
/// to is refused, and a rebinding server's second lookup is covered by
/// [`GuardResolver`] at connect time.
async fn vet_resolved_host(url: &Url, allow_loopback: bool) -> Result<(), HttpError> {
    let Some(raw) = url.host_str() else {
        return Err(HttpError::BlockedDestination("url has no host".to_owned()));
    };
    if raw.parse::<Ipv4Addr>().is_ok()
        || raw
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .is_some_and(|inner| inner.parse::<Ipv6Addr>().is_ok())
    {
        return Ok(());
    }
    let addrs = resolve(raw).await.map_err(|err| {
        HttpError::BlockedDestination(format!(
            "`{raw}` cannot be resolved ({err}); destinations are vetted fail-closed"
        ))
    })?;
    if addrs.is_empty() {
        return Err(HttpError::BlockedDestination(format!(
            "`{raw}` resolves to no address"
        )));
    }
    for ip in addrs {
        vet_ip_with(ip, allow_loopback)?;
    }
    Ok(())
}

async fn resolve(name: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (name.as_str(), 0u16)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// The address rule (issue #136): refuse everything that is not
/// publicly routable — loopback, the RFC 1918 ranges, CGNAT (`100.64/10`,
/// behind which Oracle's metadata endpoint lives), link-local (which
/// carries `169.254.169.254`), the IPv6 unique-local range (which carries
/// AWS's `fd00:ec2::254`), multicast, documentation and benchmarking
/// blocks — and unwrap the IPv4 that IPv6 embeds (mapped, 6to4) so it is
/// checked too, while refusing Teredo outright (its embedded address is
/// the attacker's to choose).
#[must_use]
pub fn vet_ip_ok(ip: IpAddr, allow_loopback: bool) -> bool {
    vet_ip_with(ip, allow_loopback).is_ok()
}

fn vet_ip_with(ip: IpAddr, allow_loopback: bool) -> Result<(), HttpError> {
    let blocked = Err(HttpError::BlockedDestination(format!(
        "{ip} is not a publicly-routable destination"
    )));
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return if allow_loopback { Ok(()) } else { blocked };
            }
            let octets = v4.octets();
            let cgnat = octets[0] == 100 && octets[1] & 0b1100_0000 == 0b0100_0000;
            // `is_benchmarking`/`is_reserved` are unstable `ip`-feature
            // methods; these are the same ranges read off the octets.
            let benchmarking = octets[0] == 198 && octets[1] & 0b1111_1110 == 18;
            let reserved = octets[0] >= 240;
            if v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || benchmarking
                || reserved
                || octets[0] == 0
                // CGNAT 100.64.0.0/10: `is_private` does not cover it.
                || cgnat
            {
                blocked
            } else {
                Ok(())
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return if allow_loopback { Ok(()) } else { blocked };
            }
            // The `ip` feature's classifiers are unstable; these are the
            // same predicates read off the address bytes directly.
            let link_local = v6.segments()[0] & 0xffc0 == 0xfe80;
            let unique_local = v6.segments()[0] & 0xfe00 == 0xfc00;
            let documentation = v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8;
            if v6.is_unspecified()
                || v6.is_multicast()
                || link_local
                || unique_local
                || documentation
            {
                return blocked;
            }
            // Teredo (2001::/32) tunnels IPv4 through a relay and can
            // arrive at loopback behind this client's own check; refuse
            // the form outright rather than decoding the far end.
            if v6.segments()[0] == 0x2001 && v6.segments()[1] == 0 {
                return blocked;
            }
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return vet_ip_with(IpAddr::V4(mapped), allow_loopback);
            }
            let octets = v6.octets();
            let embedded_v4 = || Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
            // IPv4-compatible (`::a.b.c.d`, RFC 4291 4.5.5.1): deprecated,
            // but `to_ipv4_mapped` does not recognise the form and a stack
            // that still routes it lands on the embedded address — so
            // `[::127.0.0.1]` would otherwise walk past every check above.
            // `::` and `::1` are already answered further up.
            if v6.segments()[..6] == [0, 0, 0, 0, 0, 0] {
                return vet_ip_with(IpAddr::V4(embedded_v4()), allow_loopback);
            }
            // NAT64 well-known prefix (`64:ff9b::/96`, RFC 6052): where a
            // translator is on the path, this *is* the embedded v4
            // destination.
            if v6.segments()[0] == 0x0064 && v6.segments()[1] == 0xff9b {
                return vet_ip_with(IpAddr::V4(embedded_v4()), allow_loopback);
            }
            // 6to4 (2002::/16) embeds the real destination in octets 3-6.
            if v6.segments()[0] == 0x2002 {
                let octets = v6.octets();
                let embedded = Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]);
                return vet_ip_with(IpAddr::V4(embedded), allow_loopback);
            }
            Ok(())
        }
    }
}

/// The connection-time re-vet: the pool calls this for every hostname it
/// actually dials, so the addresses a request reaches are the ones
/// vetted here, whatever a resolver answers the second time.
struct GuardResolver {
    allow_loopback: bool,
}

impl reqwest::dns::Resolve for GuardResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_loopback = self.allow_loopback;
        let name = name.as_str().to_owned();
        Box::pin(async move {
            let refusal = |why: String| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(std::io::Error::other(format!("{GUARD_TAG}: {why}")))
            };
            let addrs = resolve(&name)
                .await
                .map_err(|err| refusal(format!("`{name}` cannot be resolved ({err})")))?;
            if addrs.is_empty() {
                return Err(refusal(format!("`{name}` resolves to no address")));
            }
            for ip in &addrs {
                if let Err(err) = vet_ip_with(*ip, allow_loopback) {
                    return Err(refusal(err.to_string()));
                }
            }
            Ok(Box::new(
                addrs
                    .into_iter()
                    .map(|ip| std::net::SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            ) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test url")
    }

    fn refused(s: &str) -> bool {
        match vet_static(&url(s), false) {
            Ok(()) => false,
            Err(HttpError::BlockedDestination(_)) => true,
            Err(other) => panic!("expected a policy refusal for {s}, got {other}"),
        }
    }

    #[test]
    fn loopback_is_blocked_everywhere_it_can_be_written() {
        // Decimal, hex, octal and short IPv4 forms all normalize to
        // 127.0.0.1 before this module sees the host.
        for s in [
            "http://127.0.0.1/",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://[::1]/",
            "http://[::ffff:7f00:1]/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        ] {
            assert!(refused(s), "{s} must be refused");
        }
    }

    #[test]
    fn private_and_special_ranges_are_blocked() {
        for s in [
            "http://10.0.0.1/",
            "http://192.168.70.70/",
            "http://172.16.0.1/",
            "http://0.0.0.0/",
            "http://[fe80::1]/",
            "http://[::]/",
            "http://[ff02::1]/",
            "http://[2001:db8::1]/",
            "http://100.100.100.200/",
            "http://255.255.255.255/",
        ] {
            assert!(refused(s), "{s} must be refused");
        }
    }

    #[test]
    fn cloud_metadata_endpoints_are_blocked() {
        // EC2 (v4 and v6), GCE by name, and the private-DNS name forms.
        for s in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/",
            "http://metadata.google.internal/",
            "http://metadata/",
            "http://foo.internal/",
            "http://printer.local/",
        ] {
            assert!(refused(s), "{s} must be refused");
        }
    }

    #[test]
    fn non_http_schemes_and_userinfo_are_blocked() {
        for s in [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/",
            "ftp://example.com/",
            "http://admin:pw@example.com/",
            "https://tok@169.254.169.254/",
        ] {
            assert!(refused(s), "{s} must be refused");
        }
    }

    #[test]
    fn ipv6_tunnel_forms_cannot_smuggle_an_ipv4_destination() {
        // 6to4 carrying 127.0.0.1, and Teredo (refused outright).
        assert!(refused("http://[2002:7f00:1::1]/"));
        assert!(refused("http://[2001:0:4136:8000:0:63bf:3fff:fdd2]/"));
        // IPv4-compatible: deprecated, unseen by `to_ipv4_mapped`, and
        // routable enough to be worth refusing.
        assert!(refused("http://[::127.0.0.1]/"));
        assert!(refused("http://[::7f00:1]/"));
        assert!(refused("http://[::10.0.0.1]/"));
        // NAT64 well-known prefix carrying the EC2 metadata address.
        assert!(refused("http://[64:ff9b::169.254.169.254]/"));
        // The same forms carrying a public address stay allowed: the
        // embedded destination is what is judged, not the shape.
        assert!(!refused("http://[::93.184.216.34]/"));
        assert!(!refused("http://[64:ff9b::93.184.216.34]/"));
    }

    #[test]
    fn legitimate_public_destinations_still_pass() {
        for s in [
            "https://api.resend.com/emails",
            "https://93.184.216.34/",
            // Boundaries just outside the blocked ranges.
            "http://172.15.255.255/",
            "http://172.32.0.1/",
            "http://100.63.255.255/",
            "http://100.128.0.1/",
        ] {
            assert!(!refused(s), "{s} must be allowed");
        }
    }

    #[test]
    fn loopback_opt_in_admits_only_loopback() {
        assert!(!vet_ip_ok(IpAddr::V4(Ipv4Addr::LOCALHOST), false));
        assert!(vet_ip_ok(IpAddr::V4(Ipv4Addr::LOCALHOST), true));
        assert!(
            !vet_ip_ok(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), true),
            "metadata must stay blocked with loopback on"
        );
        assert!(
            !vet_ip_ok(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), true),
            "private must stay blocked with loopback on"
        );
    }

    #[test]
    fn names_are_refused_before_any_lookup() {
        // vet_static is synchronous: these pass or fail without a resolver.
        assert!(refused("http://localhost:8080/x"));
        assert!(refused("http://LOCALHOST./x"));
        assert!(refused("http://sub.localhost/x"));
        assert!(!refused("http://api.example.com/x"));
    }

    #[test]
    fn method_change_follows_the_http_rules() {
        let post = http::Method::POST;
        let get = http::Method::GET;
        let code = |n: u16| http::StatusCode::from_u16(n).expect("test status");
        assert!(redirect_changes_method(code(303), &post));
        assert!(redirect_changes_method(code(302), &post));
        assert!(!redirect_changes_method(code(307), &post));
        assert!(!redirect_changes_method(code(301), &get));
        assert!(!redirect_changes_method(code(303), &get));
    }
}
