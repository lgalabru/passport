//! OpenID for Verifiable Presentations 1.0, the subset a claim proof needs
//! (`docs/design.md` §3.3).
//!
//! A relying party opens `openid4vp://?…` (or `passport://?…`) with either the
//! request parameters inline or a `request_uri` the app fetches. The DCQL query
//! names the claims; the answer is a `direct_post` of `vp_token` to the
//! `response_uri`, where `vp_token` maps the credential query id to the compact
//! claim proof. `aud` is the `client_id` and `cnf.kid` carries the `nonce`, so a
//! proof answers one request from one relying party only.
//!
//! Only `redirect_uri:` client ids are accepted, and the response URI must be
//! the client id: the proof's audience is then where it is posted, so a site
//! cannot ask for a proof meant for another relying party and keep it. Other
//! schemes (`x509_san_dns:`, `decentralized_identifier:`, …) name a verifier
//! that only a signed request object can authenticate, and request signatures
//! are not checked yet.
//!
//! Not yet supported: request signatures, `direct_post.jwt` (encrypted
//! responses), and transaction data.

use serde_json::{Value, json};

use crate::claims::Claim;
use crate::{Error, Result};

/// Credential formats a DCQL query can ask for to get a claim proof.
pub const FORMATS: [&str; 2] = ["passport-claim+zk", "zk-groth16-bn254"];

/// A parsed authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub nonce: String,
    pub state: Option<String>,
    pub response_uri: String,
    /// The DCQL credential query id the proof answers.
    pub credential_id: String,
    pub claims: Vec<Claim>,
    /// `client_metadata.client_name`: self-declared, so the consent screen
    /// names the relying party by [`AuthorizationRequest::recipient`].
    pub client_name: Option<String>,
    pub logo_uri: Option<String>,
    /// Why the relying party asks, if it said (`purpose` in older drafts).
    pub purpose: Option<String>,
}

impl AuthorizationRequest {
    /// The audience a claim proof for this request carries.
    pub fn audience(&self) -> &str {
        &self.client_id
    }

    /// `cnf.kid` of the proof: the request's nonce.
    pub fn holder(&self) -> String {
        format!("nonce:{}", self.nonce)
    }

    /// The host of the response URI, shown as who will receive the proof.
    pub fn recipient(&self) -> String {
        host(&self.response_uri).unwrap_or_else(|| self.response_uri.clone())
    }
}

/// What the link says: the request itself, or where to fetch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Inline(AuthorizationRequest),
    /// Fetch this URL (`GET`, or `POST` when `post` is set) and pass the body
    /// to [`parse_request_object`].
    Fetch {
        request_uri: String,
        client_id: String,
        post: bool,
    },
}

/// The only client id scheme an unsigned request can use.
const REDIRECT_URI: &str = "redirect_uri:";

fn check_scheme(client_id: &str) -> Result<()> {
    if client_id.starts_with(REDIRECT_URI) {
        return Ok(());
    }
    let scheme = client_id
        .split_once(':')
        .map_or("a bare client id", |(s, _)| s);
    Err(Error::Unsupported(format!(
        "{scheme}: only redirect_uri client ids until request signatures are checked"
    )))
}

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?', '#']).next()?.to_string())
}

/// Percent-decoding for query strings and form bodies (`+` is a space).
pub fn decode_component(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
                continue;
            }
            (b'+', _) => out.push(b' '),
            (b, _) => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn encode_component(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn query(url: &str) -> Vec<(String, String)> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let query = query.split('#').next().unwrap_or("");
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (decode_component(k), decode_component(v))
        })
        .collect()
}

/// Parse an `openid4vp://` (or `passport://`, `https://…`) request link.
pub fn parse_link(url: &str) -> Result<Link> {
    let params = query(url);
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    if let Some(request_uri) = get("request_uri") {
        let client_id =
            get("client_id").ok_or_else(|| Error::Request("client_id is missing".into()))?;
        // Refused before anything is fetched.
        check_scheme(&client_id)?;
        let post = get("request_uri_method").as_deref() == Some("post");
        return Ok(Link::Fetch {
            request_uri,
            client_id,
            post,
        });
    }
    if let Some(request) = get("request") {
        return parse_request_object(&request, None).map(Link::Inline);
    }
    let mut object = serde_json::Map::new();
    for (k, v) in &params {
        let value = match k.as_str() {
            "dcql_query" | "client_metadata" => {
                serde_json::from_str(v).map_err(|_| Error::Request(format!("{k} is not JSON")))?
            }
            _ => Value::String(v.clone()),
        };
        object.insert(k.clone(), value);
    }
    from_object(&Value::Object(object), None).map(Link::Inline)
}

/// Parse a fetched request object: a JWT (`header.payload.signature`, the
/// signature is **not** verified yet) or plain JSON. `client_id` is the one
/// from the link, which the object must repeat.
pub fn parse_request_object(body: &str, client_id: Option<&str>) -> Result<AuthorizationRequest> {
    let body = body.trim();
    let value: Value = if body.starts_with('{') {
        serde_json::from_str(body)
            .map_err(|_| Error::Request("request object is not JSON".into()))?
    } else {
        use base64::Engine as _;
        let payload = body
            .split('.')
            .nth(1)
            .ok_or_else(|| Error::Request("request object is not a JWT".into()))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .map_err(|_| Error::Request("request object payload is not base64url".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::Request("request object payload is not JSON".into()))?
    };
    from_object(&value, client_id)
}

fn from_object(o: &Value, link_client_id: Option<&str>) -> Result<AuthorizationRequest> {
    let text = |name: &str| o[name].as_str().map(str::to_owned);
    let need = |name: &str| text(name).ok_or_else(|| Error::Request(format!("{name} is missing")));

    let client_id = need("client_id")?;
    check_scheme(&client_id)?;
    if link_client_id.is_some_and(|c| c != client_id) {
        return Err(Error::Request(
            "client_id differs between link and request object".into(),
        ));
    }
    if let Some(t) = text("response_type")
        && t != "vp_token"
    {
        return Err(Error::Unsupported(format!("response_type {t}")));
    }
    let mode = text("response_mode").unwrap_or_else(|| "direct_post".into());
    if mode != "direct_post" {
        return Err(Error::Unsupported(format!("response_mode {mode}")));
    }
    let response_uri = need("response_uri")?;
    if !response_uri.starts_with("https://")
        && !response_uri.starts_with("http://localhost")
        && !response_uri.starts_with("http://127.0.0.1")
    {
        return Err(Error::Request("response_uri must be https".into()));
    }
    // OpenID4VP: with a redirect_uri client id, it must be the response URI.
    if client_id.strip_prefix(REDIRECT_URI) != Some(response_uri.as_str()) {
        return Err(Error::Request(
            "client_id does not match response_uri".into(),
        ));
    }
    let nonce = need("nonce")?;
    if nonce.len() < 8 {
        return Err(Error::Request("nonce is too short".into()));
    }

    let (credential_id, claims) = dcql(&o["dcql_query"])?;
    let metadata = &o["client_metadata"];
    Ok(AuthorizationRequest {
        client_id,
        nonce,
        state: text("state"),
        response_uri,
        credential_id,
        claims,
        client_name: metadata["client_name"].as_str().map(str::to_owned),
        logo_uri: metadata["logo_uri"].as_str().map(str::to_owned),
        purpose: text("purpose").or_else(|| {
            o["dcql_query"]["credentials"][0]["purpose"]
                .as_str()
                .map(str::to_owned)
        }),
    })
}

/// The first credential query asking for a claim proof, as circuit claims.
fn dcql(query: &Value) -> Result<(String, Vec<Claim>)> {
    let credentials = query["credentials"]
        .as_array()
        .ok_or_else(|| Error::Request("dcql_query has no credentials".into()))?;
    let credential = credentials
        .iter()
        .find(|c| c["format"].as_str().is_some_and(|f| FORMATS.contains(&f)))
        .ok_or_else(|| {
            Error::Unsupported("no credential query for a passport claim proof".into())
        })?;
    let id = credential["id"]
        .as_str()
        .ok_or_else(|| Error::Request("credential query has no id".into()))?
        .to_owned();
    let mut claims = Vec::new();
    for claim in credential["claims"].as_array().into_iter().flatten() {
        let path: Vec<String> = claim["path"]
            .as_array()
            .ok_or_else(|| Error::Request("claim without a path".into()))?
            .iter()
            .map(|p| match p {
                Value::String(s) => Ok(s.clone()),
                Value::Number(n) => Ok(n.to_string()),
                _ => Err(Error::Request("claim path element is not a string".into())),
            })
            .collect::<Result<_>>()?;
        let refs: Vec<&str> = path.iter().map(String::as_str).collect();
        let parsed = Claim::from_path(&refs)?;
        if !claims.contains(&parsed) {
            claims.push(parsed);
        }
    }
    if claims.is_empty() {
        return Err(Error::Request("the request asks for no claims".into()));
    }
    claims.sort();
    Ok((id, claims))
}

/// The `application/x-www-form-urlencoded` body of the `direct_post`.
pub fn response_body(request: &AuthorizationRequest, claim_proof: &str) -> String {
    let vp_token = json!({ request.credential_id.clone(): [claim_proof] }).to_string();
    let mut body = format!("vp_token={}", encode_component(&vp_token));
    if let Some(state) = &request.state {
        body.push_str(&format!("&state={}", encode_component(state)));
    }
    body
}

/// The body of a `direct_post` that declines the request.
pub fn error_body(request: &AuthorizationRequest, error: &str) -> String {
    let mut body = format!("error={}", encode_component(error));
    if let Some(state) = &request.state {
        body.push_str(&format!("&state={}", encode_component(state)));
    }
    body
}
