//! A minimal relying party: prints an OpenID4VP request link, waits for the
//! wallet's `direct_post` on `http://localhost:8787/response`, verifies the
//! claim proof and prints what it proves.
//!
//! ```sh
//! cargo run -p passport-attest --example relying_party -- 'age.gte(18)' nationality
//! xcrun simctl openurl booted "<the printed link>"
//! ```
//!
//! `RP_NAME` and `RP_PURPOSE` set the name and the reason the wallet shows.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use passport_attest::claims::Claim;
use passport_attest::oid4vp::{decode_component as decode, encode_component};
use passport_attest::prover::read_verifying_key;
use passport_attest::token::{DEV_ISSUER, Expectations, Roots, verify_token};
use serde_json::{Value, json};

const RESPONSE_URI: &str = "http://localhost:8787/response";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let wanted = if args.is_empty() {
        vec!["age.gte(18)".to_string()]
    } else {
        args
    };
    let claims: Vec<Claim> = wanted
        .iter()
        .map(|c| Claim::parse_short(c).expect("known claim"))
        .collect();

    let vk_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../circuits/claim/target/xark/passport_claim/vk.bin");
    let vk =
        read_verifying_key(&std::fs::read(vk_path).expect("run `just claim-artifacts`")).unwrap();

    let nonce = format!("{:016x}", rand::random::<u64>());
    let state = format!("{:08x}", rand::random::<u32>());
    let client_id = format!("redirect_uri:{RESPONSE_URI}");
    let dcql = json!({ "credentials": [{
        "id": "passport",
        "format": "passport-claim+zk",
        "claims": claims.iter().map(|c| json!({ "path": c.path() })).collect::<Vec<_>>(),
    }]});
    let name = std::env::var("RP_NAME").unwrap_or_else(|_| "Bar Example".into());
    let mut link = format!(
        "openid4vp://?client_id={}&response_type=vp_token&response_mode=direct_post&response_uri={}&nonce={nonce}&state={state}&dcql_query={}&client_metadata={}",
        encode_component(&client_id),
        encode_component(RESPONSE_URI),
        encode_component(&dcql.to_string()),
        encode_component(&json!({ "client_name": name }).to_string()),
    );
    if let Ok(purpose) = std::env::var("RP_PURPOSE") {
        link.push_str(&format!("&purpose={}", encode_component(&purpose)));
    }
    println!("{link}");

    let listener = TcpListener::bind("127.0.0.1:8787").expect("port 8787 free");
    eprintln!("waiting for the wallet on {RESPONSE_URI} …");
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut length = 0;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header.trim().is_empty() {
                break;
            }
            if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let form = String::from_utf8_lossy(&body).to_string();
        let field = |name: &str| {
            form.split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                .map(decode)
        };

        let (status, reply) = if let Some(error) = field("error") {
            eprintln!("wallet declined: {error}");
            ("200 OK", json!({}))
        } else if field("state").as_deref() != Some(state.as_str()) {
            ("400 Bad Request", json!({ "error": "invalid_request" }))
        } else {
            let vp: Value =
                serde_json::from_str(&field("vp_token").unwrap_or_default()).unwrap_or_default();
            let token = vp["passport"][0].as_str().unwrap_or_default();
            let holder = format!("nonce:{nonce}");
            let expect = Expectations {
                issuer: DEV_ISSUER,
                audience: &client_id,
                holder: &holder,
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                claims: &claims,
                roots: Roots::AnyDevelopment,
            };
            match verify_token(token, &vk, &expect) {
                Ok(verified) => {
                    println!("VERIFIED {}", verified.payload["verified_claims"]["claims"]);
                    println!("sub {}", verified.payload["sub"]);
                    ("200 OK", json!({}))
                }
                Err(e) => {
                    println!("REJECTED {e}");
                    ("400 Bad Request", json!({ "error": "invalid_request" }))
                }
            }
        };
        let reply = reply.to_string();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
        if status.starts_with("200") {
            break;
        }
    }
}
