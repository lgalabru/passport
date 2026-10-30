//! The claim vocabulary of `docs/design.md` §2: what a relying party can ask,
//! how each claim maps onto the circuit's selector bits and parameters, and
//! how it renders in a payload (EU PID / OIDC claim names).
//!
//! [`evaluate`] mirrors the circuit's arithmetic exactly; it has to, because the
//! results and revealed values are public inputs the prover supplies.

use serde_json::{Map, Value, json};

use crate::document::{Date, Document};
use crate::{Error, Result};

/// Age thresholds the v1 circuit has a selector bit for, in bit order.
pub const AGE_THRESHOLDS: [u8; 5] = [13, 16, 18, 21, 65];

const ISSUING_COUNTRY: usize = 5;
const NATIONALITY: usize = 6;
const EXPIRY_VALID: usize = 7;
const BIRTHDATE: usize = 9;
const AGE_IN_YEARS: usize = 10;

/// One claim a relying party can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Claim {
    /// `age_equal_or_over: {"18": true}`; the threshold is one of [`AGE_THRESHOLDS`].
    AgeOver(u8),
    /// `issuing_country: "FRA"`, revealed.
    IssuingCountry,
    /// `nationalities: ["FRA"]`, revealed.
    Nationality,
    /// `expiry_date_valid: true`.
    ExpiryValid,
    /// `birthdate: "1990-01-01"`, revealed.
    Birthdate,
    /// `age_in_years: 34`, revealed.
    AgeInYears,
}

impl Claim {
    pub fn bit(self) -> usize {
        match self {
            Claim::AgeOver(n) => AGE_THRESHOLDS
                .iter()
                .position(|&t| t == n)
                .expect("validated threshold"),
            Claim::IssuingCountry => ISSUING_COUNTRY,
            Claim::Nationality => NATIONALITY,
            Claim::ExpiryValid => EXPIRY_VALID,
            Claim::Birthdate => BIRTHDATE,
            Claim::AgeInYears => AGE_IN_YEARS,
        }
    }

    pub fn age(threshold: u8) -> Result<Self> {
        if AGE_THRESHOLDS.contains(&threshold) {
            Ok(Claim::AgeOver(threshold))
        } else {
            Err(Error::Unsupported(format!(
                "age threshold {threshold} (supported: 13, 16, 18, 21, 65)"
            )))
        }
    }

    /// Whether answering reveals a value from the document, rather than a yes/no.
    pub fn discloses(self) -> bool {
        matches!(
            self,
            Claim::IssuingCountry | Claim::Nationality | Claim::Birthdate | Claim::AgeInYears
        )
    }

    /// The claim path in a payload / DCQL query, e.g. `["age_equal_or_over", "18"]`.
    pub fn path(self) -> Vec<String> {
        match self {
            Claim::AgeOver(n) => vec!["age_equal_or_over".into(), n.to_string()],
            Claim::IssuingCountry => vec!["issuing_country".into()],
            Claim::Nationality => vec!["nationalities".into()],
            Claim::ExpiryValid => vec!["expiry_date_valid".into()],
            Claim::Birthdate => vec!["birthdate".into()],
            Claim::AgeInYears => vec!["age_in_years".into()],
        }
    }

    /// Inverse of [`Claim::path`].
    pub fn from_path(path: &[&str]) -> Result<Self> {
        match path {
            ["age_equal_or_over", n] => Claim::age(
                n.parse()
                    .map_err(|_| Error::Request(format!("bad age threshold {n}")))?,
            ),
            [single] if single.starts_with("age_over_") => {
                let n = &single["age_over_".len()..];
                Claim::age(
                    n.parse()
                        .map_err(|_| Error::Request(format!("bad claim {single}")))?,
                )
            }
            ["issuing_country"] => Ok(Claim::IssuingCountry),
            ["nationalities"] | ["nationality"] => Ok(Claim::Nationality),
            ["expiry_date_valid"] => Ok(Claim::ExpiryValid),
            ["birthdate"] | ["birth_date"] => Ok(Claim::Birthdate),
            ["age_in_years"] => Ok(Claim::AgeInYears),
            other => Err(Error::Unsupported(format!("claim {}", other.join(".")))),
        }
    }

    /// The short CLI syntax: `age.gte(18)`, `nationality`, `reveal(birthdate)`…
    pub fn parse_short(text: &str) -> Result<Self> {
        let t = text.trim();
        let arg = |prefix: &str| t.strip_prefix(prefix).and_then(|r| r.strip_suffix(')'));
        if let Some(n) = arg("age.gte(")
            .or_else(|| arg("age.gt("))
            .or_else(|| arg("age.lt("))
        {
            let n: u8 = n
                .trim()
                .parse()
                .map_err(|_| Error::Request(format!("bad claim {t}")))?;
            // `gt(17)` is `gte(18)`; keep the threshold the circuit knows.
            let n = if t.starts_with("age.gt(") { n + 1 } else { n };
            return Claim::age(n);
        }
        match t {
            "issuer" | "issuer.eq" | "reveal(issuing_country)" => Ok(Claim::IssuingCountry),
            "nationality" | "reveal(nationality)" => Ok(Claim::Nationality),
            "expiry.valid" => Ok(Claim::ExpiryValid),
            "reveal(birthdate)" | "birthdate" => Ok(Claim::Birthdate),
            "age.years" | "reveal(age)" => Ok(Claim::AgeInYears),
            other => Err(Error::Unsupported(format!("claim {other}"))),
        }
    }
}

/// What the circuit's public inputs say about the claims: which were selected,
/// the revealed values, and the truth bit of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Statement {
    pub selector: u16,
    /// `issuing_country`, `nationality` (24-bit ASCII), `birthdate` (`YYYYMMDD`),
    /// `age_in_years`; zero when not selected.
    pub params: [u32; 4],
    pub result: u16,
}

/// Evaluate `claims` on `document` as of `today`, the way the circuit does.
pub fn evaluate(claims: &[Claim], document: &Document, today: Date) -> Statement {
    let mut statement = Statement::default();
    let birth = document.birth_date(today);
    for &claim in claims {
        let bit = claim.bit();
        statement.selector |= 1 << bit;
        let truth = match claim {
            Claim::AgeOver(n) => birth.0 + u32::from(n) * 10_000 <= today.0,
            Claim::ExpiryValid => document.expiry_date().0 >= today.0,
            Claim::IssuingCountry => {
                statement.params[0] = document.issuer();
                true
            }
            Claim::Nationality => {
                statement.params[1] = document.nationality();
                true
            }
            Claim::Birthdate => {
                statement.params[2] = birth.0;
                true
            }
            Claim::AgeInYears => {
                statement.params[3] = birth.age_on(today);
                true
            }
        };
        if truth {
            statement.result |= 1 << bit;
        }
    }
    statement
}

fn ascii3(value: u32) -> String {
    let bytes = [(value >> 16) as u8, (value >> 8) as u8, value as u8];
    String::from_utf8_lossy(&bytes)
        .trim_end_matches('<')
        .to_string()
}

fn from_ascii3(code: &str) -> Result<u32> {
    let padded = format!("{code:<<3}");
    let bytes = padded.as_bytes();
    if bytes.len() != 3 || !bytes.iter().all(|b| b.is_ascii_uppercase() || *b == b'<') {
        return Err(Error::Payload(format!("bad country code {code}")));
    }
    Ok(u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]))
}

/// The `verified_claims.claims` object for a statement.
pub fn render(statement: &Statement) -> Value {
    let mut out = Map::new();
    let on = |bit: usize| statement.selector & (1 << bit) != 0;
    let truth = |bit: usize| statement.result & (1 << bit) != 0;
    let mut ages = Map::new();
    for (bit, n) in AGE_THRESHOLDS.iter().enumerate() {
        if on(bit) {
            ages.insert(n.to_string(), Value::Bool(truth(bit)));
        }
    }
    if !ages.is_empty() {
        out.insert("age_equal_or_over".into(), Value::Object(ages));
    }
    if on(ISSUING_COUNTRY) {
        out.insert("issuing_country".into(), json!(ascii3(statement.params[0])));
    }
    if on(NATIONALITY) {
        out.insert("nationalities".into(), json!([ascii3(statement.params[1])]));
    }
    if on(EXPIRY_VALID) {
        out.insert("expiry_date_valid".into(), json!(truth(EXPIRY_VALID)));
    }
    if on(BIRTHDATE) {
        let d = statement.params[2];
        out.insert(
            "birthdate".into(),
            json!(format!(
                "{:04}-{:02}-{:02}",
                d / 10_000,
                d / 100 % 100,
                d % 100
            )),
        );
    }
    if on(AGE_IN_YEARS) {
        out.insert("age_in_years".into(), json!(statement.params[3]));
    }
    Value::Object(out)
}

/// Inverse of [`render`]: the statement a claims object stands for. Anything it
/// cannot account for is an error (§3.1: the payload is a rendering of the
/// public inputs, nothing more).
pub fn parse_rendered(claims: &Value) -> Result<Statement> {
    let object = claims
        .as_object()
        .ok_or_else(|| Error::Payload("claims is not an object".into()))?;
    let mut s = Statement::default();
    let mut set = |bit: usize, truth: bool| {
        s.selector |= 1 << bit;
        if truth {
            s.result |= 1 << bit;
        }
    };
    let bool_of = |v: &Value, name: &str| {
        v.as_bool()
            .ok_or_else(|| Error::Payload(format!("{name} is not a boolean")))
    };
    let mut params = [0u32; 4];
    for (key, value) in object {
        match key.as_str() {
            "age_equal_or_over" => {
                let ages = value
                    .as_object()
                    .ok_or_else(|| Error::Payload("age_equal_or_over is not an object".into()))?;
                for (n, truth) in ages {
                    let claim = Claim::age(
                        n.parse()
                            .map_err(|_| Error::Payload(format!("bad age {n}")))?,
                    )
                    .map_err(|e| Error::Payload(e.to_string()))?;
                    set(claim.bit(), bool_of(truth, "age_equal_or_over")?);
                }
            }
            "issuing_country" => {
                params[0] = from_ascii3(value.as_str().unwrap_or_default())?;
                set(ISSUING_COUNTRY, true);
            }
            "nationalities" => {
                let list = value.as_array().filter(|l| l.len() == 1).ok_or_else(|| {
                    Error::Payload("nationalities must hold exactly one code".into())
                })?;
                params[1] = from_ascii3(list[0].as_str().unwrap_or_default())?;
                set(NATIONALITY, true);
            }
            "expiry_date_valid" => set(EXPIRY_VALID, bool_of(value, key)?),
            "birthdate" => {
                let text = value.as_str().unwrap_or_default();
                let digits: String = text.chars().filter(char::is_ascii_digit).collect();
                if text.len() != 10 || digits.len() != 8 {
                    return Err(Error::Payload(format!("bad birthdate {text}")));
                }
                params[2] = digits
                    .parse()
                    .map_err(|_| Error::Payload("bad birthdate".into()))?;
                set(BIRTHDATE, true);
            }
            "age_in_years" => {
                params[3] = value
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| Error::Payload("age_in_years is not a number".into()))?;
                set(AGE_IN_YEARS, true);
            }
            other => return Err(Error::Payload(format!("unexpected claim {other}"))),
        }
    }
    s.params = params;
    Ok(s)
}

/// Human wording for a consent screen.
pub fn describe(claim: Claim) -> String {
    match claim {
        Claim::AgeOver(n) => format!("You are {n} or older"),
        Claim::IssuingCountry => "The country that issued your document".into(),
        Claim::Nationality => "Your nationality".into(),
        Claim::ExpiryValid => "Your document has not expired".into(),
        Claim::Birthdate => "Your date of birth".into(),
        Claim::AgeInYears => "Your age".into(),
    }
}
