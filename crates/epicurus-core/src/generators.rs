//! Secret generators.
//!
//! Each generator produces a value in a provider's public format (prefix,
//! length, alphabet) so stealer regexes collect it, but the value is random
//! and never registered anywhere. Where a format carries a checksum (GitHub
//! and npm tokens embed a CRC32 of the random part) the checksum is
//! deliberately wrong, so the provider rejects the token without even a
//! database lookup.
//!
//! Provider prefixes are assembled from fragments at runtime. Literal
//! token-shaped strings must never appear in this repository: GitHub push
//! protection rejects them and secret scanners flag the repository.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use time::OffsetDateTime;

use crate::seed::Chooser;
use crate::{Error, Result};

const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const URLSAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const DIGITS: &[u8] = b"0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PASSWORD: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+";

/// Joins prefix fragments. Exists so no complete provider prefix plus body
/// ever appears as a literal in source.
fn pfx(parts: &[&str]) -> String {
    parts.concat()
}

/// Source of randomness for secret material.
pub trait Entropy {
    /// Fills `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);

    /// Uniform value in `0..n` (`n > 0`).
    fn below(&mut self, n: u64) -> u64 {
        if n <= 1 {
            return 0;
        }
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let mut b = [0u8; 8];
            self.fill(&mut b);
            let v = u64::from_le_bytes(b);
            if v < zone {
                return v % n;
            }
        }
    }
}

impl<R: rand::Rng> Entropy for R {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill_bytes(buf);
    }
}

/// A generated value. `parts` exposes sub-values such as the public half of
/// a key pair, addressable in templates as `{{field.part}}`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Generated {
    /// Primary value, used by `{{field}}`.
    pub value: String,
    /// Named sub-values, used by `{{field.part}}`.
    pub parts: BTreeMap<String, String>,
    /// True when the value came from a user-supplied canary.
    pub canary: bool,
}

impl Generated {
    fn plain(value: String) -> Self {
        Self {
            value,
            ..Self::default()
        }
    }
}

/// Everything a generator may draw on.
pub struct GenContext<'a> {
    /// CSPRNG for secret material.
    pub entropy: &'a mut dyn Entropy,
    /// Deterministic per-install choices (names, sizes).
    pub chooser: &'a mut Chooser,
    /// Named value sets from the catalog (`[sets]`).
    pub sets: &'a BTreeMap<String, Vec<String>>,
    /// User-supplied canary values keyed by generator name.
    pub canaries: &'a BTreeMap<String, String>,
    /// Reference "now", injectable for tests.
    pub now: OffsetDateTime,
}

impl GenContext<'_> {
    fn chars(&mut self, alphabet: &[u8], n: usize) -> String {
        (0..n)
            .map(|_| alphabet[self.entropy.below(alphabet.len() as u64) as usize] as char)
            .collect()
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.entropy.fill(&mut v);
        v
    }

    fn pick_set(&mut self, set: &str) -> Result<String> {
        let items = self
            .sets
            .get(set)
            .ok_or_else(|| Error::Generator(format!("unknown set {set:?}")))?;
        self.chooser
            .pick(items)
            .cloned()
            .ok_or_else(|| Error::Generator(format!("set {set:?} is empty")))
    }
}

/// Names of every built-in generator, used for catalog validation and docs.
pub const GENERATOR_NAMES: &[&str] = &[
    "aws_access_key_id",
    "aws_secret_access_key",
    "github_pat",
    "github_oauth",
    "github_fine_grained",
    "anthropic_api_key",
    "anthropic_oauth_access",
    "anthropic_oauth_refresh",
    "openai_api_key",
    "openai_refresh_token",
    "google_api_key",
    "google_oauth_access",
    "google_oauth_refresh",
    "google_client_secret",
    "slack_bot_token",
    "slack_user_token",
    "stripe_secret_key",
    "notion_token",
    "npm_token",
    "pypi_token",
    "discord_token",
    "telegram_bot_token",
    "azure_refresh_token",
    "jwt",
    "private_key_pem",
    "ssh_ed25519",
    "docker_auth",
    "xprv",
    "eth_address",
    "uuid",
    "hex",
    "alnum",
    "digits",
    "b64",
    "b64url",
    "base58",
    "password",
    "int",
    "pick",
    "username",
    "email",
    "hostname",
    "epoch_ms_future",
    "epoch_past",
    "date_past",
];

/// A parsed generator specification such as `hex:32` or `pick:projects`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorSpec {
    /// Generator name.
    pub name: String,
    /// Colon-separated arguments.
    pub args: Vec<String>,
}

impl GeneratorSpec {
    /// Parses and validates a specification.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut it = spec.split(':');
        let name = it.next().unwrap_or_default().trim().to_string();
        if !GENERATOR_NAMES.contains(&name.as_str()) {
            return Err(Error::Generator(format!("unknown generator {name:?}")));
        }
        let args: Vec<String> = it.map(|s| s.trim().to_string()).collect();
        let spec = Self { name, args };
        spec.validate()?;
        Ok(spec)
    }

    fn arg_usize(&self, idx: usize, default: usize) -> Result<usize> {
        match self.args.get(idx) {
            None => Ok(default),
            Some(a) => a.parse::<usize>().map_err(|_| {
                Error::Generator(format!("{}: argument {a:?} is not a number", self.name))
            }),
        }
    }

    fn validate(&self) -> Result<()> {
        match self.name.as_str() {
            "hex" | "alnum" | "digits" | "b64" | "b64url" | "base58" | "password" => {
                let n = self.arg_usize(0, 32)?;
                if n == 0 || n > 8192 {
                    return Err(Error::Generator(format!(
                        "{}: length must be 1..=8192",
                        self.name
                    )));
                }
            }
            "int" | "epoch_past" | "date_past" => {
                let lo = self.arg_usize(0, 0)?;
                let hi = self.arg_usize(1, lo)?;
                if hi < lo {
                    return Err(Error::Generator(format!(
                        "{}: range is inverted",
                        self.name
                    )));
                }
            }
            "pick" if self.args.first().is_none_or(String::is_empty) => {
                return Err(Error::Generator("pick: requires a set name".into()));
            }
            _ => {}
        }
        Ok(())
    }

    /// True for generators whose output must stay stable per install (they
    /// feed paths and account names), as opposed to fresh secret material.
    pub fn is_deterministic(&self) -> bool {
        matches!(
            self.name.as_str(),
            "int" | "pick" | "username" | "email" | "hostname" | "epoch_past" | "date_past"
        )
    }

    /// Produces a value.
    pub fn generate(&self, ctx: &mut GenContext<'_>) -> Result<Generated> {
        if let Some(canary) = ctx.canaries.get(&self.name) {
            return Ok(Generated {
                value: canary.clone(),
                parts: BTreeMap::new(),
                canary: true,
            });
        }
        let g = match self.name.as_str() {
            "aws_access_key_id" => {
                Generated::plain(format!("{}{}", pfx(&["AK", "IA"]), ctx.chars(BASE32, 16)))
            }
            "aws_secret_access_key" => Generated::plain(ctx.chars(B64CHARS, 40)),
            "github_pat" => Generated::plain(checksummed_token(ctx, &pfx(&["gh", "p_"]))),
            "github_oauth" => Generated::plain(checksummed_token(ctx, &pfx(&["gh", "o_"]))),
            "github_fine_grained" => Generated::plain(format!(
                "{}{}_{}",
                pfx(&["github", "_pat_"]),
                ctx.chars(ALNUM, 22),
                ctx.chars(ALNUM, 59)
            )),
            "anthropic_api_key" => Generated::plain(format!(
                "{}{}AA",
                pfx(&["sk-", "ant-", "api03-"]),
                ctx.chars(URLSAFE, 93)
            )),
            "anthropic_oauth_access" => Generated::plain(format!(
                "{}{}AA",
                pfx(&["sk-", "ant-", "oat01-"]),
                ctx.chars(URLSAFE, 93)
            )),
            "anthropic_oauth_refresh" => Generated::plain(format!(
                "{}{}AA",
                pfx(&["sk-", "ant-", "ort01-"]),
                ctx.chars(URLSAFE, 93)
            )),
            "openai_api_key" => Generated::plain(format!(
                "{}{}{}{}",
                pfx(&["sk-", "proj-"]),
                ctx.chars(URLSAFE, 74),
                pfx(&["T3Blbk", "FJ"]),
                ctx.chars(URLSAFE, 74)
            )),
            "openai_refresh_token" => {
                Generated::plain(format!("{}{}", pfx(&["r", "t_"]), ctx.chars(URLSAFE, 86)))
            }
            "google_api_key" => {
                Generated::plain(format!("{}{}", pfx(&["AI", "za"]), ctx.chars(URLSAFE, 35)))
            }
            "google_oauth_access" => Generated::plain(format!(
                "{}{}",
                pfx(&["ya", "29."]),
                ctx.chars(URLSAFE, 150)
            )),
            "google_oauth_refresh" => {
                Generated::plain(format!("{}{}", pfx(&["1/", "/0"]), ctx.chars(URLSAFE, 100)))
            }
            "google_client_secret" => Generated::plain(format!(
                "{}{}",
                pfx(&["GOC", "SPX-"]),
                ctx.chars(URLSAFE, 28)
            )),
            "slack_bot_token" => Generated::plain(format!(
                "{}{}-{}-{}",
                pfx(&["xo", "xb-"]),
                ctx.chars(DIGITS, 12),
                ctx.chars(DIGITS, 13),
                ctx.chars(ALNUM, 24)
            )),
            "slack_user_token" => Generated::plain(format!(
                "{}{}-{}-{}-{}",
                pfx(&["xo", "xp-"]),
                ctx.chars(DIGITS, 12),
                ctx.chars(DIGITS, 13),
                ctx.chars(DIGITS, 13),
                ctx.chars(HEX, 32)
            )),
            "stripe_secret_key" => Generated::plain(format!(
                "{}{}",
                pfx(&["sk", "_live_"]),
                ctx.chars(ALNUM, 99)
            )),
            "notion_token" => {
                Generated::plain(format!("{}{}", pfx(&["nt", "n_"]), ctx.chars(ALNUM, 46)))
            }
            "npm_token" => Generated::plain(checksummed_token(ctx, &pfx(&["np", "m_"]))),
            "pypi_token" => Generated::plain(format!(
                "{}{}{}",
                pfx(&["py", "pi-"]),
                pfx(&["AgEIcHlw", "aS5vcmc"]),
                ctx.chars(URLSAFE, 160)
            )),
            "discord_token" => {
                let id = format!("{}{}", 1 + ctx.entropy.below(9), ctx.chars(DIGITS, 17));
                Generated::plain(format!(
                    "{}.{}.{}",
                    STANDARD_NO_PAD.encode(id.as_bytes()),
                    ctx.chars(URLSAFE, 6),
                    ctx.chars(URLSAFE, 38)
                ))
            }
            "telegram_bot_token" => Generated::plain(format!(
                "{}{}:AA{}",
                1 + ctx.entropy.below(9),
                ctx.chars(DIGITS, 9),
                ctx.chars(URLSAFE, 33)
            )),
            "azure_refresh_token" => Generated::plain(format!("0.A{}", ctx.chars(URLSAFE, 900))),
            "jwt" => Generated::plain(jwt(ctx)),
            "private_key_pem" => Generated::plain(private_key_pem(ctx)),
            "ssh_ed25519" => ssh_ed25519(ctx)?,
            "docker_auth" => {
                let user = ctx.pick_set("users").unwrap_or_else(|_| "deploy".into());
                let token = ctx.chars(ALNUM, 32);
                Generated::plain(STANDARD.encode(format!("{user}:{token}")))
            }
            "xprv" => Generated::plain(format!("xprv{}", ctx.chars(BASE58, 107))),
            "eth_address" => Generated::plain(format!("0x{}", ctx.chars(HEX, 40))),
            "uuid" => Generated::plain(uuid_v4(&ctx.bytes(16))),
            "hex" => {
                let n = self.arg_usize(0, 32)?;
                Generated::plain(ctx.chars(HEX, n))
            }
            "alnum" => {
                let n = self.arg_usize(0, 32)?;
                Generated::plain(ctx.chars(ALNUM, n))
            }
            "digits" => {
                let n = self.arg_usize(0, 8)?;
                Generated::plain(ctx.chars(DIGITS, n))
            }
            "b64" => {
                let n = self.arg_usize(0, 32)?;
                Generated::plain(STANDARD.encode(ctx.bytes(n)))
            }
            "b64url" => {
                let n = self.arg_usize(0, 32)?;
                Generated::plain(URL_SAFE_NO_PAD.encode(ctx.bytes(n)))
            }
            "base58" => {
                let n = self.arg_usize(0, 32)?;
                Generated::plain(ctx.chars(BASE58, n))
            }
            "password" => {
                let n = self.arg_usize(0, 18)?;
                Generated::plain(ctx.chars(PASSWORD, n))
            }
            "int" => {
                let lo = self.arg_usize(0, 0)? as u64;
                let hi = self.arg_usize(1, lo as usize)? as u64;
                Generated::plain(ctx.chooser.range(lo, hi).to_string())
            }
            "pick" => {
                let set = self.args.first().cloned().unwrap_or_default();
                Generated::plain(ctx.pick_set(&set)?)
            }
            "username" => Generated::plain(ctx.pick_set("users")?),
            "email" => {
                let user = ctx.pick_set("users")?;
                let domain = ctx.pick_set("domains")?;
                Generated::plain(format!("{user}@{domain}"))
            }
            "hostname" => {
                let base = ctx.pick_set("hosts")?;
                let n = ctx.chooser.range(1, 9);
                Generated::plain(format!("{base}-{n:02}"))
            }
            "epoch_ms_future" => {
                let days = 20 + ctx.entropy.below(300) as i64;
                let t = ctx.now + time::Duration::days(days);
                Generated::plain((t.unix_timestamp() * 1000).to_string())
            }
            "epoch_past" => {
                let lo = self.arg_usize(0, 30)? as u64;
                let hi = self.arg_usize(1, lo as usize)? as u64;
                let days = ctx.chooser.range(lo, hi) as i64;
                Generated::plain(
                    (ctx.now - time::Duration::days(days))
                        .unix_timestamp()
                        .to_string(),
                )
            }
            "date_past" => {
                let lo = self.arg_usize(0, 30)? as u64;
                let hi = self.arg_usize(1, lo as usize)? as u64;
                let days = ctx.chooser.range(lo, hi) as i64;
                let t = ctx.now - time::Duration::days(days);
                Generated::plain(crate::timefmt::rfc3339(t))
            }
            other => return Err(Error::Generator(format!("unhandled generator {other:?}"))),
        };
        Ok(g)
    }
}

/// CRC32 (IEEE 802.3), as used by GitHub and npm token checksums.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Base62 encoding left-padded to `width`, matching GitHub's checksum format.
pub fn base62(mut n: u32, width: usize) -> String {
    let mut out = Vec::new();
    while n > 0 {
        out.push(ALNUM_GH[(n % 62) as usize]);
        n /= 62;
    }
    while out.len() < width {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8_lossy(&out).into_owned()
}

/// GitHub's base62 digit order.
const ALNUM_GH: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The correct checksum suffix for a GitHub-style token body.
pub fn github_checksum(body: &str) -> String {
    base62(crc32(body.as_bytes()), 6)
}

/// `prefix` + 30 random characters + a 6-character checksum that is
/// guaranteed *not* to match, so the token fails offline validation.
fn checksummed_token(ctx: &mut GenContext<'_>, prefix: &str) -> String {
    let body = ctx.chars(ALNUM, 30);
    let correct = github_checksum(&body);
    let mut wrong = ctx.chars(ALNUM, 6);
    while wrong == correct {
        wrong = ctx.chars(ALNUM, 6);
    }
    format!("{prefix}{body}{wrong}")
}

fn jwt(ctx: &mut GenContext<'_>) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let iat = (ctx.now - time::Duration::days(1 + ctx.entropy.below(20) as i64)).unix_timestamp();
    let payload = format!(
        r#"{{"sub":"{}","iat":{},"exp":{},"jti":"{}"}}"#,
        uuid_v4(&ctx.bytes(16)),
        iat,
        iat + 3600 * 24 * 30,
        ctx.chars(HEX, 16)
    );
    let sig = URL_SAFE_NO_PAD.encode(ctx.bytes(256));
    format!(
        "{header}.{}.{sig}",
        URL_SAFE_NO_PAD.encode(payload.as_bytes())
    )
}

fn wrap(s: &str, width: usize) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn private_key_pem(ctx: &mut GenContext<'_>) -> String {
    let body = STANDARD.encode(ctx.bytes(1216));
    let kind = pfx(&["PRIVATE", " KEY"]);
    format!(
        "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
        wrap(&body, 64)
    )
}

fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// An OpenSSH-format ed25519 key file. The bytes are random, so the key is
/// structurally well formed but authorizes nothing anywhere. `parts.public`
/// holds the matching `.pub` line.
fn ssh_ed25519(ctx: &mut GenContext<'_>) -> Result<Generated> {
    let user = ctx.pick_set("users")?;
    let host = ctx.pick_set("hosts")?;
    let comment = format!("{user}@{host}");
    let public = ctx.bytes(32);
    let secret = ctx.bytes(32);

    let mut pub_blob = Vec::new();
    ssh_string(&mut pub_blob, b"ssh-ed25519");
    ssh_string(&mut pub_blob, &public);

    let check = ctx.bytes(4);
    let mut private = Vec::new();
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    ssh_string(&mut private, b"ssh-ed25519");
    ssh_string(&mut private, &public);
    let mut sk = secret.clone();
    sk.extend_from_slice(&public);
    ssh_string(&mut private, &sk);
    ssh_string(&mut private, comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }

    let mut blob = Vec::new();
    blob.extend_from_slice(b"openssh-key-v1\0");
    ssh_string(&mut blob, b"none");
    ssh_string(&mut blob, b"none");
    ssh_string(&mut blob, b"");
    blob.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut blob, &pub_blob);
    ssh_string(&mut blob, &private);

    let kind = pfx(&["OPENSSH PRIVATE", " KEY"]);
    let value = format!(
        "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
        wrap(&STANDARD.encode(&blob), 70)
    );
    let mut parts = BTreeMap::new();
    parts.insert(
        "public".to_string(),
        format!("ssh-ed25519 {} {comment}", STANDARD.encode(&pub_blob)),
    );
    parts.insert("comment".to_string(), comment);
    Ok(Generated {
        value,
        parts,
        canary: false,
    })
}

/// Formats 16 random bytes as an RFC 4122 version-4 UUID.
pub fn uuid_v4(bytes: &[u8]) -> String {
    let mut b = [0u8; 16];
    for (dst, src) in b.iter_mut().zip(bytes.iter()) {
        *dst = *src;
    }
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// A fresh random UUID from the thread CSPRNG.
pub fn random_uuid() -> String {
    let mut b = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut b);
    uuid_v4(&b)
}

/// Allowed character set of a value, used by format tests and canary checks.
pub fn all_in(s: &str, alphabet: &[u8]) -> bool {
    s.bytes().all(|c| alphabet.contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::InstallSeed;

    fn sets() -> BTreeMap<String, Vec<String>> {
        let mut s = BTreeMap::new();
        s.insert("users".into(), vec!["jdoe".into(), "mkim".into()]);
        s.insert("domains".into(), vec!["example.com".into()]);
        s.insert("hosts".into(), vec!["devbox".into()]);
        s.insert("projects".into(), vec!["billing-api-legacy".into()]);
        s
    }

    fn generate(spec: &str) -> Generated {
        let sets = sets();
        let canaries = BTreeMap::new();
        let mut rng = rand::rng();
        let mut chooser = InstallSeed::generate().chooser("t");
        let mut ctx = GenContext {
            entropy: &mut rng,
            chooser: &mut chooser,
            sets: &sets,
            canaries: &canaries,
            now: OffsetDateTime::now_utc(),
        };
        GeneratorSpec::parse(spec)
            .unwrap()
            .generate(&mut ctx)
            .unwrap()
    }

    fn strip<'a>(s: &'a str, prefix: &[&str]) -> &'a str {
        let p = prefix.concat();
        assert!(s.starts_with(&p), "{s} should start with {p}");
        &s[p.len()..]
    }

    #[test]
    fn aws_keys_match_format() {
        let id = generate("aws_access_key_id").value;
        let body = strip(&id, &["AK", "IA"]);
        assert_eq!(body.len(), 16);
        assert!(all_in(body, BASE32));
        let secret = generate("aws_secret_access_key").value;
        assert_eq!(secret.len(), 40);
        assert!(all_in(&secret, B64CHARS));
    }

    #[test]
    fn github_tokens_have_wrong_checksum() {
        for _ in 0..200 {
            let t = generate("github_pat").value;
            let rest = strip(&t, &["gh", "p_"]);
            assert_eq!(rest.len(), 36);
            assert!(all_in(rest, ALNUM));
            let (body, sum) = rest.split_at(30);
            assert_ne!(github_checksum(body), sum, "checksum must never validate");
        }
        let o = generate("github_oauth").value;
        assert_eq!(strip(&o, &["gh", "o_"]).len(), 36);
        let n = generate("npm_token").value;
        let rest = strip(&n, &["np", "m_"]);
        let (body, sum) = rest.split_at(30);
        assert_ne!(github_checksum(body), sum);
    }

    #[test]
    fn checksum_algorithm_matches_reference_crc() {
        // CRC32("123456789") is the standard check value 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(base62(0, 6), "000000");
        assert_eq!(base62(61, 1), "z");
        assert_eq!(base62(62, 2), "10");
    }

    #[test]
    fn ai_provider_keys_match_format() {
        let a = generate("anthropic_api_key").value;
        let body = strip(&a, &["sk-", "ant-", "api03-"]);
        assert_eq!(body.len(), 95);
        assert!(body.ends_with("AA"));
        assert!(all_in(body, URLSAFE));
        let o = generate("openai_api_key").value;
        let body = strip(&o, &["sk-", "proj-"]);
        assert!(body.contains(&["T3Blbk", "FJ"].concat()));
        assert_eq!(body.len(), 156);
        let g = generate("google_api_key").value;
        assert_eq!(strip(&g, &["AI", "za"]).len(), 35);
        let y = generate("google_oauth_access").value;
        assert!(strip(&y, &["ya", "29."]).len() >= 100);
    }

    #[test]
    fn chat_and_payment_tokens_match_format() {
        let s = generate("slack_bot_token").value;
        let rest = strip(&s, &["xo", "xb-"]);
        let segs: Vec<&str> = rest.split('-').collect();
        assert_eq!(segs.len(), 3);
        assert!(all_in(segs[0], DIGITS) && all_in(segs[1], DIGITS));
        assert_eq!(segs[2].len(), 24);
        let st = generate("stripe_secret_key").value;
        assert_eq!(strip(&st, &["sk", "_live_"]).len(), 99);
        let d = generate("discord_token").value;
        let parts: Vec<&str> = d.split('.').collect();
        assert_eq!(parts.len(), 3);
        let id = STANDARD_NO_PAD.decode(parts[0]).unwrap();
        assert_eq!(id.len(), 18);
        assert!(id.iter().all(u8::is_ascii_digit));
        let t = generate("telegram_bot_token").value;
        let (num, tok) = t.split_once(':').unwrap();
        assert_eq!(num.len(), 10);
        assert!(tok.starts_with("AA") && tok.len() == 35);
    }

    #[test]
    fn ssh_key_is_structurally_valid_openssh() {
        let g = generate("ssh_ed25519");
        let kind = ["OPENSSH PRIVATE", " KEY"].concat();
        assert!(g.value.starts_with(&format!("-----BEGIN {kind}-----\n")));
        let b64: String = g
            .value
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let blob = STANDARD.decode(b64).unwrap();
        assert!(blob.starts_with(b"openssh-key-v1\0"));
        let public = g.parts.get("public").unwrap();
        assert!(public.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"));
        let pub_blob = STANDARD.decode(public.split(' ').nth(1).unwrap()).unwrap();
        // The public blob is embedded verbatim in the private file.
        assert!(
            blob.windows(pub_blob.len())
                .any(|w| w == pub_blob.as_slice())
        );
    }

    #[test]
    fn never_reproduces_known_test_vectors() {
        // Published documentation examples, assembled from fragments.
        let vectors = [
            ["AK", "IAIOSFODNN7", "EXAMPLE"].concat(),
            ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"].concat(),
        ];
        for _ in 0..500 {
            let id = generate("aws_access_key_id").value;
            let sk = generate("aws_secret_access_key").value;
            assert!(!vectors.contains(&id));
            assert!(!vectors.contains(&sk));
            assert!(!id.contains("EXAMPLE"));
        }
    }

    #[test]
    fn values_are_random_between_calls() {
        assert_ne!(generate("github_pat").value, generate("github_pat").value);
        assert_ne!(generate("uuid").value, generate("uuid").value);
    }

    #[test]
    fn canaries_replace_generated_values() {
        let sets = sets();
        let mut canaries = BTreeMap::new();
        canaries.insert("aws_access_key_id".to_string(), "CANARY-VALUE".to_string());
        let mut rng = rand::rng();
        let mut chooser = InstallSeed::generate().chooser("t");
        let mut ctx = GenContext {
            entropy: &mut rng,
            chooser: &mut chooser,
            sets: &sets,
            canaries: &canaries,
            now: OffsetDateTime::now_utc(),
        };
        let g = GeneratorSpec::parse("aws_access_key_id")
            .unwrap()
            .generate(&mut ctx)
            .unwrap();
        assert_eq!(g.value, "CANARY-VALUE");
        assert!(g.canary);
    }

    #[test]
    fn parse_rejects_bad_specs() {
        assert!(GeneratorSpec::parse("nope").is_err());
        assert!(GeneratorSpec::parse("hex:abc").is_err());
        assert!(GeneratorSpec::parse("hex:0").is_err());
        assert!(GeneratorSpec::parse("int:9:3").is_err());
        assert!(GeneratorSpec::parse("pick").is_err());
        assert!(GeneratorSpec::parse("hex:16").is_ok());
    }

    #[test]
    fn simple_generators_respect_lengths() {
        assert_eq!(generate("hex:24").value.len(), 24);
        assert!(all_in(&generate("hex:24").value, HEX));
        assert_eq!(generate("alnum:7").value.len(), 7);
        assert_eq!(generate("digits:5").value.len(), 5);
        let u = generate("uuid").value;
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        let e = generate("email").value;
        assert!(e.ends_with("@example.com"));
    }
}
