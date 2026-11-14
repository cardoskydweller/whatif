//! What may print. A string value prints as is only when its path names no secret and it is (a) a literal of the
//! compiled template, (b) made of parts that are each a part of a template literal or of a parameter value that the
//! person passed, (c) an IP address or CIDR, a hostname or an Azure resource id, or (d) a word of `FIXED`. A bool, a
//! number or null prints as is when its path names no secret. Every other value prints as `<masked len N hmac8>`.
//! Nothing searches the output for a secret: each printed piece is built from a field that passed these checks.

use serde_json::Value;
use std::collections::HashSet;
use std::io::Read;

/// A path word that contains one of these (any case, separators removed) makes the value under it secret.
/// `key` also covers `accountKey`, `apiKey` and `privateKey`.
const SECRET_PARTS: [&str; 12] = [
    "key",
    "secret",
    "password",
    "connectionstring",
    "azurewebjobsstorage",
    "token",
    "credential",
    "secure",
    "passwd",
    "passphrase",
    "pfx",
    "signature",
];
/// Short words that make a name secret only at the end of a token (`DBPass`, `adminpass`, `basicauth`), so that
/// `sslCertificates` and `authorizationRules` do not. `bypass` is the one token that ends in one and is not secret.
const SECRET_TOKENS: [&str; 13] =
    ["pass", "pwd", "auth", "cert", "pat", "otp", "pin", "salt", "jwt", "bearer", "cookie", "creds", "webhook"];
/// A path word that starts with one of these is secret. Only a start: `roleAssignments` holds "sig".
const SECRET_STARTS: [&str; 2] = ["sas", "sig"];

/// Words that print wherever they come from (rule d), because what-if lists live values that no template writes.
/// Each holds no secret: `True`/`False` are string bools (API Management `customProperties`), `Enabled`/`Disabled`
/// and `None` are the usual state values, `Allow`/`Deny`, `Inbound`/`Outbound`, `Tcp`/`Udp` and `*` are network
/// rule values, `Http`/`Https` are protocols, and the empty string is no value.
const FIXED: [&str; 15] = [
    "True", "False", "Enabled", "Disabled", "None", "Allow", "Deny", "Inbound", "Outbound", "Tcp", "Udp", "Http", "Https",
    "*", "",
];

/// The parts of a computed name such as `<prefix>-<abbr>-<purpose>-<env>`, in lower case (ARM's `toLower`).
fn parts(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(['-', '_', '.', '/']).filter(|p| !p.is_empty()).map(str::to_ascii_lowercase)
}

/// The words of a path or a name: its alphanumeric runs.
fn words(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty())
}

/// The tokens of a name in lower case: its words, also split before an upper-case letter that follows a lower-case
/// one (`authHeader` is `auth`, `header`) or that starts a word after an acronym (`DBPass` is `db`, `pass`).
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for w in words(s) {
        let c: Vec<char> = w.chars().collect();
        let mut cur = String::new();
        for (i, &ch) in c.iter().enumerate() {
            let next_lower = c.get(i + 1).is_some_and(char::is_ascii_lowercase);
            if i > 0 && ch.is_ascii_uppercase() && (c[i - 1].is_ascii_lowercase() || (c[i - 1].is_ascii_uppercase() && next_lower)) {
                out.push(std::mem::take(&mut cur));
            }
            cur.push(ch.to_ascii_lowercase());
        }
        out.push(cur);
    }
    out
}

/// How secret a path is. `Token`: only a `SECRET_TOKENS` word names it (`disableLocalAuth`), so a bool or a `FIXED`
/// word under it still prints. `Yes`: everything under it is masked.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Secret {
    No,
    Token,
    Yes,
}

pub fn name_secret(s: &str) -> Secret {
    let joined = words(s).collect::<String>().to_ascii_lowercase();
    if SECRET_PARTS.iter().any(|p| joined.contains(p))
        || words(s).any(|w| SECRET_STARTS.iter().any(|p| w.to_ascii_lowercase().starts_with(p)))
    {
        Secret::Yes
    } else if tokens(s).iter().any(|t| t != "bypass" && SECRET_TOKENS.iter().any(|w| t.ends_with(w))) {
        Secret::Token
    } else {
        Secret::No
    }
}

pub fn secret_name(s: &str) -> bool {
    name_secret(s) != Secret::No
}

/// `{"name": "AzureWebJobsStorage", "value": …}` or `{"secret": true, "value": …}`: an app setting or a named value
/// that says its value is a secret.
pub fn names_a_secret(obj: &Value) -> bool {
    obj.get("value").is_some() && (obj["name"].as_str().is_some_and(secret_name) || obj["secret"] == true)
}

/// A template parameter whose type is known and not `secureString`/`secureObject`, and whose name is not a secret
/// name (a plain `string` named `dbPass` still holds a secret).
fn plain_param(name: &str, param: &Value) -> bool {
    param["type"].as_str().is_some_and(|t| !t.to_ascii_lowercase().starts_with("secure")) && !secret_name(name)
}

/// An alphanumeric run of 25 or more characters that holds 3 or more digits.
fn long_run(s: &str) -> bool {
    words(s).any(|w| w.len() >= 25 && w.bytes().filter(u8::is_ascii_digit).count() >= 3)
}

fn ip_or_cidr(s: &str) -> bool {
    let (addr, prefix) = s.split_once('/').unwrap_or((s, ""));
    addr.parse::<std::net::IpAddr>().is_ok() && (prefix.is_empty() || prefix.parse::<u8>().is_ok_and(|n| n <= 128))
}

fn hostname(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && labels[labels.len() - 1].len() >= 2
        && labels[labels.len() - 1].bytes().all(|b| b.is_ascii_alphabetic())
        && !long_run(s)
}

/// An Azure resource id: `/subscriptions/…` or `/providers/…`, segments of name characters only.
fn resource_id(s: &str) -> bool {
    (s.starts_with("/subscriptions/") || s.starts_with("/providers/"))
        && s.len() <= 1024
        && s[1..].split('/').all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._()-".contains(&b)))
        && !long_run(s)
}

/// A key or path part prints as is when it holds name characters only and no long run with a digit.
fn key_safe(k: &str) -> bool {
    !k.is_empty() && k.len() <= 200 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.$@ :-()/".contains(&b)) && !long_run(k)
}

/// A word of an Azure message prints as is when it holds no `= + % & \ $` and no run of 25 letters and digits.
fn message_word_safe(w: &str) -> bool {
    w.bytes().all(|b| b.is_ascii_graphic() && !b"=+%&\\$`~^".contains(&b)) && !words(w).any(|r| r.len() >= 25)
}

/// HMAC-SHA256 (RFC 2104) as hex. The key is 64 bytes, the block size of SHA-256, so it needs no hashing or padding.
fn hmac_hex(key: &[u8; 64], data: &[u8]) -> String {
    let pad = |b: u8| key.iter().map(move |k| k ^ b);
    let inner = toolcrates_sha256::hex(&pad(0x36).chain(data.iter().copied()).collect::<Vec<u8>>());
    let inner = (0..64).step_by(2).map(|i| u8::from_str_radix(&inner[i..i + 2], 16).unwrap());
    toolcrates_sha256::hex(&pad(0x5c).chain(inner).collect::<Vec<u8>>())
}

pub struct Masker {
    pub raw: bool,
    pub masked: usize,
    key: [u8; 64],
    /// The parts that rule (b) accepts: from the template's literals and the plain parameter values.
    known: HashSet<String>,
    /// Values that never print, nor any string that holds one: secure or secret-named parameter values and every
    /// `--param-from` value.
    forbidden: Vec<String>,
}

impl Masker {
    /// A new random HMAC key for each run: masks match across the environments of one run, and a guess cannot be
    /// tested against a mask.
    pub fn new(raw: bool) -> std::io::Result<Masker> {
        let mut key = [0; 64];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
        Ok(Masker { raw, masked: 0, key, known: HashSet::new(), forbidden: Vec::new() })
    }

    /// The parts of a value that rule (b) accepts.
    pub fn learn(&mut self, value: &str) {
        self.known.extend(parts(value));
    }

    /// A value that never prints, nor any string that holds it, in any case (rule (b) ignores case, and a template
    /// can lower-case a value). ASCII case only, so that a match keeps its byte positions in the original text.
    pub fn forbid(&mut self, value: &str) {
        if !value.is_empty() {
            self.forbidden.push(value.to_ascii_lowercase());
        }
    }

    /// A `--params k=v` value: learned when the template's `k` is a plain parameter, else forbidden, and when it is
    /// JSON (a `secureObject`), each string in it is forbidden too.
    pub fn param(&mut self, template: &Value, k: &str, v: &str) {
        if plain_param(k, &template["parameters"][k]) {
            self.learn(v);
        } else {
            self.forbid(v);
            if let Ok(j) = serde_json::from_str(v) {
                self.forbid_strings(&j);
            }
        }
    }

    fn forbid_strings(&mut self, v: &Value) {
        match v {
            Value::String(s) => self.forbid(s),
            Value::Array(a) => a.iter().for_each(|x| self.forbid_strings(x)),
            Value::Object(m) => m.values().for_each(|x| self.forbid_strings(x)),
            _ => {}
        }
    }

    /// The literals of a compiled ARM template: each string that is not an expression, and each single-quoted
    /// literal inside an expression. `name` is the key that holds `v`; the `defaultValue` of a parameter that is not
    /// plain is skipped.
    pub fn learn_template(&mut self, v: &Value, name: &str) {
        match v {
            Value::String(s) if s.starts_with('[') && !s.starts_with("[[") && s.ends_with(']') => {
                // `''` is a quote inside a literal: hold it aside so that the split finds only the delimiters.
                let s = s.replace("''", "\u{1}");
                s.split('\'').skip(1).step_by(2).for_each(|q| self.learn(&q.replace('\u{1}', "'")));
            }
            Value::String(s) => self.learn(s),
            Value::Array(a) => a.iter().for_each(|x| self.learn_template(x, name)),
            Value::Object(m) => m
                .iter()
                .filter(|(k, _)| *k != "defaultValue" || plain_param(name, v))
                .for_each(|(k, x)| self.learn_template(x, k)),
            _ => {}
        }
    }

    fn holds_forbidden(&self, s: &str) -> bool {
        let s = s.to_ascii_lowercase();
        self.forbidden.iter().any(|f| s.contains(f.as_str()))
    }

    fn fixed(&self, s: &str) -> bool {
        !self.holds_forbidden(s) && FIXED.iter().any(|w| w.eq_ignore_ascii_case(s))
    }

    fn prints(&self, s: &str) -> bool {
        self.fixed(s)
            || !self.holds_forbidden(s)
                && (ip_or_cidr(s) || hostname(s) || resource_id(s) || parts(s).all(|p| self.known.contains(&p)))
    }

    fn mask(&mut self, text: &str) -> String {
        self.masked += 1;
        format!("<masked len {} {}>", text.chars().count(), &hmac_hex(&self.key, text.as_bytes())[..8])
    }

    /// One value: a leaf as JSON text or masked; an object or array walked, the same rule on each leaf. `secret`
    /// says how secret the path above it is.
    pub fn value(&mut self, v: &Value, secret: Secret) -> String {
        match v {
            Value::Object(m) => {
                let named = names_a_secret(v);
                let items: Vec<String> = m
                    .iter()
                    .map(|(k, x)| {
                        let s = if named && k != "name" { Secret::Yes } else { secret.max(name_secret(k)) };
                        format!("{}: {}", self.key(k), self.value(x, s))
                    })
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
            Value::Array(a) => {
                let items: Vec<String> = a.iter().map(|x| self.value(x, secret)).collect();
                format!("[{}]", items.join(", "))
            }
            _ if self.raw => v.to_string(),
            Value::String(s) => {
                let shows = match secret {
                    Secret::No => self.prints(s),
                    Secret::Token => self.fixed(s),
                    Secret::Yes => false,
                };
                if shows { v.to_string() } else { self.mask(s) }
            }
            Value::Bool(_) if secret != Secret::Yes => v.to_string(),
            _ if secret != Secret::No => self.mask(&v.to_string()),
            _ => v.to_string(),
        }
    }

    /// A key, a path part or a resource name.
    pub fn key(&mut self, k: &str) -> String {
        if self.raw || key_safe(k) { k.to_string() } else { self.mask(k) }
    }

    /// Free text from Azure (a diagnostic, an error): each forbidden value masked wherever it is (it can hold
    /// spaces), then each quoted span (`'…'` or `"…"`) masked as a whole, then word by word.
    pub fn text(&mut self, s: &str) -> String {
        if self.raw {
            return s.to_string();
        }
        let mut msg = s.to_string();
        for f in self.forbidden.clone() {
            let mut from = 0;
            while let Some(i) = msg.to_ascii_lowercase()[from..].find(&f).map(|i| i + from) {
                let masked = self.mask(&msg[i..i + f.len()]);
                msg.replace_range(i..i + f.len(), &masked);
                // Search on after the mask, which can itself hold a short forbidden value.
                from = i + masked.len();
            }
        }
        let (mut spans, mut rest) = (String::new(), msg.as_str());
        while let Some(i) = rest.find(['\'', '"']) {
            let q = &rest[i..i + 1];
            let Some(j) = rest[i + 1..].find(q) else { break };
            spans += &format!("{}{q}{}{q}", &rest[..i], self.mask(&rest[i + 1..i + 1 + j]));
            rest = &rest[i + 2 + j..];
        }
        spans += rest;
        let words: Vec<String> = spans
            .split_whitespace()
            .map(|w| if message_word_safe(w) { w.to_string() } else { self.mask(w) })
            .collect();
        words.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HEX32: &str = "0123456789abcdef0123456789abcdef";
    const B64_88: &str = "fake+key/AAAA0000fake+key/AAAA0000fake+key/AAAA0000fake+key/AAAA0000fake+key/AAAA000==";

    fn masker() -> Masker {
        Masker::new(false).unwrap()
    }

    /// A masker that knows the literals of the test template.
    fn with_template() -> Masker {
        let mut m = masker();
        m.learn_template(&serde_json::from_str(include_str!("../tests/fixtures/template.json")).unwrap(), "");
        m
    }

    fn attack_template() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/attack-template.json")).unwrap()
    }

    fn prints(m: &mut Masker, s: &str) -> bool {
        !m.value(&json!(s), Secret::No).starts_with("<masked")
    }

    #[test]
    fn the_fixed_words_print_in_any_case_and_other_words_do_not() {
        let mut m = masker();
        for s in FIXED.into_iter().chain(["enabled", "TRUE"]) {
            assert!(prints(&mut m, s), "{s}");
        }
        for s in ["Standard_v2", "Tls1_2", "Info", "443"] {
            assert!(!prints(&mut m, s), "only a template literal makes {s} print");
        }
    }

    #[test]
    fn bools_numbers_and_null_print() {
        let mut m = masker();
        assert_eq!(m.value(&json!([true, 443, null]), Secret::No), "[true, 443, null]");
    }

    #[test]
    fn addresses_hosts_and_resource_ids_print() {
        let mut m = masker();
        for s in [
            "10.4.0.0/24",
            "10.4.1.5",
            "2001:db8::/32",
            "ex-ample-qa.azure-api.net",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ex/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf-ex",
        ] {
            assert!(prints(&mut m, s), "{s}");
        }
    }

    #[test]
    fn a_host_or_resource_id_that_holds_a_key_shaped_run_is_masked() {
        let mut m = masker();
        for s in [format!("{HEX32}.blob.example.test"), format!("/subscriptions/0/providers/Microsoft.Ex/things/{HEX32}")] {
            assert!(!prints(&mut m, &s), "{s}");
        }
    }

    #[test]
    fn a_template_literal_prints_whole_and_in_a_computed_name() {
        let mut m = with_template();
        for s in ["Standard_v2", "Tls1_2", "Premium", "func", "443"] {
            assert!(prints(&mut m, s), "a literal of the template: {s}");
        }
        assert!(!prints(&mut m, "ex-func-qa"), "ex and qa are not known yet");
        m.learn("ex");
        m.learn("qa");
        assert!(prints(&mut m, "ex-func-qa") && prints(&mut m, "EX_func.qa/Premium"), "every part is known");
        assert!(!prints(&mut m, "ex-func-FakeName123"), "one part is not known");
    }

    #[test]
    fn a_quoted_literal_inside_an_expression_is_a_literal_and_the_expression_is_not() {
        let mut m = with_template();
        assert!(prints(&mut m, "Enabled-or-Off"), "from [if(…, 'Enabled-or-Off', …)]");
        assert!(prints(&mut m, "it's"), "'' is an escaped quote: it''s");
        assert!(!prints(&mut m, "parameters('prefix')"), "the expression text itself");
    }

    #[test]
    fn a_secure_parameter_default_is_never_a_literal() {
        let mut m = with_template();
        assert!(!prints(&mut m, "FakeDefault123"));
        assert!(!prints(&mut m, "FakeObjectDefault123"));
        assert!(prints(&mut m, "PlainDefault"), "a string parameter's default is a literal");
    }

    /// I1: random key-shaped tokens never print, even when the template's literals are known.
    #[test]
    fn random_base64url_and_alphanumeric_tokens_of_16_to_43_characters_never_print() {
        let mut m = with_template();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let alphabets = [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        ];
        let mut printed = Vec::new();
        for alphabet in alphabets {
            for len in 16..=43 {
                for _ in 0..200 {
                    let token: String = (0..len)
                        .map(|_| {
                            x ^= x << 13;
                            x ^= x >> 7;
                            x ^= x << 17;
                            alphabet.as_bytes()[(x % alphabet.len() as u64) as usize] as char
                        })
                        .collect();
                    if prints(&mut m, &token) {
                        printed.push(token);
                    }
                }
            }
        }
        assert!(printed.is_empty(), "{printed:?}");
    }

    #[test]
    fn free_text_and_connection_strings_are_masked() {
        let mut m = masker();
        for s in [
            "DefaultEndpointsProtocol=https;AccountName=example;AccountKey=fake-key-AAAA",
            "https://ex.example.test/path?sig=fake",
            "hello world",
            HEX32,
            B64_88,
            "2026-11-10T00:00:00Z",
        ] {
            assert!(!prints(&mut m, s), "{s}");
        }
    }

    #[test]
    fn a_secret_word_in_the_path_masks_even_a_value_that_would_print() {
        let mut m = with_template();
        assert!(m.value(&json!("Enabled"), Secret::Yes).starts_with("<masked len 7 "));
        assert!(m.value(&json!("Standard_v2"), Secret::Yes).starts_with("<masked len 11 "));
        assert!(m.value(&json!(42), Secret::Yes).starts_with("<masked len 2 "));
        for name in ["primaryKey", "clientSecret", "adminPassword", "AzureWebJobsStorage", "sasUrl", "sig", "accessToken", "credentials"] {
            assert!(secret_name(name), "{name}");
        }
        for name in ["roleAssignments", "publicNetworkAccess", "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10"] {
            assert!(!secret_name(name), "{name}");
        }
    }

    #[test]
    fn a_token_that_ends_in_pass_pwd_auth_or_cert_is_secret_except_bypass() {
        for name in ["DB_PASS", "SQL_PWD", "PASS_PHRASE", "authHeader", "cert", "sslCert", "adminpass", "dbpwd", "basicauth", "clientcert"] {
            assert!(secret_name(name), "{name}");
        }
        for name in ["bypass", "sslCertificates", "authorizationRules", "properties.networkAcls.bypass", "privateIPAddress"] {
            assert!(!secret_name(name), "{name}");
        }
    }

    #[test]
    fn token_and_session_words_are_secret_only_at_the_end_of_a_token() {
        for name in ["pat", "githubPat", "otp", "pin", "salt", "jwt", "bearer", "cookie", "creds", "webhookUrl"] {
            assert!(secret_name(name), "{name}");
        }
        for name in ["path", "pinnedVersion", "patchMode", "cookieless"] {
            assert!(!secret_name(name), "{name}");
        }
    }

    #[test]
    fn a_word_after_an_acronym_is_its_own_token() {
        for name in ["DBPass", "SMTPPass", "SQLPwd"] {
            assert!(secret_name(name), "{name}");
        }
        assert_eq!(tokens("SMTPPass privateIPAddress"), ["smtp", "pass", "private", "ip", "address"]);
    }

    #[test]
    fn pfx_and_signature_are_secret_words() {
        for name in ["pfx", "pfxBlob", "sharedAccessSignature"] {
            assert!(secret_name(name), "{name}");
        }
    }

    #[test]
    fn a_secret_named_plain_parameter_value_is_forbidden_and_a_plain_one_is_learned() {
        let (mut m, t) = (masker(), attack_template());
        m.param(&t, "dbPass", "FakeDbPass9");
        m.param(&t, "gwCertData", "FakeCertBlobAAAA");
        m.param(&t, "envName", "FakeEnvQa");
        assert!(!prints(&mut m, "FakeDbPass9") && !prints(&mut m, "FakeCertBlobAAAA"));
        assert!(prints(&mut m, "FakeEnvQa"));
    }

    #[test]
    fn a_secret_named_parameter_default_is_never_a_literal() {
        let mut m = masker();
        m.learn_template(&attack_template(), "");
        assert!(!prints(&mut m, "FakeDefault77"));
    }

    #[test]
    fn a_string_that_holds_a_secure_value_never_prints_even_when_its_parts_are_known() {
        let mut m = masker();
        let t: Value = serde_json::from_str(include_str!("../tests/fixtures/parts-template.json")).unwrap();
        m.learn_template(&t, "");
        assert!(prints(&mut m, "FakeAdmin-Secure-7"), "each part is in some literal");
        m.param(&t, "adminPassword", "FakeAdmin-Secure-7");
        assert!(!prints(&mut m, "FakeAdmin-Secure-7") && !prints(&mut m, "rg-FakeAdmin-Secure-7"));
        assert!(prints(&mut m, "rg-fakeadmin"), "a literal still prints");
    }

    #[test]
    fn a_lower_cased_secure_value_never_prints() {
        let mut m = masker();
        let t: Value = serde_json::from_str(include_str!("../tests/fixtures/parts-template.json")).unwrap();
        m.learn_template(&t, "");
        m.param(&t, "adminPassword", "FakeAdmin-Secure-7");
        assert!(!prints(&mut m, "fakeadmin-secure-7") && !prints(&mut m, "FAKEADMIN-SECURE-7"));
    }

    #[test]
    fn a_message_word_that_holds_a_forbidden_value_is_masked() {
        let mut m = masker();
        m.forbid("FakeAdmin-Secure-7");
        let out = m.text("value FakeAdmin-Secure-7 is not valid");
        assert!(out.starts_with("value <masked len 18 ") && out.ends_with("> is not valid"), "{out}");
    }

    #[test]
    fn a_forbidden_value_with_spaces_is_masked_in_a_message_in_any_case() {
        let mut m = masker();
        m.forbid("Fake Admin Seven");
        let out = m.text("ERROR: the value fake admin SEVEN is not valid");
        assert!(out.starts_with("ERROR: the value <masked len 16 ") && out.ends_with("> is not valid"), "{out}");
    }

    #[test]
    fn a_short_forbidden_value_that_is_in_its_own_mask_still_ends() {
        let mut m = masker();
        m.forbid("a");
        assert!(!m.text("a cat").contains(" cat"));
    }

    #[test]
    fn each_string_in_a_secure_object_value_is_forbidden() {
        let mut m = masker();
        let t: Value = serde_json::from_str(include_str!("../tests/fixtures/obj-template.json")).unwrap();
        m.learn_template(&t, "");
        assert!(prints(&mut m, "db.example.test"), "a hostname and a template literal");
        m.param(&t, "cfg", r#"{"host":"db.example.test","user":"FakeObjLeaf"}"#);
        assert!(!prints(&mut m, "db.example.test") && !prints(&mut m, "FakeObjLeaf"));
    }

    #[test]
    fn under_a_token_only_path_only_a_bool_or_a_fixed_word_prints() {
        assert_eq!((name_secret("disableLocalAuth"), name_secret("adminPassword")), (Secret::Token, Secret::Yes));
        let mut m = with_template();
        assert_eq!(m.value(&json!(true), Secret::Token), "true");
        assert_eq!(m.value(&json!("Disabled"), Secret::Token), "\"Disabled\"");
        for v in [json!("Standard_v2"), json!(42), json!(null)] {
            assert!(m.value(&v, Secret::Token).starts_with("<masked"), "{v}");
        }
        assert!(m.value(&json!(true), Secret::Yes).starts_with("<masked len 4 "));
    }

    #[test]
    fn secure_is_a_secret_word() {
        assert!(secret_name("secureValue"));
    }

    #[test]
    fn private_key_is_secret_and_other_private_names_are_not() {
        for name in ["privateKey", "private_key", "PRIVATE_KEY_PEM"] {
            assert!(secret_name(name), "{name}");
        }
        for name in ["privateIPAddress", "privateLinkServiceConnections", "privateEndpoints", "privateDnsZones"] {
            assert!(!secret_name(name), "{name}");
        }
    }

    #[test]
    fn passwd_and_passphrase_are_secret_words() {
        assert!(secret_name("DB_PASSWD"));
        assert!(secret_name("userPassphrase"));
    }

    #[test]
    fn a_secret_word_split_by_separators_is_still_a_secret_word() {
        assert!(secret_name("CONNECTION_STRING"));
        assert!(secret_name("APPLICATIONINSIGHTS_CONNECTION_STRING"));
    }

    #[test]
    fn a_value_beside_secret_true_is_secret() {
        assert!(names_a_secret(&json!({"displayName": "backend", "secret": true, "value": "Enabled"})));
        assert!(!names_a_secret(&json!({"displayName": "backend", "secret": false, "value": "Enabled"})));
    }

    #[test]
    fn hmac_matches_rfc_4231_test_case_2() {
        let mut key = [0; 64];
        key[..4].copy_from_slice(b"Jefe");
        assert_eq!(
            hmac_hex(&key, b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_mask_gives_the_length_and_the_first_8_hex_of_the_hmac() {
        let mut m = masker();
        m.key = [7; 64];
        assert_eq!(m.value(&json!("abc"), Secret::Yes), format!("<masked len 3 {}>", &hmac_hex(&[7; 64], b"abc")[..8]));
        assert_eq!(m.masked, 1);
        assert!(!m.value(&json!("abc"), Secret::Yes).contains(&toolcrates_sha256::hex(b"abc")[..8]), "not the plain SHA-256");
    }

    #[test]
    fn each_run_has_its_own_key_and_one_run_gives_one_mask_per_value() {
        let (mut a, mut b) = (masker(), masker());
        assert_eq!(a.value(&json!("x"), Secret::Yes), a.value(&json!("x"), Secret::Yes));
        assert_ne!(a.value(&json!("x"), Secret::Yes), b.value(&json!("x"), Secret::Yes));
    }

    #[test]
    fn objects_and_arrays_are_walked_leaf_by_leaf() {
        let mut m = masker();
        let v = json!({"state": "Enabled", "nested": {"password": "Enabled"}, "list": [HEX32, 7]});
        let out = m.value(&v, Secret::No);
        assert!(out.starts_with("{list: [<masked len 32 "), "{out}");
        assert!(out.contains(", 7], nested: {password: <masked len 7 "), "{out}");
        assert!(out.ends_with("state: \"Enabled\"}"), "{out}");
    }

    #[test]
    fn a_secret_name_field_masks_its_siblings() {
        let mut m = with_template();
        m.learn("AzureWebJobsStorage");
        m.learn("AllowKeyVaultOutbound");
        let out = m.value(&json!({"name": "AzureWebJobsStorage", "value": "Premium"}), Secret::No);
        assert!(out.starts_with("{name: \"AzureWebJobsStorage\", value: <masked len 7 "), "{out}");
        let rule = m.value(&json!({"name": "AllowKeyVaultOutbound", "properties": {"priority": 100}}), Secret::No);
        assert_eq!(rule, "{name: \"AllowKeyVaultOutbound\", properties: {priority: 100}}", "only a name with a value");
    }

    #[test]
    fn message_words_with_a_long_run_or_an_equals_sign_are_masked() {
        let mut m = masker();
        let out = m.text(&format!("The value {HEX32} and AccountKey={} were refused.", &B64_88[..20]));
        assert!(out.starts_with("The value <masked len 32 "), "{out}");
        assert!(out.contains(" and <masked len 31 ") && out.ends_with(" were refused."), "{out}");
    }

    #[test]
    fn a_quoted_span_in_a_message_is_masked_whole() {
        let mut m = masker();
        let out = m.text("The provided value 'FakePass123' for the template parameter \"admin Pass\" is not valid.");
        assert!(!out.contains("FakePass123") && !out.contains("admin Pass"), "{out}");
        assert!(out.starts_with("The provided value '<masked len 11 ") && out.contains(">' for the template parameter \"<masked len 10 "), "{out}");
        assert!(out.ends_with(">\" is not valid."), "{out}");
    }

    #[test]
    fn keys_with_a_long_run_holding_a_digit_are_masked() {
        let mut m = masker();
        assert_eq!(m.key("applicationGatewayIPConfigurations"), "applicationGatewayIPConfigurations");
        assert_eq!(m.key("exPrivateFrontendIpConfigIPv4"), "exPrivateFrontendIpConfigIPv4");
        assert!(m.key(HEX32).starts_with("<masked len 32 "));
    }

    #[test]
    fn raw_prints_everything() {
        let mut m = Masker::new(true).unwrap();
        assert_eq!(m.value(&json!({"password": HEX32}), Secret::No), format!("{{password: \"{HEX32}\"}}"));
        assert_eq!(m.text("value 'FakePass123'"), "value 'FakePass123'");
        assert_eq!(m.masked, 0);
    }
}
