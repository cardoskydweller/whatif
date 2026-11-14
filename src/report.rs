//! One what-if result (the JSON of `az deployment … what-if --no-pretty-print -o json`) as lines of text.

use crate::mask::{Masker, Secret, name_secret, names_a_secret, secret_name};
use serde_json::Value;
use std::collections::BTreeMap;

/// Read-only properties that every what-if lists as removed, whatever the template says.
const READ_ONLY: [&str; 2] = ["applicationGatewayIPConfigurations", "privateLinkIpConfigurations"];

/// The what-if `changeType` and `propertyChangeType` values. Anything else prints as `?`.
const CHANGE_TYPES: [&str; 9] = ["Array", "Create", "Delete", "Deploy", "Ignore", "Modify", "NoChange", "NoEffect", "Unsupported"];

fn change_type(v: &Value) -> &'static str {
    CHANGE_TYPES.into_iter().find(|t| v.as_str() == Some(t)).unwrap_or("?")
}

/// The segments of a resource type after its namespace (`vaults`, `secrets`) count as path words.
fn type_is_secret(id: &str) -> bool {
    id.rsplit_once("/providers/").is_some_and(|(_, r)| r.split('/').skip(1).step_by(2).any(secret_name))
}

#[derive(Default)]
pub struct Counts {
    pub by_type: BTreeMap<String, usize>,
    pub dropped: usize,
    pub noise: usize,
}

/// The value at a delta path inside a resource payload. A path level can be dotted (`properties.priority`) and
/// a key can hold dots (`Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10`), so the longest
/// key that exists wins.
fn resolve<'a>(mut v: &'a Value, levels: &[String]) -> Option<&'a Value> {
    let segs: Vec<&str> = levels.iter().flat_map(|l| l.split('.')).collect();
    let mut i = 0;
    while i < segs.len() {
        match v {
            Value::Array(a) => {
                v = a.get(segs[i].parse::<usize>().ok()?)?;
                i += 1;
            }
            Value::Object(m) => {
                let k = (i + 1..=segs.len()).rev().find(|&k| m.contains_key(&segs[i..k].join(".")))?;
                v = &m[&segs[i..k].join(".")];
                i = k;
            }
            _ => return None,
        }
    }
    Some(v)
}

/// Why a delta is noise, if it is.
fn noise(change: &Value, levels: &[String]) -> Option<&'static str> {
    if levels.iter().flat_map(|l| l.split('.')).any(|w| READ_ONLY.iter().any(|r| r.eq_ignore_ascii_case(w))) {
        return Some("read-only property, listed by every what-if");
    }
    let sorted = |side: &str| {
        let mut items: Vec<String> = resolve(&change[side], levels)?.as_array()?.iter().map(Value::to_string).collect();
        items.sort();
        Some(items)
    };
    match (sorted("before"), sorted("after")) {
        (Some(b), Some(a)) if a == b => Some("the same items in a new order"),
        _ => None,
    }
}

fn path_text(m: &mut Masker, levels: &[String]) -> String {
    let mut out = String::new();
    for l in levels {
        if l.parse::<usize>().is_ok() {
            out += &format!("[{l}]");
        } else {
            out += &format!("{}{}", if out.is_empty() { "" } else { "." }, m.key(l));
        }
    }
    out
}

/// `Microsoft.Network/applicationGateways/agw-ex/…` as its type and its name, and its resource group.
fn resource(m: &mut Masker, id: &str) -> String {
    let rest = id.rsplit_once("/providers/").map(|(_, r)| r).unwrap_or(id);
    let mut segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    if !id.contains("/providers/") && segs.first() == Some(&"subscriptions") {
        segs.drain(..segs.len().min(2));
    }
    let (mut types, mut names) = (Vec::new(), Vec::new());
    if id.contains("/providers/") && !segs.is_empty() {
        types.push(m.key(segs.remove(0)));
    }
    for pair in segs.chunks(2) {
        types.push(m.key(pair[0]));
        names.extend(pair.get(1).map(|n| m.key(n)));
    }
    let mut out = format!("{}  {}", types.join("/"), names.join("/"));
    let rg = id.split('/').skip_while(|s| !s.eq_ignore_ascii_case("resourceGroups")).nth(1);
    if let Some(rg) = rg.filter(|_| id.contains("/providers/")) {
        out += &format!("  (group {})", m.key(rg));
    }
    out
}

fn walk(m: &mut Masker, change: &Value, deltas: &[Value], parent: &[String], counts: &mut Counts, out: &mut Vec<String>) {
    for x in deltas {
        let kind = change_type(&x["propertyChangeType"]);
        if kind == "NoEffect" {
            continue;
        }
        let levels = [parent, &[x["path"].as_str().unwrap_or("?").to_string()]].concat();
        let path = path_text(m, &levels);
        if let Some(why) = noise(change, &levels) {
            counts.noise += 1;
            out.push(format!("    noise   {kind:<7} {path}: {why}"));
            continue;
        }
        if let Some(children) = x["children"].as_array().filter(|c| !c.is_empty()) {
            walk(m, change, children, &levels, counts, out);
            continue;
        }
        // The object that holds the value, on either side: an array that shifts puts a secret setting in `before` only.
        let segs: Vec<String> = levels.iter().flat_map(|l| l.split('.')).map(String::from).collect();
        let named = ["before", "after"].iter().filter_map(|s| resolve(&change[s], &segs[..segs.len() - 1])).any(names_a_secret);
        let secret = if named || type_is_secret(change["resourceId"].as_str().unwrap_or("")) {
            Secret::Yes
        } else {
            levels.iter().map(|l| name_secret(l)).max().unwrap_or(Secret::No)
        };
        let before = if kind == "Create" { "(none)".to_string() } else { m.value(&x["before"], secret) };
        let after = if kind == "Delete" { "(none)".to_string() } else { m.value(&x["after"], secret) };
        let dropped = kind == "Delete" && levels.last().is_some_and(|l| l.parse::<usize>().is_err());
        counts.dropped += dropped as usize;
        let flag = if dropped { "  DROPPED-BY-OMISSION" } else { "" };
        out.push(format!("    {kind:<7} {path}: {before} -> {after}{flag}"));
    }
}

fn error_lines(m: &mut Masker, e: &Value, indent: &str, out: &mut Vec<String>) {
    if e.is_null() {
        return;
    }
    let code = m.key(e["code"].as_str().unwrap_or("?"));
    out.push(format!("{indent}error {code}: {}", m.text(e["message"].as_str().unwrap_or(""))));
    for d in e["details"].as_array().into_iter().flatten() {
        error_lines(m, d, &format!("{indent}  "), out);
    }
}

pub fn render(m: &mut Masker, d: &Value, only_changes: bool, out: &mut Vec<String>) -> Counts {
    let mut counts = Counts::default();
    error_lines(m, &d["error"], "", out);
    for g in d["diagnostics"].as_array().into_iter().flatten() {
        let level = m.key(g["level"].as_str().unwrap_or("?"));
        let code = m.key(g["code"].as_str().unwrap_or("?"));
        out.push(format!("diagnostic {level} {code}: {}", m.text(g["message"].as_str().unwrap_or(""))));
        if let Some(t) = g["target"].as_str() {
            out.push(format!("    target {}", resource(m, t)));
        }
    }
    for c in d["changes"].as_array().into_iter().flatten() {
        let kind = change_type(&c["changeType"]);
        *counts.by_type.entry(kind.to_string()).or_default() += 1;
        if only_changes && (kind == "NoChange" || kind == "Ignore") {
            continue;
        }
        let mut line = format!("{kind:<11} {}", resource(m, c["resourceId"].as_str().unwrap_or("?")));
        if let Some(r) = c["unsupportedReason"].as_str() {
            line += &format!(": {}", m.text(r));
        }
        out.push(line);
        walk(m, c, c["delta"].as_array().map_or(&[], |v| v), &[], &mut counts, out);
    }
    if let Some(n) = d["potentialChanges"].as_array().map(Vec::len).filter(|&n| n > 0) {
        out.push(format!("potentialChanges: {n} (not shown)"));
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(fixture: &str, only_changes: bool) -> (Vec<String>, Counts) {
        run_knowing(fixture, only_changes, &[])
    }

    /// As if the template wrote each of `known` as a literal, so that only the secret-path rules can mask them.
    fn run_knowing(fixture: &str, only_changes: bool, known: &[&str]) -> (Vec<String>, Counts) {
        let d: Value = serde_json::from_str(fixture).unwrap();
        let (mut m, mut out) = (Masker::new(false).unwrap(), Vec::new());
        known.iter().for_each(|k| m.learn(k));
        let counts = render(&mut m, &d, only_changes, &mut out);
        (out, counts)
    }

    const LEAK_FAKES: [&str; 15] = [
        "FakePass123",
        "FakeKvValue123",
        "FakeDbPass123",
        "FakeDbPass124",
        "Fake-Pwd-2024",
        "Fake-Pwd-2025",
        "FakeCorrectHorseBattery",
        "FakeCorrectHorseStaple",
        "FakeShifted123",
        "FakeSecure123",
        "FakeSecure124",
        "FakeNamed123",
        "FakeConn123",
        "FakePem123",
        "FakeAuth123",
    ];

    #[test]
    fn no_fake_secret_of_the_leak_fixture_prints_even_as_a_template_literal() {
        let (out, _) = run_knowing(include_str!("../tests/fixtures/leaks.json"), false, &LEAK_FAKES);
        let text = out.join("\n");
        for fake in LEAK_FAKES {
            assert!(!text.contains(fake), "{fake}:\n{text}");
        }
    }

    #[test]
    fn a_secret_setting_is_masked_when_the_array_shifts_it_out_of_after() {
        let (out, _) = run_knowing(include_str!("../tests/fixtures/leaks.json"), false, &["FakeShifted123", "Info"]);
        let l = line(&out, "appSettings[0].value: ");
        assert!(l.contains(": <masked len 14 ") && l.contains(" -> <masked len 4 "), "{l}");
    }

    #[test]
    fn a_key_vault_secret_value_is_masked_by_its_resource_type() {
        let (out, _) = run_knowing(include_str!("../tests/fixtures/leaks.json"), false, &["FakeKvValue123"]);
        line(&out, "properties.value: (none) -> <masked len 14 ");
    }

    #[test]
    fn the_review_names_are_masked_and_the_network_names_print() {
        let mut m = Masker::new(false).unwrap();
        m.learn_template(&serde_json::from_str(include_str!("../tests/fixtures/names-template.json")).unwrap(), "");
        let mut out = Vec::new();
        render(&mut m, &serde_json::from_str(include_str!("../tests/fixtures/names-whatif.json")).unwrap(), false, &mut out);
        for name in ["DBPass", "SMTPPass", "SQLPwd", "adminpass", "dbpwd", "clientcert", "basicauth", "BasicAuth", "pfxBlob", "pfx", "sharedAccessSignature"] {
            assert!(line(&out, &format!("properties.{name}: ")).contains("-> <masked len 8 "), "{name}");
        }
        for name in ["bypass", "privateIPAddress", "sslCertificates", "authorizationRules"] {
            assert!(line(&out, &format!("properties.{name}: ")).ends_with("-> \"FakeVal1\""), "{name}");
        }
    }

    #[test]
    fn a_token_only_path_masks_a_known_string_and_prints_a_bool_or_fixed_word() {
        let (out, _) = run_knowing(include_str!("../tests/fixtures/names2-whatif.json"), false, &["FakeVal1"]);
        for name in ["disableLocalAuth", "cookieBasedAffinity", "clientCertEnabled", "clientCertMode", "siteAuthEnabled", "saltValue"] {
            assert!(line(&out, &format!("properties.{name}: ")).contains("-> <masked len 8 "), "{name}");
        }
        let bools = r#"{"changes":[{"changeType":"Modify","resourceId":"/subscriptions/0/resourceGroups/rg-ex/providers/Microsoft.Web/sites/ex","delta":[
            {"path":"properties.disableLocalAuth","propertyChangeType":"Modify","before":false,"after":true},
            {"path":"properties.clientCertMode","propertyChangeType":"Modify","before":"Disabled","after":"Enabled"},
            {"path":"properties.cookieBasedAffinity","propertyChangeType":"Modify","before":7,"after":null},
            {"path":"properties.adminPassword","propertyChangeType":"Modify","before":false,"after":true}]}]}"#;
        let (out, _) = run(bools, false);
        line(&out, "properties.disableLocalAuth: false -> true");
        line(&out, "properties.clientCertMode: \"Disabled\" -> \"Enabled\"");
        assert!(line(&out, "properties.cookieBasedAffinity: <masked len 1 ").contains("-> <masked len 4 "));
        assert!(line(&out, "properties.adminPassword: <masked len 5 ").contains("-> <masked len 4 "));
    }

    #[test]
    fn a_bool_or_fixed_word_stays_masked_under_the_type_rule_a_named_setting_or_secret_true() {
        let fixture = r#"{"changes":[
            {"changeType":"Modify","resourceId":"/subscriptions/0/resourceGroups/rg-ex/providers/Microsoft.KeyVault/vaults/kv-ex/secrets/s",
             "delta":[{"path":"properties.enabledFlag","propertyChangeType":"Modify","before":false,"after":true}]},
            {"changeType":"Modify","resourceId":"/subscriptions/0/resourceGroups/rg-ex/providers/Microsoft.Web/sites/ex",
             "before":{"s":[{"name":"DB_PASSWORD","value":"Enabled"}],"n":{"secret":true,"value":"Enabled"}},
             "after":{"s":[{"name":"DB_PASSWORD","value":"Disabled"}],"n":{"secret":true,"value":"Disabled"}},
             "delta":[{"path":"s","propertyChangeType":"Array","children":[{"path":"0","propertyChangeType":"Modify","children":[
                {"path":"value","propertyChangeType":"Modify","before":"Enabled","after":"Disabled"}]}]},
               {"path":"n.value","propertyChangeType":"Modify","before":"Enabled","after":"Disabled"}]}]}"#;
        let (out, _) = run(fixture, false);
        assert!(line(&out, "properties.enabledFlag: <masked len 5 ").contains("-> <masked len 4 "));
        assert!(line(&out, "s[0].value: <masked len 7 ").contains("-> <masked len 8 "));
        assert!(line(&out, "n.value: <masked len 7 ").contains("-> <masked len 8 "));
    }

    #[test]
    fn a_private_endpoint_or_dns_zone_type_is_not_secret() {
        for t in ["Microsoft.Network/privateEndpoints/pe-ex", "Microsoft.Network/privateDnsZones/ex.example.test/A/rec"] {
            assert!(!type_is_secret(&format!("/subscriptions/0/resourceGroups/rg-ex/providers/{t}")), "{t}");
        }
    }

    #[test]
    fn a_value_beside_secret_true_is_masked() {
        let (out, _) = run_knowing(include_str!("../tests/fixtures/leaks.json"), false, &["FakeNamed123"]);
        line(&out, "properties.value: (none) -> <masked len 12 ");
    }

    #[test]
    fn a_change_type_outside_the_what_if_list_prints_as_a_question_mark() {
        let fixture = r#"{"changes":[{"changeType":"FakeType<x>","resourceId":"/subscriptions/0/resourceGroups/rg-ex/providers/Microsoft.Web/sites/ex",
            "delta":[{"path":"properties.a","propertyChangeType":"FakeKind","before":1,"after":2}]}]}"#;
        let (out, counts) = run(fixture, false);
        assert!(out[0].starts_with("?           Microsoft.Web/sites  ex"), "{}", out.join("\n"));
        assert_eq!(out[1], "    ?       properties.a: 1 -> 2");
        assert_eq!(counts.by_type["?"], 1);
    }

    fn line<'a>(out: &'a [String], has: &str) -> &'a str {
        out.iter().find(|l| l.contains(has)).unwrap_or_else(|| panic!("no line with {has}:\n{}", out.join("\n")))
    }

    #[test]
    fn diagnostics_print_before_the_changes() {
        let (out, _) = run(include_str!("../tests/fixtures/short-circuited.json"), false);
        assert!(out[0].starts_with("diagnostic Warning NestedDeploymentShortCircuited: "), "{}", out.join("\n"));
        assert!(out[1].contains("Microsoft.Resources/deployments  ex-nested  (group rg-ex-qa)"), "{}", out[1]);
        assert!(out[0].contains(" a parameter <masked len 21 "), "the message is masked word by word: {}", out[0]);
    }

    #[test]
    fn an_unsupported_resource_prints_its_reason_masked() {
        let (out, _) = run(include_str!("../tests/fixtures/short-circuited.json"), false);
        let l = line(&out, "Unsupported Microsoft.Web/sites  func-ex-qa  (group rg-ex-qa): The value <masked len 17 ");
        assert!(l.ends_with("> cannot be evaluated."), "{l}");
    }

    #[test]
    fn a_secret_word_in_a_delta_path_masks_a_known_value() {
        let (out, _) = run_knowing(include_str!("../tests/fixtures/gateway.json"), false, &["Microsoft.Storage", "Microsoft.Keyvault"]);
        let l = line(&out, "properties.encryption.keySource: ");
        assert!(l.contains(": <masked len 17 ") && l.contains("-> <masked len 18 "), "{l}");
    }

    #[test]
    fn one_line_per_resource_with_its_type_and_name() {
        let (out, counts) = run(include_str!("../tests/fixtures/gateway.json"), false);
        line(&out, "NoChange    Microsoft.Network/networkSecurityGroups  nsg-ex-qa  (group rg-ex-qa)");
        line(&out, "Create      Microsoft.Network/networkSecurityGroups/securityRules  nsg-ex-qa/allow-ex  (group rg-ex-qa)");
        assert_eq!(counts.by_type["Modify"], 2);
    }

    #[test]
    fn a_modified_property_prints_its_path_before_and_after() {
        let (out, _) = run(include_str!("../tests/fixtures/gateway.json"), false);
        line(&out, "    Modify  properties.publicNetworkAccess: \"Enabled\" -> \"Disabled\"");
        line(&out, "    Modify  properties.securityRules[0].properties.priority: 100 -> 200");
    }

    #[test]
    fn a_property_removed_by_omission_is_flagged() {
        let (out, counts) = run(include_str!("../tests/fixtures/gateway.json"), false);
        let l = line(&out, "Gateway.Security.Protocols.Tls10");
        assert!(l.contains("\"False\" -> (none)  DROPPED-BY-OMISSION"), "{l}");
        assert_eq!(counts.dropped, 2);
        assert!(!line(&out, "securityRules[1]").contains("DROPPED"), "an array item is not a property");
    }

    #[test]
    fn read_only_properties_and_reordered_arrays_are_noise() {
        let (out, counts) = run(include_str!("../tests/fixtures/gateway.json"), false);
        line(&out, "    noise   Delete  properties.privateLinkIpConfigurations: read-only property");
        line(&out, "    noise   Array   zones: the same items in a new order");
        assert_eq!(counts.noise, 2);
        assert!(!out.iter().any(|l| l.contains("zones[")), "{}", out.join("\n"));
    }

    #[test]
    fn a_storage_key_in_an_app_setting_is_masked() {
        let fixture = include_str!("../tests/fixtures/app-settings.json");
        let (out, _) = run(fixture, false);
        let text = out.join("\n");
        assert!(!text.contains("fake-key-AAAA") && !text.contains("short-secret"), "{text}");
        line(&out, "properties.siteConfig.appSettings[0].value: <masked len ");
        let l = line(&out, "appSettings[1].value");
        assert!(l.contains(": <masked len 12 ") && l.contains("-> <masked len 12 "), "the name masks a short value: {l}");
        line(&out, "properties.siteConfig.appSettings[2].value: \"Enabled\" -> \"Disabled\"");
    }

    #[test]
    fn only_changes_hides_nochange_and_ignore_but_counts_them() {
        let (out, counts) = run(include_str!("../tests/fixtures/gateway.json"), true);
        assert!(!out.iter().any(|l| l.starts_with("NoChange") || l.starts_with("Ignore")), "{}", out.join("\n"));
        assert_eq!((counts.by_type["NoChange"], counts.by_type["Ignore"]), (1, 1));
    }

    #[test]
    fn a_failed_what_if_prints_its_error_masked() {
        let (out, _) = run(r#"{"status":"Failed","error":{"code":"InvalidTemplate","message":"Value AccountKey=fake-key-AAAA is bad","details":[{"code":"Inner","message":"more"}]},"changes":null}"#, false);
        assert!(out[0].starts_with("error InvalidTemplate: Value <masked len 24 ") && out[0].ends_with("> is bad"), "{}", out.join("\n"));
        assert_eq!(out[1], "  error Inner: more");
    }
}
