//! Runs the binary against a fake `az` on PATH that serves fixtures and logs each call.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static N: AtomicUsize = AtomicUsize::new(0);

/// A scratch dir in cargo's target tmp dir, holding a fake `az`. It logs each call and the content of each `@file`
/// argument, answers `bicep build` with `template` (or fails when the file `bicepfail` exists), answers the
/// workspace lookup with a fake id and the Key Vault lookup with a fake secret, fails the what-if when the file
/// `fail` exists, and otherwise serves `whatif` with a Bicep notice on stderr. When the file `reverse` exists, it
/// reads the `@file` arguments last to first and logs only their sizes. Each test removes its dir when it passes.
fn fake_az_with(template: &str, whatif: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("whatif-e2e-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("whatif.json"), whatif).unwrap();
    std::fs::write(dir.join("template.json"), template).unwrap();
    let d = dir.display();
    let script = format!(
        r#"#!/bin/sh
echo "$*" >> "{d}/calls.log"
if [ -f "{d}/reverse" ]; then
  order=""; for a in "$@"; do order="$a $order"; done
  for a in $order; do case "$a" in @*) cat "${{a#@}}" | wc -c | tr -d ' ' >> "{d}/sizes.log" ;; esac; done
else
  for a in "$@"; do case "$a" in @*) cat "${{a#@}}" >> "{d}/params.log"; echo >> "{d}/params.log" ;; esac; done
fi
case "$1 $2" in
  "bicep build")
    if [ -f "{d}/bicepfail" ]; then
      echo "ERROR: {d}/main.bicep(4,13) : Error BCP019: Expected 'FakeLiteral1' here." >&2
      echo "{d}/main.bicep(10,36) : Error BCP057: The name \"FakeName2\" does not exist." >&2
      exit 1
    fi
    cat "{d}/template.json" ;;
  "monitor log-analytics") echo "/subscriptions/0/resourceGroups/rg-$6/providers/x/fake-workspace-id" ;;
  "keyvault secret") echo "FakeLawShared+AAAA/BBBB==" ;;
  "deployment sub")
    echo "WARNING: A new Bicep release is available: v9.9.9." >&2
    if [ -f "{d}/fail" ]; then echo "ERROR: InvalidTemplate: parameter value AccountKey=fake-key-CCCC is not valid" >&2; exit 1; fi
    cat "{d}/whatif.json" ;;
  *) echo "ERROR: unexpected az $*" >&2; exit 1 ;;
esac
"#
    );
    std::fs::write(dir.join("az"), script).unwrap();
    Command::new("chmod").arg("+x").arg(dir.join("az")).status().unwrap();
    dir
}

fn fake_az() -> PathBuf {
    fake_az_with(include_str!("fixtures/template.json"), include_str!("fixtures/app-settings.json"))
}

fn whatif(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_whatif"));
    c.args(args).env("PATH", format!("{}:{}", dir.display(), std::env::var("PATH").unwrap())).current_dir(dir);
    c
}

const ARGS: [&str; 11] = [
    "main.bicep",
    "--env",
    "qa,prod",
    "--location",
    "westeurope",
    "--params",
    "environmentType={env}",
    "prefix=ex",
    "adminPassword=FakeAdmin123",
    "--param-from",
    "workspaceId=az:monitor log-analytics workspace show -g {env} --query id",
];

fn read(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap()
}

#[test]
fn each_environment_runs_with_its_parameters_and_prints_no_secret() {
    let dir = fake_az();
    let out: Output = whatif(&dir, &ARGS).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    let (calls, params) = (read(&dir, "calls.log"), read(&dir, "params.log"));
    assert_eq!(calls.matches("bicep build --file main.bicep --stdout").count(), 1, "{calls}");
    for env in ["qa", "prod"] {
        assert!(text.contains(&format!("== main.bicep ({env})")), "{text}");
        assert!(text.contains(&format!("{env}: Modify 1; 0 dropped by omission; 0 noise; 6 values masked")), "{text}");
        let call = "deployment sub what-if --template-file main.bicep --location westeurope --parameters @/dev/fd/";
        assert!(calls.contains(call), "{calls}");
        let wanted = format!(
            "environmentType={env}\nprefix=ex\nadminPassword=FakeAdmin123\nworkspaceId=/subscriptions/0/resourceGroups/rg-{env}/providers/x/fake-workspace-id\n"
        );
        assert!(params.contains(&wanted), "{params}");
    }
    assert!(!calls.contains("FakeAdmin123") && !calls.contains("prefix=ex"), "a value on az's command line: {calls}");
    assert!(text.contains("appSettings[3].value: <masked len 12 "), "a secure parameter's value is masked: {text}");
    assert!(text.contains("> -> \"ex-func-qa\""), "a name of a template literal and parameter values prints: {text}");
    assert!(text.contains("appSettings[4].value: \"Enabled\" -> <masked len 67 "), "a --param-from value is masked even as a resource id: {text}");
    for bad in ["fake-key", "short-secre", "fake-workspace-id", "Bicep release", "FakeAdmin123"] {
        assert!(!text.contains(bad), "{bad} reached the output:\n{text}");
    }
    assert!(text.ends_with("Read each Modify line.\n"), "{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn no_value_of_a_secret_named_or_secure_parameter_or_a_param_from_prints() {
    let dir = fake_az_with(include_str!("fixtures/attack-template.json"), include_str!("fixtures/attack-whatif.json"));
    let args = [
        "main.bicep",
        "--location",
        "westeurope",
        "--params",
        "envName=qa",
        "dbPass=FakeDbPass9",
        "gwCertData=FakeCertBlobAAAA",
        "adminPassword=FakeAdmin-Secure-7",
        "--param-from",
        "lawShared=az:keyvault secret show --query value",
    ];
    let out = whatif(&dir, &args).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    for bad in ["FakeDbPass9", "FakeLawShared", "FakeDefault77", "FakeAdmin-Secure-7", "FakeCertBlobAAAA", "FakePfxBlobAAAA"] {
        assert!(!text.contains(bad), "{bad} reached the output:\n{text}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_json_template_is_read_as_is_without_bicep_build() {
    let dir = fake_az();
    let out = whatif(&dir, &[&["template.json"], &ARGS[1..]].concat()).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(!read(&dir, "calls.log").contains("bicep build"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_bicep_build_exits_1_with_its_errors_masked_and_runs_no_what_if() {
    let dir = fake_az();
    std::fs::write(dir.join("bicepfail"), "").unwrap();
    let out = whatif(&dir, &ARGS).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.starts_with("whatif: main.bicep: az bicep build failed\naz: ERROR: "), "{text}");
    assert!(text.contains(": Error BCP057: The name \"<masked len 9 "), "{text}");
    assert!(!text.contains("FakeLiteral1") && !text.contains("FakeName2"), "{text}");
    assert!(!read(&dir, "calls.log").contains("deployment"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_what_if_exits_1_with_its_error_masked() {
    let dir = fake_az();
    std::fs::write(dir.join("fail"), "").unwrap();
    let out = whatif(&dir, &ARGS).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("az: ERROR: InvalidTemplate: parameter value <masked len 24 "), "{text}");
    assert!(!text.contains("fake-key"), "{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn az_may_read_two_parameter_pipes_of_over_64_kb_in_reverse_order() {
    let dir = fake_az();
    std::fs::write(dir.join("reverse"), "").unwrap();
    let (a, b) = (format!("prefix={}", "x".repeat(70_000)), format!("environmentType={}", "y".repeat(70_000)));
    let args = ["main.bicep", "--location", "westeurope", "--params", &a, &b];
    let mut child = whatif(&dir, &args).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(60) {
            child.kill().unwrap();
            panic!("whatif hung: az read the pipes in reverse order");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success());
    assert_eq!(read(&dir, "sizes.log"), format!("{}\n{}\n", b.len(), a.len()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn raw_writes_only_to_a_new_file_never_to_stdout() {
    let dir = fake_az();
    let out = whatif(&dir, &[&ARGS[..], &["--raw", "raw.txt"]].concat()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("wrote the unmasked output to raw.txt") && !text.contains("short-secret"), "{text}");
    assert!(read(&dir, "raw.txt").contains("short-secret"));
    let again = whatif(&dir, &[&ARGS[..], &["--raw", "raw.txt"]].concat()).output().unwrap();
    assert_eq!(again.status.code(), Some(2), "an existing file is never overwritten");
    std::fs::remove_dir_all(&dir).unwrap();
}
