mod mask;
mod report;

use mask::Masker;
use serde_json::Value;
use std::io::{PipeReader, PipeWriter, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, ExitCode, Stdio};

const USAGE: &str = "usage: whatif <template> [--env <e1,e2>] [--params <k=v|@file>...] [--param-from '<k>=az:<args>']...
              [--scope sub|group] [--location <loc>] [-g <rg>] [--only-changes] [--raw <new file>]

Runs `az deployment <scope> what-if --no-pretty-print -o json` once for each environment and prints one line
for each resource (Create, Modify, Delete, Deploy, NoChange, Ignore, Unsupported), its type and its name, then
one line for each changed property path with before -> after. Read-only.

  --env <list>        run once for each name; `{env}` in --params, --param-from and -g becomes the name
  --params <k=v>...   template parameters (`@file.json` too); az reads each k=v from an inherited pipe
                      (@/dev/fd/N), so no value is on a command line or on disk; the values never print
  --param-from <k>=az:<args>
                      a parameter whose value is the output of `az <args>` (split at spaces, `{env}` filled);
                      the value, and any string that holds it, never prints
  --scope sub|group   the deployment scope (default sub); sub needs --location, group needs -g
  --only-changes      do not print NoChange and Ignore lines (they are still counted)
  --raw <new file>    write the output unmasked to a new file (mode 0600), never to stdout

The template is compiled with `az bicep build` (local), or read as is when it is a .json file. A value prints as
is only when no word of its path or resource type is a secret name (under a path named only by a short word
such as pass, auth or cert, a bool or one of the words below still prints), and it is a bool, a number or null, or a
string that is a template literal, a name made of parts of template literals and of --params values whose
parameter is not secure and has no secret name, an IP address or CIDR, a hostname, an Azure resource id, or one of
True False Enabled Disabled None Allow Deny Inbound Outbound Tcp Udp Http Https * and the empty string. A string
that holds, in any case, the value of a secure or secret-named parameter (each string of it when it is JSON), or of
a --param-from, never prints, and is masked in messages too. Every other value
prints as <masked len N hmac8>: the first 8 hex digits of its HMAC-SHA256 with a new random key for each run.
Exit: 0 done; 1 an az call or a what-if failed; 2 misuse.";

fn version() -> String {
    format!(
        "whatif {} ({} {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("WHATIF_BUILD_SHA").unwrap_or("unknown-sha"),
        option_env!("WHATIF_BUILD_DATE").unwrap_or("unknown-date"),
    )
}

#[derive(Default)]
struct Opts {
    template: String,
    envs: Vec<String>,
    params: Vec<String>,
    param_from: Vec<(String, String)>,
    group_scope: bool,
    location: Option<String>,
    group: Option<String>,
    only_changes: bool,
    raw: Option<String>,
}

fn parse_args(args: Vec<String>) -> Result<Option<Opts>, String> {
    let mut o = Opts::default();
    let mut it = args.into_iter().peekable();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "--version" => {
                println!("{}", version());
                return Ok(None);
            }
            "--env" => o.envs = value("--env")?.split(',').filter(|e| !e.is_empty()).map(String::from).collect(),
            "--params" => {
                while let Some(p) = it.next_if(|p| !p.starts_with('-') || p.contains('=')) {
                    o.params.push(p);
                }
            }
            "--param-from" => {
                let v = value("--param-from")?;
                match v.split_once("=az:") {
                    Some((k, cmd)) if !k.is_empty() && !cmd.trim().is_empty() => o.param_from.push((k.into(), cmd.into())),
                    _ => return Err("--param-from takes <name>=az:<args>".into()),
                }
            }
            "--scope" => match value("--scope")?.as_str() {
                "sub" => o.group_scope = false,
                "group" => o.group_scope = true,
                s => return Err(format!("--scope is sub or group, not {s}")),
            },
            "--location" => o.location = Some(value("--location")?),
            "-g" => o.group = Some(value("-g")?),
            "--only-changes" => o.only_changes = true,
            "--raw" => o.raw = Some(value("--raw")?),
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            _ if o.template.is_empty() => o.template = a,
            _ => return Err(format!("one template only, not also {a}")),
        }
    }
    if o.template.is_empty() {
        return Err("no template".into());
    }
    if o.group_scope && o.group.is_none() {
        return Err("--scope group needs -g <rg>".into());
    }
    if !o.group_scope && o.location.is_none() {
        return Err("--scope sub needs --location <loc>".into());
    }
    let uses_env = o.params.iter().chain(o.param_from.iter().map(|(_, c)| c)).chain(&o.group).any(|s| s.contains("{env}"));
    if uses_env && o.envs.is_empty() {
        return Err("{env} is used but no --env is given".into());
    }
    Ok(Some(o))
}

/// az's error lines and Bicep's (` : Error BCP…`, after the first only that one has `ERROR:`), masked. Warnings and
/// the "new Bicep release" notice are dropped.
fn az_errors(m: &mut Masker, stderr: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter(|l| l.contains("ERROR") || l.contains(" : Error "))
        .map(|l| format!("az: {}", m.text(l)))
        .collect()
}

/// The compiled ARM template: the file itself when it is `.json`, else `az bicep build --stdout` (local, no Azure call).
fn compile(template: &str, m: &mut Masker, lines: &mut Vec<String>) -> Option<Value> {
    let text = if template.ends_with(".json") {
        std::fs::read(template).map_err(|e| e.to_string())
    } else {
        match Command::new("az").args(["bicep", "build", "--file", template, "--stdout"]).output() {
            Ok(out) if out.status.success() => Ok(out.stdout),
            Ok(out) => Err(["az bicep build failed".to_string()].into_iter().chain(az_errors(m, &out.stderr)).collect::<Vec<_>>().join("\n")),
            Err(e) => Err(format!("cannot run az: {e}")),
        }
    };
    match text.and_then(|t| serde_json::from_slice(&t).map_err(|e| format!("not an ARM template: {e}"))) {
        Ok(t) => Some(t),
        Err(e) => {
            lines.push(format!("whatif: {template}: {e}"));
            None
        }
    }
}

unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

/// The az arguments for the parameters. Each `k=v` goes through its own pipe that az inherits, as `@/dev/fd/N`: az
/// reads the file in place of the argument, so no value is on a command line for `ps` to show, and none is on disk
/// for a killed run to leave. A `@file` or `k=@file` argument already names a file and passes as is.
type Pipes = (Vec<String>, Vec<PipeReader>, Vec<(PipeWriter, String)>);
fn param_pipes(params: &[String]) -> std::io::Result<Pipes> {
    let (mut args, mut readers, mut writers) = (Vec::new(), Vec::new(), Vec::new());
    for p in params {
        if p.starts_with('@') || p.split_once('=').is_some_and(|(_, v)| v.starts_with('@')) {
            args.push(p.clone());
        } else {
            let (r, w) = std::io::pipe()?;
            // F_SETFD (2 on macOS and Linux) to 0: clear close-on-exec, so that az inherits the read end.
            if unsafe { fcntl(r.as_raw_fd(), 2, 0) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            args.push(format!("@/dev/fd/{}", r.as_raw_fd()));
            readers.push(r);
            writers.push((w, p.clone()));
        }
    }
    Ok((args, readers, writers))
}

/// One environment: fill the parameters, run what-if, add its lines to `lines`. Returns false when anything failed.
fn run(o: &Opts, template: &Value, env: Option<&str>, m: &mut Masker, lines: &mut Vec<String>) -> bool {
    let fill = |s: &str| env.map_or(s.to_string(), |e| s.replace("{env}", e));
    lines.push(format!("== {}{}", o.template, env.map_or(String::new(), |e| format!(" ({e})"))));
    let mut params: Vec<String> = o.params.iter().map(|p| fill(p)).collect();
    for (k, v) in params.iter().filter_map(|p| p.split_once('=')).filter(|(_, v)| !v.starts_with('@')) {
        m.param(template, k, v);
    }
    for (name, cmd) in &o.param_from {
        let out = match Command::new("az").args(fill(cmd).split_whitespace()).output() {
            Ok(out) => out,
            Err(e) => {
                lines.push(format!("whatif: cannot run az: {e}"));
                return false;
            }
        };
        let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || value.is_empty() {
            lines.push(format!("--param-from {name}: az printed no value"));
            lines.extend(az_errors(m, &out.stderr));
            return false;
        }
        m.forbid(&value);
        params.push(format!("{name}={value}"));
    }
    let (args, readers, writers) = match param_pipes(&params) {
        Ok(p) => p,
        Err(e) => {
            lines.push(format!("whatif: cannot make the parameter pipes: {e}"));
            return false;
        }
    };
    let mut cmd = Command::new("az");
    cmd.args(["deployment", if o.group_scope { "group" } else { "sub" }, "what-if", "--template-file", &o.template]);
    match (&o.group, &o.location) {
        (Some(g), _) if o.group_scope => cmd.args(["-g", &fill(g)]),
        (_, Some(l)) => cmd.args(["--location", l]),
        _ => &mut cmd,
    };
    if !args.is_empty() {
        cmd.arg("--parameters").args(&args);
    }
    cmd.args(["--result-format", "FullResourcePayloads", "--no-pretty-print", "-o", "json"]);
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
    drop(readers);
    // One writer for each pipe, so that az may read them in any order. A write fails only when az has quit without
    // reading, which its exit shows.
    let feeds: Vec<_> = writers.into_iter().map(|(mut w, v)| std::thread::spawn(move || w.write_all(v.as_bytes()))).collect();
    let out = child.and_then(|c| c.wait_with_output());
    feeds.into_iter().for_each(|f| drop(f.join()));
    let out = match out {
        Ok(out) => out,
        Err(e) => {
            lines.push(format!("whatif: cannot run az: {e}"));
            return false;
        }
    };
    let errors = az_errors(m, &out.stderr);
    let failed = !errors.is_empty();
    lines.extend(errors);
    let d: Value = match serde_json::from_slice(&out.stdout) {
        Ok(d) if out.status.success() => d,
        _ => {
            lines.push(format!("whatif: az exited {} with no what-if result", out.status.code().unwrap_or(-1)));
            return false;
        }
    };
    let masked_before = m.masked;
    let counts = report::render(m, &d, o.only_changes, lines);
    let types: Vec<String> = counts.by_type.iter().map(|(k, n)| format!("{k} {n}")).collect();
    lines.push(format!(
        "{}: {}; {} dropped by omission; {} noise; {} values masked",
        env.unwrap_or(&o.template),
        if types.is_empty() { "no changes listed".to_string() } else { types.join(", ") },
        counts.dropped,
        counts.noise,
        m.masked - masked_before,
    ));
    d["status"].as_str() != Some("Failed") && !failed
}

fn main() -> ExitCode {
    // `whatif … | head`: the first print after head quits panics. Say nothing for that one panic; it still
    // unwinds, so every cleanup runs (restoring SIGPIPE's default would end the process before them).
    let h = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| if !i.to_string().contains("failed printing to stdout") { h(i) }));
    let o = match parse_args(std::env::args().skip(1).collect()) {
        Ok(Some(o)) => o,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("whatif: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // Unmasked values go only to a new file that the person named, never to stdout: an agent's shell keeps its
    // stdout in a regular file and shows it to the model, so "stdout is a file" protects nothing.
    let mut raw_file = match &o.raw {
        None => None,
        Some(path) => match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("whatif: --raw {path}: {e} (it writes only to a new file)");
                return ExitCode::from(2);
            }
        },
    };
    let mut m = match Masker::new(o.raw.is_some()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("whatif: cannot read /dev/urandom for the mask key: {e}");
            return ExitCode::from(1);
        }
    };
    let mut lines = Vec::new();
    let template = compile(&o.template, &mut m, &mut lines);
    if let Some(t) = &template {
        m.learn_template(t, "");
    }
    let envs: Vec<Option<&str>> = if o.envs.is_empty() { vec![None] } else { o.envs.iter().map(|e| Some(e.as_str())).collect() };
    let mut ok = template.is_some();
    for env in envs {
        if let Some(t) = &template {
            ok &= run(&o, t, env, &mut m, &mut lines);
        }
        lines.push(String::new());
        match raw_file.as_mut() {
            Some(f) => {
                if let Err(e) = f.write_all(lines.join("\n").as_bytes()) {
                    eprintln!("whatif: --raw: {e}");
                    return ExitCode::from(1);
                }
            }
            None => print!("{}", lines.join("\n")),
        }
        lines.clear();
        if template.is_none() {
            break;
        }
    }
    if let Some(path) = &o.raw {
        println!("whatif: wrote the unmasked output to {path}");
    }
    println!(
        "Note: what-if can list a change that a deploy does not make (Microsoft's what-if documentation). A DROPPED-BY-OMISSION property can be one whose Azure default equals its live value; a deploy then does not change it. Read each Modify line."
    );
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_stop_at_an_option_without_an_equals_sign() {
        let args = ["t.bicep", "--scope", "group", "--params", "a=1", "b=-2", "-g", "rg-ex"].map(String::from).to_vec();
        let o = parse_args(args).unwrap().unwrap();
        assert_eq!((o.params, o.group), (vec!["a=1".to_string(), "b=-2".to_string()], Some("rg-ex".to_string())));
    }
}
