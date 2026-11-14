# whatif
<!-- tool: scope=any | when=before you deploy a Bicep or ARM template to Azure, or when you must read what a deploy would change in each environment: one line per resource and one line per changed property, secret values masked, properties that a deploy drops flagged | run=whatif main.bicep --env qa,prod --location <loc> --params 'environmentType={env}'; whatif main.bicep --scope group -g 'rg-{env}' --env qa --only-changes; whatif main.bicep --env qa --location <loc> --param-from 'workspaceId=az:monitor log-analytics workspace show -g rg-{env} -n law-{env} --query id -o tsv' -->

Show what an Azure deploy would change. The tool runs `az deployment <scope> what-if` once for each environment.
It prints one line for each resource, and one line for each changed property with its value before and after. It
masks each value that it cannot show to be safe. It flags each property that what-if lists as removed because the
template does not declare it. The tool is read-only: it runs only `az bicep build` (local), `what-if`, and the az
commands that you give to `--param-from`.

## Usage

```
whatif <template> [--env <e1,e2>] [--params <k=v|@file>...] [--param-from '<k>=az:<args>']...
       [--scope sub|group] [--location <loc>] [-g <rg>] [--only-changes] [--raw <new file>]
```

- `--env <list>`: run the what-if one time for each name. In `--params`, `--param-from` and `-g`, the tool
  replaces `{env}` with the name.
- `--params <k=v>...`: the template parameters. `@file.json` also works. The tool writes each `k=v` into its own
  pipe, which az inherits, and gives az `@/dev/fd/<n>`. az reads the pipe in place of the argument. Thus no value
  is on a command line, where `ps` shows it, and no value is on disk, where a killed run can leave it. The tool does
  not print a parameter value. The list stops at the next argument that starts with `-` and has no `=`.
- `--param-from <k>=az:<args>`: a parameter whose value is the output of `az <args>`. The tool splits the args
  at spaces and replaces `{env}`. Use it for a value that you must find each time, for example a Log Analytics
  workspace id. The value never prints, and a string that holds it never prints.
- `--scope sub|group`: the deployment scope. The default is `sub`. `sub` needs `--location`. `group` needs `-g`.
- `--only-changes`: do not print the `NoChange` and `Ignore` lines. The summary line still counts them.
- `--raw <new file>`: write the output without masks to a new file (mode 0600). The tool does not write to a file
  that exists. It never writes values without masks to stdout. The shell of an AI agent keeps stdout in a regular
  file and shows it to the model. Thus a "stdout is a file" check does not keep secrets out of a transcript.

Exit codes: 0 when each what-if is complete. 1 when an az call or a what-if fails (the tool continues with the
next environment). 2 for a usage error.

### Output

```
== <template> (<env>)
diagnostic <level> <code>: <message>
    target <type>  <name>  (group <rg>)
<change>    <type>  <name>  (group <rg>)
    <change> <property path>: <before> -> <after>[  DROPPED-BY-OMISSION]
    noise   <change> <property path>: <why>
<env>: <count of each change type>; <n> dropped by omission; <n> noise; <n> values masked
Note: what-if can list a change that a deploy does not make (Microsoft's what-if documentation). A DROPPED-BY-OMISSION property can be one whose Azure default equals its live value; a deploy then does not change it. Read each Modify line.
```

- The diagnostics come first. A nested deployment that what-if cannot evaluate
  (`NestedDeploymentShortCircuited`) makes no resource lines. Only its diagnostic tells you why the list is empty.
- The change types are the types of what-if: `Create`, `Modify`, `Delete`, `Deploy`, `NoChange`, `Ignore`,
  `Unsupported`, and for a property `Create`, `Modify`, `Delete`, `Array`, `NoEffect`. Any other value prints as
  `?`. The tool always asks for full payloads (`--result-format FullResourcePayloads`).
- A property line has the full path of the property. An array item is `[n]`. The tool does not show a `NoEffect`
  property (read-only, no change).
- `DROPPED-BY-OMISSION`: what-if lists the property as deleted, and the property is not an array item. The live
  resource has the property, and the template does not declare it. The deploy can reset it. But the property can
  also be one whose Azure default equals the live value (for example API Management `publicNetworkAccess`, default
  `Enabled`). Then a deploy does not change it.
- `noise`: a line that what-if always shows, also when nothing changes. The tool shows one line for it and does not
  show its children. The noise is the read-only properties `applicationGatewayIPConfigurations` and
  `privateLinkIpConfigurations`, and an array whose items are the same in a new order (for example `zones`).
- The tool shows each az error line (`ERROR: …`) and each Bicep error line (`… : Error BCP…`) with the same masks
  as a diagnostic. It does not show warnings or the "new Bicep release" message. When `az bicep build` fails, the
  tool shows its errors, runs no what-if and exits 1.

### Masks

The tool does not search its output for secrets. A value prints only when the tool can show where it came from.
Before the first what-if, the tool compiles the template with `az bicep build --file <template> --stdout` (a local
step, no Azure call). It reads a `.json` template as it is.

1. A secret path masks every value under it, also a value that rule 4 lets print. A path is secret when one of
   its words is a secret name. A segment of the resource type after the namespace (`vaults`, `secrets`) counts as
   a path word. The tool removes the separators of a name (`CONNECTION_STRING`) before the check. A secret name
   contains one of these: `key`, `secret`, `password`, `connectionstring`, `azurewebjobsstorage`, `token`,
   `credential`, `secure`, `passwd`, `passphrase`, `pfx`, `signature`. Thus `accountKey`, `apiKey` and
   `privateKey` contain `key`. A name is also secret when one of its tokens ends in a short word. The
   short words are `pass`, `pwd`, `auth`, `cert`, `pat`, `otp`, `pin`, `salt`, `jwt`, `bearer`, `cookie`, `creds`
   and `webhook`. The token `bypass` is not secret. The tokens of a name are its words. The tool also splits a word
   before an upper-case letter after a lower-case letter, and before the first word after an acronym. Thus `DB_PASS`,
   `DBPass`, `adminpass`, `authHeader` and `basicauth` are secret names. But `bypass`, `sslCertificates`,
   `authorizationRules` and `privateEndpoints` are not. A name that has a word that starts with `sas` or `sig` is
   also a secret name. The case is not important. When only a short word makes a path secret, a bool under it
   still prints, and so does a word of rule 4 (d). Thus `disableLocalAuth: true` and `clientCertMode: "Enabled"`
   show. The tool masks every other value under such a path.
2. An object with a `value` makes that value secret in two cases. Its `name` is a secret name (an app setting), or
   it has `secret: true` (an API Management named value). The tool reads that object on both sides of the change.
   An array that shifts can put a secret setting on one side only.
3. A string never prints when it holds a forbidden value, in any case. A forbidden value is a value that you gave
   with `--params k=v` for a parameter that is not plain, or any `--param-from` value. When such a `--params` value
   is JSON (a `secureObject`), each string in it is also a forbidden value. A plain parameter has a type that the
   template gives and that is not secure, and its name is not a secret name.
4. A bool, a number or null prints. A string prints only when one of these is true:
   - (a) It is a literal of the compiled template. A literal is a string that is not an expression (`[…]`), or a
     single-quoted literal in an expression (`[if(…, 'Enabled', 'Disabled')]`). The default value of a parameter
     that is not plain is never a literal.
   - (b) Each of its parts, split at `-`, `_`, `.` and `/`, is a part of a literal or of a parameter value. A
     parameter value counts when you gave it with `--params k=v` for a plain parameter. A `--param-from` value
     never counts. Thus a computed name such as `<prefix>-<abbr>-<purpose>-<env>` prints. The case of a part is
     not important, because names often go through `toLower`. The tool does not read the values in a
     `--params @file.json`.
   - (c) It is an IP address or a CIDR, or a hostname (two or more labels, the last label letters only). Or it is an
     Azure resource id (`/subscriptions/…` or `/providers/…`, with name characters only). A long run is 25 or more
     letters and digits, with 3 or more digits in it. A hostname or a resource id with a long run does not pass.
   - (d) It is one of the words below, in any case. Each word tells nothing secret. What-if shows them as live
     values that no template writes.
     - `True` and `False`: string bools, for example in API Management `customProperties`.
     - `Enabled`, `Disabled` and `None`: states.
     - `Allow`, `Deny`, `Inbound`, `Outbound`, `Tcp`, `Udp` and `*`: network rule values.
     - `Http` and `Https`: protocols.
     - The empty string.

All other values print as `<masked len N hmac8>`: the length of the value, and the first 8 hex digits of its
HMAC-SHA256. A random token, for example a 32-character base64url key, is not a literal, so it never prints. The
key of the HMAC is 64 random bytes from `/dev/urandom`, new for each run. In one run, the same value gives the same
mask, also across the environments. Thus you can see if a masked value changes. A mask of one run does not match
a mask of a different run, and nobody can test a guess against a mask.

The tool walks objects and arrays and applies the same checks to each leaf. A key, a path part or a resource name
prints as it is when it has only name characters and no long run. In a diagnostic or an error message, the tool
first masks each forbidden value, in any case, also when it holds spaces. Then it masks each quoted span (`'…'` or
`"…"`) as a whole. Then it prints the message word by word. It masks a word that holds `=`, `+`, `%`, `&` or `$`,
or a run of 25 letters and digits.

## Evidence

- A client IaC repo (sessions 7dc9f74f, a7608b96, 2026-11-10 and 2026-11-12): eleven hand-written
  `az deployment sub what-if … | python3` parsers over four templates, for qa and prod. One full what-if, written to
  a scratch file, held two storage account keys in plain text. The TLS settings that the live API gateway had, and
  the template did not declare, showed only as a Modify with removed properties. A person found them in the text.
- One run printed nothing. The whole nested deployment was `NestedDeploymentShortCircuited`, and the parser read
  only `changes`.
- Read-only properties and reordered `zones` arrays showed as changes on each run.
- On each run, a person found the Log Analytics workspace id parameter by hand.

## Verified 2026-11-14

These runs passed against a real Azure subscription, at subscription scope, from a build of commit `ff63737`:

1. An API gateway template, a Front Door template, an API module template and a root template, each in two
   environments. Each run exited 0.
2. The gateway template before and after a commit that declared the gateway's live TLS settings. Before, the
   gateway's `customProperties` showed as `DROPPED-BY-OMISSION`. After, that line was gone.
3. A leak count. A script compared a hash of each storage account key of the subscription with the output of each
   run. It found 0 keys. Its positive control found each key in text that held it.

The runs passed again from a build of commit `a6e54f1`, which sends the parameters through pipes. All five runs
exited 0, each count was the same as before, and the hashed key count found 0 keys, with a positive control.
The fixtures of the tests show the changes after that commit.

## Install

```
./install.sh          # installs a copy in ~/.local/bin
whatif --version      # whatif <version> (<sha> <date>)
```

## Tests

`cargo test --locked`. The fixtures are what-if JSON and a compiled template, written by hand in the structure of
the real output. Their values are fake (`fake-key-AAAA…`, `Fake…123`, zeros, `rg-ex-qa`).

`tests/fixtures/leaks.json` holds the secret holders that a security review saw in plain text:

- a Key Vault secret, an API Management named value and a Container Instances `secureValue`
- app settings as a dictionary, and a secret setting that an array shift moves
- a quoted value in a diagnostic.

The unit tests cover each print rule, each secret name rule, the noise list, `DROPPED-BY-OMISSION`, the
diagnostics and the errors. They check the HMAC against RFC 4231 test case 2. They make random base64url and
alphanumeric tokens of 16 to 43 characters, and none prints. The end-to-end tests put a fake `az` on `PATH`. This
fake records each call and the content of each `@file`. The tests make sure of these items:

- `az bicep build` runs once, and a `.json` template is read without it. A failed build exits 1 and runs no what-if.
- `{env}` and `--param-from` give the correct parameters, through `@/dev/fd/<n>` pipes. No value is on az's
  command line.
- A name made of template literals and parameter values prints. The value of a secure parameter does not.
- No value of a secure or secret-named parameter, no secret-named default and no `--param-from` value prints
  (`tests/fixtures/attack-*.json`).
- az can read two parameter pipes of more than 64 KB in reverse order, and the run does not stop.
- The tests run in cargo's `target/tmp` folder, and each test removes its folder when it passes.
- No fake key gets to the output.
- A failed what-if exits 1.
- `--raw` writes only to a new file, and never to stdout.

## Extending

Cases that are paid for:

- Diagnostics before the changes, with the target resource. A what-if `error` with its details.
- The two read-only noise properties, and reordered arrays. Add a property to `READ_ONLY` in `src/report.rs`
  when a what-if always lists it.
- `DROPPED-BY-OMISSION` on a deleted property that is not an array item.
- The `{name, value}` and `{secret: true, value}` rules, and the secret words of a resource type.
- `--param-from` with `{env}`.

Not built:

- `--json`. Add it from the masked lines when a script needs it.
- A per-repo parameters file. `--params @file.json` gives a file to az.
- The payload of a `Create` or a `Delete` resource. The tool shows only the property changes of a resource.
- Management-group and tenant scopes.
- Rule (b) for the values in a `--params @file.json`. The tool masks them unless rule (a), (c) or (d) holds.
- GUIDs, URLs and timestamps that are not template literals. The tool masks these values. Compare them by their
  `hmac8` in one run.
