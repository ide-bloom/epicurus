# Decoy catalog

The default catalog is [`decoys/catalog.toml`](../decoys/catalog.toml), embedded into `epicurus.exe` at compile time. Extend or override it by dropping TOML files with the same schema into `%ProgramData%\Epicurus\catalog.d\`. Files are merged in file-name order: an entry with an existing `id` replaces it, and `disabled = true` removes it. The merged catalog is validated on load, and an invalid override stops the service from starting with a clear error in the log.

## Rules every entry must follow

- Every secret is a `{{placeholder}}` filled by a generator at plant time. Never write a token-shaped literal: GitHub push protection rejects it and secret scanners flag the repository. A unit test checks the embedded catalog for well-known provider prefixes.
- Every path starts with `%USERPROFILE%\`, `%APPDATA%\` or `%LOCALAPPDATA%\` and contains no `.`/`..` components or `:`. The variables resolve to the *protected user's* folders (read from the registry), not the service's.

## Schema

```toml
schema_version = 1

[profiles]                 # name -> categories ("*" = all); "default" is required
default = ["*"]
ai = ["ai_agent", "mcp"]

[sets]                     # value lists for pick: generators
projects = ["billing-api-legacy", "payments-service-old"]

[snippets]                 # shared template fragments, inserted with {{@name}}
mcp_servers_json = '''"github": { ... "{{gh_token}}" ... }'''

[groups.chrome]            # fields and conditions shared by several decoys
fields = { profile = "pick:chromium_profiles" }
require_any = ['%LOCALAPPDATA%\Google\Chrome\User Data']   # plant only if one exists
skip_if_any = []                                            # skip if any exists

[[decoy]]
id = "aws-credentials"                 # [a-z0-9-]+, unique
category = "cloud"                     # see categories below
group = "chrome"                       # optional
description = "AWS shared credentials file"
targets = [                            # candidates in order; first = real tool location
  '%USERPROFILE%\.aws\credentials',
  '%USERPROFILE%\.aws\credentials.bak',
]
installed_if = ['%USERPROFILE%\.aws\credentials']   # real tool present -> never use targets[0]
require_any = []                       # plant only if one of these exists
skip_if_any = []                       # skip entirely if one exists (e.g. real wallet)
fresh_dirs = []                        # a target under one of these is rejected if the dir
                                       # already exists and was not created by Epicurus
conflict = "alternate"                 # "alternate" (default) or "skip"
fields = { id1 = "aws_access_key_id", secret1 = "aws_secret_access_key" }
plausibility = { age_days = [60, 500], hidden = false, not_content_indexed = true, pad_to = [800, 1200] }
content = { kind = "text", template = '''[default]
aws_access_key_id = {{id1}}
aws_secret_access_key = {{secret1}}
''' }
```

A path counts as "existing" for `installed_if`, `require_any`, `skip_if_any` and `fresh_dirs` only if it exists **and is not in Epicurus's manifest**, so Epicurus's own decoys never masquerade as a real installation.

### Categories

`ai_agent`, `mcp`, `cloud`, `browser`, `wallet`, `messaging`, `password_manager`.

### Content kinds

| Kind | Fields | Produces |
|---|---|---|
| `text` | `template` | the rendered template |
| `sqlite` | `shape`, `rows` | an SQLite database built in memory. Shapes: `chromium_login_data` (row keys `origin`, `username`; passwords are random `v10` AES-GCM-shaped blobs with no key anywhere), `chromium_cookies` (`host`, `name`, optional `path`), `vscode_state` (`key`, `value` into `ItemTable`) |
| `leveldb` | `entries` (`key`, `value`) | a LevelDB directory (`CURRENT`, `LOCK`, `LOG`, `MANIFEST-000001`, `000003.log`) whose write-ahead log holds a CRC32C-checksummed WriteBatch of the entries; the target is the directory |
| `binary` | `size` `[min, max]`, optional `magic` (hex), optional `payload` (template) | magic header, payload, then random fill to a seeded size |

### Templates

`{{field}}`, `{{field.part}}` (for example `{{key.public}}` from `ssh_ed25519`), `{{field|json}}` (escape for a JSON string), `|b64`, `|upper`, `|lower`, `{{@snippet}}`. An unknown field, part, filter or snippet is a load-time error.

### Plausibility

- `age_days`: created, modified and accessed times are backdated by a seeded amount in this range.
- `hidden`: `FILE_ATTRIBUTE_HIDDEN`.
- `not_content_indexed` (default true): `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, so Windows Search leaves decoys alone.
- `pad_to`: pad text decoys to a seeded size.

All choices (picks, sizes, ages) come from an HMAC-SHA256 stream keyed by the per-install seed and labelled by group, decoy and field, so adding an entry never reshuffles the others.

## Generators

Each produces a value in the provider's public format (prefix, length, alphabet). Values are random and unregistered. Where the format carries a checksum, the checksum is deliberately wrong so the provider rejects the value offline.

| Generator | Format |
|---|---|
| `aws_access_key_id` | `AKIA` + 16 base32 |
| `aws_secret_access_key` | 40 base64 characters |
| `github_pat`, `github_oauth` | `ghp_` / `gho_` + 30 alphanumerics + 6-character CRC32 checksum that never validates |
| `github_fine_grained` | `github_pat_` + 22 + `_` + 59 |
| `anthropic_api_key`, `anthropic_oauth_access`, `anthropic_oauth_refresh` | `sk-ant-api03-` / `sk-ant-oat01-` / `sk-ant-ort01-` + 93 + `AA` |
| `openai_api_key` | `sk-proj-` + 156 characters containing the `T3BlbkFJ` marker |
| `openai_refresh_token` | `rt_` + 86 |
| `google_api_key` | `AIza` + 35 |
| `google_oauth_access`, `google_oauth_refresh`, `google_client_secret` | `ya29.` + 150, `1//0` + 100, `GOCSPX-` + 28 |
| `slack_bot_token`, `slack_user_token` | `xoxb-…`, `xoxp-…` |
| `stripe_secret_key` | `sk_live_` + 99 |
| `notion_token` | `ntn_` + 46 |
| `npm_token` | `npm_` + 36 with a failing checksum |
| `pypi_token` | `pypi-AgEIcHlwaS5vcmc` + 160 |
| `discord_token` | base64(18-digit id) `.` 6 `.` 38 |
| `telegram_bot_token` | 10 digits `:AA` + 33 |
| `azure_refresh_token` | `0.A` + 900 |
| `jwt` | RS256-shaped JWT with plausible claims and a random signature |
| `private_key_pem` | PKCS#8-shaped PEM of random bytes |
| `ssh_ed25519` | an OpenSSH-format ed25519 private key file (structurally valid, random bytes); `.public` gives the matching `.pub` line |
| `docker_auth` | base64(`user:token`) |
| `xprv`, `eth_address` | `xprv` + 107 base58; `0x` + 40 hex |
| `uuid`, `hex:N`, `alnum:N`, `digits:N`, `b64:N` (N random bytes), `b64url:N`, `base58:N`, `password:N` | as named |
| `int:lo:hi`, `pick:set`, `username`, `email`, `hostname`, `epoch_past:lo:hi`, `date_past:lo:hi` | seeded, stable per install |
| `epoch_ms_future` | an expiry 20–320 days ahead |

## Live canaries

Any generator can be replaced by your own canary value in `config.toml`:

```toml
[canaries]
aws_access_key_id = "<access key id from canarytokens.org>"
aws_secret_access_key = "<its secret>"
```

Every decoy that uses that generator then contains the canary. If a stealer's operator ever uses it, the canary service alerts you. Epicurus itself never contacts any canary service. Manifest entries containing canaries are marked, and the dashboard shows them.

## Example override

`%ProgramData%\Epicurus\catalog.d\10-team.toml`:

```toml
schema_version = 1

# Remove the password-export decoy.
[[decoy]]
id = "password-export-csv"
category = "password_manager"
targets = ['%USERPROFILE%\x']
content = { kind = "text", template = "" }
disabled = true

# Add an internal tool's token file.
[[decoy]]
id = "acme-cli-token"
category = "cloud"
targets = ['%APPDATA%\acme-cli\token.json', '%APPDATA%\acme-cli\token.json.bak']
installed_if = ['%APPDATA%\acme-cli\token.json']
fields = { t = "alnum:40" }
content = { kind = "text", template = '{"token":"acme_{{t}}"}' }
```

Run `epicurus plant --dry-run` to see the effect before planting.
