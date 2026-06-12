<h1 align="center">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-white.svg#gh-dark-mode-only" alt="infisical">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-black.svg#gh-light-mode-only" alt="infisical">
</h1>

<p align="center">
  <p align="center"><b>Infisical PKCS#11 Module</b>: Sign code and artifacts using keys managed in Infisical — private keys never leave Infisical.</p>
</p>

<h4 align="center">
  <a href="https://infisical.com/docs/documentation/platform/pki/code-signing/overview">Docs</a> |
  <a href="https://infisical.com/slack">Slack</a> |
  <a href="https://infisical.com/">Infisical Cloud</a> |
  <a href="https://www.infisical.com">Website</a>
</h4>

<h4 align="center">
  <a href="https://github.com/Infisical/infisical/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Infisical is released under the MIT license." />
  </a>
  <a href="https://github.com/Infisical/infisical-pkcs-11/issues">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://infisical.com/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
</h4>

## Introduction

The **Infisical PKCS#11 Module** is a shared library (`.so`, `.dylib`, `.dll`) that implements [PKCS#11 v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html). It acts as a bridge between standard signing tools and the Infisical API — your tool loads the library, and all cryptographic operations are performed by Infisical.

Each **Signer** in your Infisical project appears as a PKCS#11 **slot**, exposing a private key object (for signing) and a certificate object (for verification and chain building).

## Features

- **[Remote Signing](https://infisical.com/docs/documentation/platform/pki/code-signing/overview)**: Private keys never leave Infisical. All signing operations are performed by Infisical.
- **[Universal Tool Compatibility](#tool-integration-guides)**: Works with jarsigner, osslsigncode, signtool, pkcs11-tool, GnuTLS, OpenSSL, and any PKCS#11 consumer.
- **[RSA and ECDSA Support](#supported-mechanisms)**: SHA-256/384/512 with PKCS#1 v1.5, PSS, and ECDSA. Supports P-256, P-384, and P-521 curves.
- **[Approval Workflows](#approval-workflow)**: Require human review before signing, bounded by a signature count and/or a time window per approval.
- **[Audit Logging](https://infisical.com/docs/documentation/platform/audit-logs)**: Every signing operation is recorded with actor, timestamp, and client metadata.
- **[Cross-Platform](#install)**: Pre-built binaries for Linux (x86_64, ARM64), macOS (x86_64, ARM64), and Windows (x86_64).

## Prerequisites

- An Infisical instance with the **Cert Manager** product enabled
- At least one **Signer** created (Cert Manager > Code Signing > Signers)
- The Signer must be backed by an Internal CA, AWS Private CA, or Azure AD CS
- A way to authenticate as a member of the Signer with the Administrator or Operator role (the signer's Members tab): either a **Machine Identity** with Universal Auth, or an Infisical **access token** (a user's or a machine identity's). See [Authentication](#authentication).
- If using approval policies: an approved sign request for the signer before signing

## Quick Start

### 1. Install

Download the binary for your platform from the [releases page](https://github.com/Infisical/infisical-pkcs-11/releases):

| Platform | File |
|----------|------|
| Linux x86_64 | `libinfisical-pkcs11-linux-amd64.so` |
| Linux ARM64 | `libinfisical-pkcs11-linux-arm64.so` |
| macOS x86_64 | `libinfisical-pkcs11-darwin-amd64.dylib` |
| macOS ARM64 | `libinfisical-pkcs11-darwin-arm64.dylib` |
| Windows x86_64 | `libinfisical-pkcs11-windows-amd64.dll` |

Or build from source (requires Go 1.21+ and a C compiler):

```bash
make build
```

### 2. Configure

Create `/etc/infisical/pkcs11.conf` (or set `INFISICAL_CONFIG` to a custom path):

```json
{
  "server_url": "https://app.infisical.com"
}
```

Set credentials via environment variables (recommended):

```bash
export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="your-client-id"
export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="your-client-secret"
```

### 3. Verify

```bash
# List available signers (slots)
pkcs11-tool --module ./libinfisical-pkcs11.so --list-slots

# List objects in a slot
pkcs11-tool --module ./libinfisical-pkcs11.so --list-objects --slot 0
```

### 4. Sign

```bash
pkcs11-tool --module ./libinfisical-pkcs11.so --sign \
  --slot 0 --mechanism SHA256-RSA-PKCS \
  --input-file document.bin --output-file document.sig
```

## Configuration

The module reads a JSON config file and environment variables. Environment variables take precedence over config file values for credentials.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` | Machine Identity client ID (Universal Auth) |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` | Machine Identity client secret (Universal Auth) |
| `INFISICAL_TOKEN` | An Infisical access token (a user or machine identity token). Selects token auth; used instead of Universal Auth credentials |
| `INFISICAL_CONFIG` | Path to config file (default: `/etc/infisical/pkcs11.conf`) |
| `INFISICAL_SERVER_URL` | Override `server_url` from config file |

### Config File

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `server_url` | Yes | — | Infisical server URL |
| `auth.method` | No | `universal-auth` | Authentication method: `universal-auth` or `token` |
| `auth.client_id` | No | (none) | Machine Identity client ID, for `universal-auth` (prefer env var) |
| `auth.client_secret` | No | (none) | Machine Identity client secret, for `universal-auth` (prefer env var) |
| `auth.token` | No | (none) | Infisical access token, for `token` auth (prefer the env var) |
| `tls.ca_cert_path` | No | — | Custom CA certificate for self-hosted instances |
| `tls.skip_verify` | No | `false` | Skip TLS verification (development only) |
| `cache.token_ttl_seconds` | No | `300` | Auth token cache duration |
| `cache.cert_ttl_seconds` | No | `3600` | Certificate data cache duration |
| `cache.signer_ttl_seconds` | No | `300` | Signer list cache duration |
| `approval.signing_duration` | No | — | Auto-request approval with this time window (e.g. `"8h"`, `"30m"`, `"2d"`). Range: 1m–30d |
| `approval.signing_count` | No | — | Auto-request approval for this many signings |
| `log_level` | No | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `log_file` | No | stderr | Path to log file |

<details>
<summary>Full config example</summary>

```json
{
  "server_url": "https://app.infisical.com",
  "auth": {
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  },
  "tls": {
    "ca_cert_path": "/path/to/custom-ca.pem",
    "skip_verify": false
  },
  "cache": {
    "token_ttl_seconds": 300,
    "cert_ttl_seconds": 3600,
    "signer_ttl_seconds": 300
  },
  "approval": {
    "signing_duration": "8h",
    "signing_count": 10
  },
  "log_level": "info",
  "log_file": "/var/log/infisical-pkcs11.log"
}
```

</details>

### Authentication

The module supports two ways to authenticate with Infisical.

**Universal Auth (Machine Identity)** is the default. The module exchanges the client ID/secret for an access token and refreshes it automatically. Provide the credentials three ways (in order of precedence):

1. **Environment variables** (recommended for CI/CD and production):
   ```bash
   export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="your-client-id"
   export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="your-client-secret"
   ```

2. **Config file** (convenient for development):
   ```json
   {
     "auth": {
       "client_id": "your-client-id",
       "client_secret": "your-client-secret"
     }
   }
   ```

3. **PIN at login time** — tools that call `C_Login` can pass credentials as the PIN in the format `clientId:clientSecret`.

When credentials are available, the module auto-authenticates during initialization — no explicit `C_Login` is needed from tools.

**Token auth** uses an Infisical access token directly, either a user's token or a machine identity's. Setting `INFISICAL_TOKEN` selects it:

```bash
export INFISICAL_TOKEN="your-access-token"
```

> **Token auth is temporary.** The module uses the token as-is and does not refresh it. When the token expires, signing fails until you set a new token.

Environment variables take precedence over the config file, and `INFISICAL_TOKEN` takes precedence over Universal Auth credentials.

## Tool Integration Guides

### Java jarsigner

[jarsigner](https://docs.oracle.com/en/java/javase/17/docs/specs/man/jarsigner.html) is the standard tool for signing JAR files, included with the JDK.

**Step 1:** Create a SunPKCS11 provider config (`infisical-pkcs11.cfg`):

```
name = Infisical
library = /path/to/libinfisical-pkcs11.so
```

On Windows, use the DLL path:
```
name = Infisical
library = C:\path\to\libinfisical-pkcs11-windows-amd64.dll
```

**Step 2:** Sign:

```bash
# Java 9+ (recommended)
jarsigner -keystore NONE -storetype PKCS11 \
  -addprovider SunPKCS11 \
  -providerArg infisical-pkcs11.cfg \
  -sigalg SHA256withRSA \
  myapp.jar "your-signer-name"
```

<details>
<summary>Java 8</summary>

```bash
jarsigner -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 \
  -providerArg infisical-pkcs11.cfg \
  -sigalg SHA256withRSA \
  myapp.jar "your-signer-name"
```

</details>

<details>
<summary>Windows (PowerShell)</summary>

```powershell
$env:INFISICAL_CONFIG = "C:\path\to\pkcs11.conf"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "your-client-id"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "your-client-secret"

jarsigner -keystore NONE -storetype PKCS11 `
  -addprovider SunPKCS11 `
  -providerArg infisical-pkcs11.cfg `
  -sigalg SHA256withRSA `
  myapp.jar "your-signer-name"
```

</details>

**Step 3:** Verify:

```bash
jarsigner -verify -verbose myapp.jar
```

> **Note:** The alias (`"your-signer-name"`) must match the **Signer name** in Infisical exactly.

### osslsigncode (Authenticode on Linux/macOS)

[osslsigncode](https://github.com/mtrojnar/osslsigncode) signs Windows executables (`.exe`, `.dll`, `.msi`) from Linux or macOS.

```bash
osslsigncode sign \
  -pkcs11module /path/to/libinfisical-pkcs11.so \
  -pkcs11cert "pkcs11:object=your-signer-name;type=cert" \
  -key "pkcs11:object=your-signer-name;type=private" \
  -h sha256 \
  -in MyApp.exe -out MyApp-signed.exe
```

### signtool (Windows Authenticode)

```powershell
$env:INFISICAL_CONFIG = "C:\path\to\pkcs11.conf"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_ID = "your-client-id"
$env:INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET = "your-client-secret"

signtool sign /fd SHA256 /f cert.cer `
  /csp "Infisical PKCS#11" `
  /kc "your-signer-name" `
  MyApp.exe
```

> **Note:** Windows integration typically requires registering the PKCS#11 module as a CSP/KSP or using a wrapper like `pkcs11-csp`.

### pkcs11-tool (OpenSC)

[pkcs11-tool](https://github.com/OpenSC/OpenSC/wiki/Using-pkcs11-tool-and-OpenSSL) is useful for testing and exploring the module.

```bash
# List available slots (one per signer)
pkcs11-tool --module ./libinfisical-pkcs11.so --list-slots

# List objects in a slot
pkcs11-tool --module ./libinfisical-pkcs11.so --list-objects --slot 0

# List supported mechanisms
pkcs11-tool --module ./libinfisical-pkcs11.so --list-mechanisms --slot 0

# Sign a file
pkcs11-tool --module ./libinfisical-pkcs11.so --sign \
  --slot 0 --mechanism SHA256-RSA-PKCS \
  --input-file document.bin --output-file document.sig
```

### GnuPG (via gnupg-pkcs11-scd)

```bash
# Install: macOS: brew install gnupg-pkcs11-scd | Ubuntu: apt install gnupg-pkcs11-scd
```

Add to `~/.gnupg/gpg-agent.conf`:

```
scdaemon-program /usr/bin/gnupg-pkcs11-scd
```

Add to `~/.gnupg/gnupg-pkcs11-scd.conf`:

```
providers infisical
provider-infisical-library /path/to/libinfisical-pkcs11.so
```

Restart and verify:

```bash
gpgconf --kill gpg-agent
gpg --card-status
```

## Supported Mechanisms

### RSA

| Mechanism | PKCS#11 Constant | Key Sizes |
|-----------|-----------------|-----------|
| SHA256-RSA-PKCS | `CKM_SHA256_RSA_PKCS` | 2048, 3072, 4096 |
| SHA384-RSA-PKCS | `CKM_SHA384_RSA_PKCS` | 2048, 3072, 4096 |
| SHA512-RSA-PKCS | `CKM_SHA512_RSA_PKCS` | 2048, 3072, 4096 |
| SHA256-RSA-PKCS-PSS | `CKM_SHA256_RSA_PKCS_PSS` | 2048, 3072, 4096 |
| SHA384-RSA-PKCS-PSS | `CKM_SHA384_RSA_PKCS_PSS` | 2048, 3072, 4096 |
| SHA512-RSA-PKCS-PSS | `CKM_SHA512_RSA_PKCS_PSS` | 2048, 3072, 4096 |
| RSA-PKCS (raw DigestInfo) | `CKM_RSA_PKCS` | 2048, 3072, 4096 |

### ECDSA

| Mechanism | PKCS#11 Constant | Curves |
|-----------|-----------------|--------|
| ECDSA-SHA256 | `CKM_ECDSA_SHA256` | P-256, P-384, P-521 |
| ECDSA-SHA384 | `CKM_ECDSA_SHA384` | P-256, P-384, P-521 |
| ECDSA-SHA512 | `CKM_ECDSA_SHA512` | P-256, P-384, P-521 |
| ECDSA (raw pre-hashed) | `CKM_ECDSA` | P-256, P-384, P-521 |

## Approval Workflow

If a signer has an approval policy, you need an approved sign request before signing. Without it, sign requests will return `CKR_GENERAL_ERROR` (HTTP 403).

### Automatic Approval Requests

When `approval.signing_duration` and/or `approval.signing_count` are configured, the module **automatically creates an approval request** when signing is denied because no approved sign request exists. The sign operation still fails (an approver must approve the request first), but the request is created for you — no manual API call needed.

```json
{
  "approval": {
    "signing_duration": "8h",
    "signing_count": 10
  }
}
```

Once an approver approves the request (via the Infisical UI at Cert Manager > Code Signing > Signers > `<signer>` > Approvals tab), retrying the sign operation will succeed.

<details>
<summary>Requesting approval via API</summary>

```bash
# Authenticate
TOKEN=$(curl -s https://app.infisical.com/api/v1/auth/universal-auth/login \
  -H "Content-Type: application/json" \
  -d '{"clientId":"...","clientSecret":"..."}' | jq -r '.accessToken')

# Request access for an 8-hour window, capped at 10 signatures
# macOS / BSD:
START=$(date -u -v+1M +"%Y-%m-%dT%H:%M:%SZ")
END=$(date -u -v+8H +"%Y-%m-%dT%H:%M:%SZ")
# Linux / GNU coreutils (uncomment if your `date` is GNU):
# START=$(date -u -d '+1 minute' +"%Y-%m-%dT%H:%M:%SZ")
# END=$(date -u -d '+8 hours' +"%Y-%m-%dT%H:%M:%SZ")

curl -s https://app.infisical.com/api/v1/cert-manager/signers/your-signer-id/requests \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"justification\": \"CI/CD release build\",
    \"requestedSignings\": 10,
    \"requestedWindowStart\": \"$START\",
    \"requestedWindowEnd\": \"$END\"
  }"
```

An approver must approve the request via the Infisical UI (Cert Manager > Code Signing > Signers > `<signer>` > Approvals tab). Once approved, signing works for the granted window.

</details>

### Request Shape

Each approval request can be bounded by a signature count, a time window, or both. The Signer's policy sets the ceiling for each (`Signatures per approval`, `Signing window`) — a request that exceeds the policy is rejected with a 400. `justification` is the only required field; omitting a bound falls back to the policy ceiling.

| Field | Description |
|-------|-------------|
| `justification` | **Required.** Free-text reason for the request (1–2048 chars), shown to approvers. |
| `requestedSignings` | How many sign operations the approval permits. Leave empty to fall back to the policy ceiling. |
| `requestedWindowStart` | ISO 8601 timestamp the access window opens. Defaults to "now". |
| `requestedWindowEnd` | ISO 8601 timestamp the access window closes. Leave empty to fall back to the policy ceiling. |

#### Admin endpoints

Administrators of a Signer can also pre-approve or revoke requests on behalf of other members:

- `POST /api/v1/cert-manager/signers/{signerId}/requests/pre-approve` — body accepts `granteeUserId` **or** `granteeIdentityId` plus the same `justification` / `requestedSignings` / `requestedWindowStart` / `requestedWindowEnd` fields. Creates a request that is already approved.
- `POST /api/v1/cert-manager/signers/{signerId}/requests/{requestId}/revoke` — revokes a pending or active request. No body.

## Troubleshooting

Enable debug logging by adding to your config file:

```json
{
  "log_level": "debug",
  "log_file": "/tmp/infisical-pkcs11.log"
}
```

Then monitor: `tail -f /tmp/infisical-pkcs11.log`

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `CKR_GENERAL_ERROR` on init | Config file not found or invalid | Check `INFISICAL_CONFIG` path and JSON syntax |
| `CKR_GENERAL_ERROR` on sign | Approval required or permission denied | Request approval, or confirm the Machine Identity is a Signer member with the Administrator or Operator role (Auditors cannot sign) |
| `CKR_USER_NOT_LOGGED_IN` | No credentials or token expired | Set `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` and `CLIENT_SECRET` |
| `CKR_PIN_INCORRECT` | Invalid credentials in PIN | Use format `clientId:clientSecret` |
| `CKR_SLOT_ID_INVALID` | No signers visible to this Machine Identity (none exist, or the identity isn't a member of any signer) | Create a signer in Cert Manager > Code Signing, or add this identity as a member on the signer's Members tab |
| `CKR_DEVICE_ERROR` | Server unreachable | Check `server_url` and network connectivity |

## Building from Source

Requires Go 1.21+ and a C compiler (GCC or Clang).

```bash
# Build for current platform
make build

# Run tests
make test

# Cross-compile (requires appropriate cross-compilers)
make build-linux-amd64
make build-linux-arm64
make build-darwin-amd64
make build-darwin-arm64
make build-windows-amd64    # requires MinGW
```

## Security

- **Private keys never leave Infisical.** All signing happens inside Infisical.
- **Use environment variables for credentials** — avoid committing secrets to config files.
- If using config-file credentials, restrict permissions: `chmod 600 /etc/infisical/pkcs11.conf`
- Auth tokens are cached in memory only — never written to disk.
- Enable [approval policies](https://infisical.com/docs/documentation/platform/pki/code-signing/approvals) on signers to require human review before signing.
- Every signing operation is recorded in [Infisical audit logs](https://infisical.com/docs/documentation/platform/audit-logs) with actor, timestamp, and client metadata.

Please do not file GitHub issues or post on public forums for security vulnerabilities. If you believe you have uncovered a vulnerability, contact [security@infisical.com](mailto:security@infisical.com).

## Contributing

Whether it's big or small, we love contributions. Check out our [contributing guide](https://infisical.com/docs/contributing/getting-started) to get started.

Not sure where to get started? Join our [Slack](https://infisical.com/slack) and ask us any questions.
