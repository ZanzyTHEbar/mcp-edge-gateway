# Tunnel-free headless MCP login

`mcp-edge-credential-bridge` is a local Go executable that connects an ordinary
stdio MCP client to a Streamable HTTP MCP Edge service. It does not modify the
client, listen on a callback port, or require SSH forwarding.

```text
OpenCode (stdio) -> credential bridge -> MCP Edge (HTTPS) -> service
                         |
                 encrypted local keystore
```

## Build and sign in

The bridge requires a Unix host with Secret Service, `secret-tool` (libsecret),
`gdbus` (GLib), and OS file locking. It does not currently integrate with macOS
Keychain or Windows Credential Manager. On Debian/Ubuntu, install
`libsecret-tools`, `libglib2.0-bin`, and a Secret Service provider such as
`gnome-keyring`. Use a **password-protected, encrypted default collection**.

Build from the repository root:

```sh
go build -buildvcs=false -o ./mcp-edge-credential-bridge ./cmd/mcp-edge-credential-bridge
```

Install the executable at a stable absolute path accessible to your MCP client.
Run login **on the host that will run the bridge**:

```sh
/absolute/path/mcp-edge-credential-bridge login \
  --url https://mcp.example.com/example/mcp
```

Open the displayed verification URL on another device, check the requested
service and scope, and approve. Login polls for approval and saves the credential
locally. The stdio process never attempts an interactive login itself; missing,
expired, or revoked credentials produce a stderr instruction to sign in again.
Normal access-token expiry is handled automatically with a refresh token.

Login requires a public client with device-code and refresh-token grants. If
public dynamic registration is enabled for the service, the bridge registers
one. If registration is operator-only, pre-register a public client through the
operator channel and supply its non-secret ID:

```sh
/absolute/path/mcp-edge-credential-bridge login \
  --url https://mcp.example.com/example/mcp \
  --client-id <registered-public-client-id>
```

Registration metadata:

```json
{
  "client_name": "mcp-edge-credential-bridge",
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
  "redirect_uris": [],
  "response_types": [],
  "token_endpoint_auth_method": "none",
  "scope": "mcp:example"
}
```

No operator token or client secret belongs in the bridge's arguments, environment,
or MCP configuration. Existing successful device-client registration is reused
on the next login. Use `logout` before login to discard a revoked registration.

## Configure unmodified OpenCode V2

Configure the service as a **local** MCP server, not a remote OAuth server:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "example": {
        "type": "local",
        "command": [
          "/absolute/path/mcp-edge-credential-bridge",
          "--url",
          "https://mcp.example.com/example/mcp"
        ]
      }
    }
  }
}
```

Preserve unrelated server settings and replace only the intended remote entry.
After login, reconnect the entry from `/mcps`. Do not run OpenCode's remote OAuth
login for this local bridge. Other stdio MCP clients use the same command and
arguments. Stdout contains JSON-RPC only; login instructions and errors go to
stderr.

## Encrypted keystore and concurrent sessions

The complete credential record (access token, refresh token, client ID, issuer,
scope, and token endpoint) is stored in the OS Secret Service's **encrypted
default keyring**, not a bridge-managed JSON file. Encryption at rest is owned
by the keystore provider. Secret Service itself does not mandate disk encryption:
the operator must configure and verify a password-protected collection. Never
use an empty-password/plaintext collection or a session-only collection for
durable credentials.

The binary reads and updates the record at runtime using libsecret's
`secret-tool`. Values are sent over private subprocess pipes: no secret appears
in command arguments, environment variables, logs, or temporary credential
files. The helpers are invoked directly, without a shell. The item attributes
are `service=mcp-edge-credential-bridge` and `resource=SHA256(service URL)`.

Only empty refresh-lock files live in the bridge's state directory (normally
`~/.config/mcp-edge-credential-bridge/` on Linux, respecting `XDG_CONFIG_HOME`).
Set `--state-dir` on both login and the configured stdio command to override it.

- State directory mode is `0700`; empty lock files are `0600`. They contain no
  tokens, passwords, or encryption keys.
- The keystore must be available and unlocked in the bridge process's user
  session. Both login and serving fail closed if it is unavailable or locked.
  There is no file, environment-variable, or plaintext fallback.
- Unlock through the OS's trusted login/PAM or secure interactive mechanism.
  After a reboot the keystore may need unlocking again, but stored OAuth
  credentials persist in its encrypted storage. Do not save its unlock password
  in a service unit, script, environment variable, or an agent conversation.
- Existing credential items are replaced only after authorization succeeds.
  Failed login does not discard a previous credential.
- An OS file lock serializes keystore replacement and token refresh across
  processes. Each refresh rereads the latest keystore item, preserving rotated
  refresh tokens when multiple client sessions share the same service.
- Locks are released by the OS when a process exits. Do not delete `.lock` files
  while bridges are running; replacing the lock inode defeats mutual exclusion.
- If legacy bridge plaintext JSON files exist, startup refuses to use them.
  Revoke the old tokens and remove the old files through a trusted operator
  channel before signing in again. They are not silently imported or deleted.

An unlocked Secret Service is scoped to the OS user, not exclusively to this
binary. Other code running as that user (and privileged host administrators)
can potentially access it. Tokens necessarily exist transiently in process
memory for use over HTTPS. The keystore protects persistence; it does not
protect an already-compromised user session. Keep the host account, user D-Bus,
the bridge executable, and the helper search path trusted.

The executable disables core dumps for itself and its helper subprocesses.
Host operators should also use encrypted or disabled swap and protect keystore
backups; the bridge cannot enforce the host's memory, backup, or storage policy.

Remove the local credential with:

```sh
/absolute/path/mcp-edge-credential-bridge logout \
  --url https://mcp.example.com/example/mcp
```

Logout removes the matching keystore item, not other applications' secrets.
It does not revoke server-side tokens or terminate an already-open stream.
Stop existing bridge processes as well, and use operator session revocation if
immediate server-side invalidation is required.

## Transport and security boundaries

The bridge discovers the service's RFC 9728 metadata and service-scoped RFC 8414
issuer. It checks the resource and issuer, uses exactly one `mcp:<service>` scope,
and includes the RFC 8707 resource in device and refresh requests.

This is an **MCP Edge client**, not a generic cross-origin OAuth client. OAuth
endpoints must use the same origin as the service URL. HTTPS is required except
on loopback for local development; redirects are not followed. A stored bearer
token is attached only to the exact configured MCP resource URL.

The stdio relay preserves JSON-RPC requests, responses, capabilities, extension
fields, and IDs. It handles JSON and SSE POST responses, MCP session/version
headers, and the optional legacy server-initiated GET SSE stream. It forwards
notifications and server requests without replacing them with a fixed tool list.
It closes the remote session on exit. Requests are bounded to 32 in flight and
16 MiB per message. A failed MCP POST is not blindly replayed: only a `401`
can trigger one credential refresh and replay. The notification-only GET stream
reconnects after idle proxy timeouts, clean closures, transient network failures,
and HTTP 429/500/502/503/504 responses. It retains the MCP session ID and last event
cursor, with retry backoff capped at 30 seconds. A quiet stream need not produce
JSON-RPC messages to keep the bridge alive. Invalid non-empty JSON-RPC,
authentication/keystore errors, and expired server sessions still surface as
failures; reconnect the MCP client after resolving those conditions.

Deploy the Edge compatibility fixes before relying on standard device polling:
empty registration arrays must encode as `[]`, and device token errors must
use the OAuth `{"error":"authorization_pending"}` shape, not the platform's
nested error object.

## Verification

Run the normal Go checks without requiring a desktop/keyring service. The
separate end-to-end acceptance scenario requires a real, unlocked encrypted
Secret Service; it does not mock credential storage:

```sh
go test -buildvcs=false ./...
go test -race -buildvcs=false -tags=integration ./internal/edge \
  -run '^TestCredentialBridgeDeviceLoginAndStdio$' -count=1 -timeout=90s
```

The acceptance scenario uses a unique loopback service and removes only its
own keystore item on completion. It checks device polling, browser approval,
keystore persistence, absence of credential files, rotation, tool calls, and
server notifications.
