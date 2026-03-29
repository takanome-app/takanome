# Takanome

Security scanner for AI agents. Scans your agent installation, checks it against the official security documentation, and gives you a score out of 100.

Now with **AI-powered analysis and smart fixes** via the [Bankr LLM Gateway](https://docs.bankr.bot/llm-gateway/overview/).

Currently supports **OpenClaw**. Pluggable architecture makes it easy to add more agent types.

Built in Rust — ships as a single self-contained binary. No runtime required.

## Installation

**From source:**

```bash
cargo build --release
cp target/release/takanome /usr/local/bin/
```

**Via cargo:**

```bash
cargo install takanome
```

**Homebrew** (coming soon):

```bash
brew install takanome
```

## Usage

```bash
# Auto-detect installed agent and scan
takanome scan

# Specify agent type
takanome scan --agent openclaw

# Show all checks (including passing)
takanome scan --verbose

# Machine-readable JSON output
takanome scan --json
```

### AI Features (Bankr LLM Gateway)

All AI commands require a Bankr API key. Get one at [bankr.bot/api](https://bankr.bot/api).

```bash
# Set your API key (recommended)
export BANKR_API_KEY=bk_YOUR_KEY

# Scan + AI narrative analysis of all findings
takanome analyze

# Use a specific model (default: claude-haiku-4.5)
takanome analyze --model claude-sonnet-4.6
takanome analyze --model gemini-3-flash
takanome analyze --model gpt-5-nano

# Pass API key inline instead of env var
takanome analyze --api-key bk_YOUR_KEY

# Get JSON output (scan report + AI analysis combined)
takanome analyze --json

# AI-generated smart fixes (preview only)
takanome ai-fix --dry-run

# AI-generated smart fixes with confirmation prompt per fix
takanome ai-fix --interactive

# Apply all AI-generated fixes automatically
takanome ai-fix

# AI fix with a stronger model for complex configs
takanome ai-fix --model claude-sonnet-4.6
```

### Supported Models

Any model available on the [Bankr LLM Gateway](https://docs.bankr.bot/llm-gateway/models) can be used with `--model`:

| Model | Speed | Best for |
|---|---|---|
| `claude-haiku-4.5` | Fast | Default — good for most scans |
| `claude-sonnet-4.6` | Medium | Complex configs, detailed analysis |
| `gemini-3-flash` | Fast | Cost-efficient alternative |
| `gpt-5-nano` | Fast | OpenAI alternative |

## What It Checks

Takanome runs 30+ security checks across 14 categories, all derived from the [OpenClaw Security Documentation](https://docs.openclaw.ai/gateway/security):

| Category | Points | Checks |
| --- | --- | --- |
| Authentication | 12 | Auth mode, token vs password, token strength (>= 32 chars) |
| File Permissions | 10 | `~/.openclaw` dir is 700, config is 600, credential files protected |
| Network Exposure | 12 | Loopback binding, port not publicly exposed, Tailscale preferred |
| DM Security | 8 | DM policy is pairing/allowlist, per-channel-peer session isolation |
| Group Security | 6 | Groups require @mention, no open group policies |
| Tool Authorization | 10 | Dangerous tools denied, elevated tools disabled, restrictive profile |
| Exec Security | 10 | Shell exec denied, approval required, strict inline eval |
| Sandboxing | 10 | Sandbox mode enabled, per-agent/session scope, no dangerous Docker flags |
| Browser Security | 6 | SSRF private network blocked, dedicated browser profile |
| Dangerous Flags | 6 | No insecure config flags enabled |
| Logging & Privacy | 4 | Sensitive data redaction, transcript permissions |
| mDNS/Discovery | 2 | mDNS set to minimal or off |
| Control UI | 2 | Origin allowlist configured, device auth enabled |
| Plugins | 2 | Explicit plugin allowlist configured |
| Secrets Management | 12 | secrets.json permissions, auth profile permissions, no hardcoded passwords, no plaintext API keys, secrets not in agent workspace |

## Scoring

Each check has a severity level (critical, high, medium, low) and a point value. Your score is normalized to 100 regardless of how many checks are active.

* **80–100**: Well hardened
* **60–79**: Needs attention
* **Below 60**: Significant risks

## Example Output

### `takanome scan`

```
  Takanome Security Scan — OpenClaw
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Score: 72/100 (81/112 pts)

  Authentication                     8/12
    ✓ Gateway auth enabled                 4/4
    ✓ Token auth mode (recommended)        4/4
    ✗ Auth token strength                  0/4
      Token length: 13 chars (minimum 32 recommended)
      Fix: Generate a strong token: openclaw doctor --generate-gateway-token
```

### `takanome analyze`

```
  Takanome Security Scan — OpenClaw
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score: 72/100 ...

  Takanome AI Analysis — Bankr LLM Gateway
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Model: claude-haiku-4.5

  Risk Summary
  Your OpenClaw installation scores 72/100, indicating a moderately hardened setup
  with several gaps that could allow privilege escalation or data exfiltration.
  The most critical risk is your weak auth token (13 chars), which could be brute-forced.
  Secondary concerns are around exec security and sandbox isolation.

  Critical & High Priority Issues
  - Auth token strength (Authentication): A short token can be brute-forced in minutes,
    giving an attacker full gateway access.
    Fix: openclaw doctor --generate-gateway-token

  Recommended Action Order
  1. Regenerate auth token to 32+ characters (auth.token_strength)
  2. Enable sandbox mode for all agent sessions (sandboxing)
  3. Deny shell exec and set approval required (exec_security)
```

### `takanome ai-fix --dry-run`

```
  Takanome AI Fix — Bankr LLM Gateway
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Model: claude-haiku-4.5   Failed checks: 4
  [DRY RUN — no changes will be made]

  1. [CRITICAL] Auth token strength
     A 13-char token can be brute-forced in minutes.
     → Regenerate gateway auth token
     openclaw doctor --generate-gateway-token

  2. [HIGH] Shell exec denied
     Shell exec allows arbitrary code execution on the host.
     → Disable shell exec in config
     openclaw config set exec.shell_exec deny
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Scan passed (no critical failures) |
| 1 | Critical security issues found |
| 2 | Scanner error (agent not found, config parse failure, etc.) |

## Architecture

```
takanome scan      → rule-based only (offline, no API key needed)
takanome fix       → rule-based auto-fix (offline)
takanome analyze   → scan + Bankr LLM Gateway AI narrative
takanome ai-fix    → scan + Bankr LLM Gateway AI-generated patches
```

The AI layer is purely additive — all existing commands work without any API key.

## Adding a New Agent

Create a new module under `src/agents/<name>/` and implement the `AgentPlugin` trait:

```rust
pub trait AgentPlugin {
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn detect(&self) -> bool;
    fn scan(&self) -> anyhow::Result<Vec<CheckResult>>;
}
```

Then register it in `src/agents/mod.rs`. See `src/agents/openclaw/` for a complete example.

## Building

Requires Rust 1.75+.

```bash
cargo build            # Debug build
cargo build --release  # Optimized release build (stripped, LTO enabled)
```

## License

MIT
