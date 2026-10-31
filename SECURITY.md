# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1.0 | :x:                |

## Reporting a Vulnerability

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in `agent-runtime-guard` — including bypass techniques, false negatives, or vulnerabilities in the receipt signing mechanism — please report it responsibly:

- **Email**: `security@correctover.com`
- **Subject line prefix**: `[ARG-SECURITY]` — e.g. `[ARG-SECURITY] SSRF bypass via DNS rebinding`
- **GPG key**: Available at `https://correctover.com/security/gpg.txt` (fingerprint to be published)

We aim to acknowledge receipt within **48 hours** and provide an initial assessment within **5 business days**.

## What to Include

A high-quality report should include:

1. **Description**: What the vulnerability is and why it matters in an AI agent runtime context.
2. **Reproduction**: A minimal test case or payload that triggers the bypass. For `agent-runtime-guard`, this means a tool call JSON that passes `verify_tool_call` but should be blocked.
3. **Impact**: What an attacker could achieve (e.g., credential exfiltration, SSRF to cloud metadata, command execution).
4. **Affected versions**: Which npm version(s) you tested against.
5. **Suggested fix**: If you have one — we welcome patches.

## Disclosure Policy

- **Private window**: We request **90 days** from initial report to public disclosure, to allow time for patch development and distribution.
- **Coordination**: We will keep you informed of our progress and credit you in the advisory unless you request anonymity.
- **Exception**: If we believe active exploitation is occurring in the wild, we may expedite disclosure with your coordination.

## Scope

### In Scope

- Bypasses of `verify_tool_call` (command injection, SSRF, path traversal, prompt injection)
- Weaknesses in the Ed25519 receipt signing/verification chain
- False negatives in `verify_intent_binding`
- MCP protocol handling vulnerabilities (JSON-RPC injection, stdio hijacking)
- Side-channel or timing issues in the verification path

### Out of Scope

- Vulnerabilities in downstream MCP servers that `agent-runtime-guard` wraps (report to the server vendor)
- Vulnerabilities in Node.js runtime itself (report to Node.js security team)
- Social engineering of end users
- Issues that require the attacker to already control the host machine

## Acknowledgements

We will maintain a public `SECURITY.md` acknowledgements section for researchers who report valid vulnerabilities. Hall of Fame to be published after our first responsible disclosure cycle.

## Security Design Notes

This project operates under a **fail-closed** model: if verification fails for any reason (including internal errors), the tool call is denied. However, `agent-runtime-guard` is a **detection layer**, not a kernel-level sandbox. It cannot prevent a compromised host process from bypassing it entirely.

For high-assurance environments, we recommend combining `agent-runtime-guard` with:
- OS-level sandboxing (seccomp-bpf, Landlock, gVisor)
- Network-level egress filtering
- Hardware security modules (HSM) for Ed25519 signing keys
