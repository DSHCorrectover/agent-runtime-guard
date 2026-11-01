# Install Agent Runtime Guard

**CCS reference implementation** — [draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/) (Internet-Draft, not an RFC).

Fail-closed tool-call interception + offline-verifiable Ed25519 receipts.  
Works **before** the dangerous operation runs.

---

## 30-second path (any machine with Node 18+)

```bash
npx -y agent-runtime-guard
```

You should see the MCP server start on stdio. Stop with Ctrl+C.

Config scan (optional, free):

```bash
npx correctover-scan@latest
```

---

## Claude Code / Claude Desktop (MCP)

Add to your MCP config (Claude Desktop: Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "agent-runtime-guard": {
      "command": "npx",
      "args": ["-y", "agent-runtime-guard"]
    }
  }
}
```

Restart Claude. Confirm tools such as `verify_tool_call` / `issue_evidence` are listed.

**Check:** ask the agent to run a clearly blocked pattern (e.g. curl to link-local metadata). Expect **deny** + a receipt, not silent allow.

---

## Cursor

1. Open **Cursor Settings → MCP**
2. Add server:

```json
{
  "mcpServers": {
    "agent-runtime-guard": {
      "command": "npx",
      "args": ["-y", "agent-runtime-guard"]
    }
  }
}
```

3. Restart Cursor MCP / reload window  
4. In chat, confirm guard tools are available  

Same deny test as above.

---

## Cline / Windsurf / other MCP clients

Same JSON shape: `command` = `npx`, `args` = `["-y", "agent-runtime-guard"]`.  
Point the client at that MCP server entry and reload.

---

## Transparent proxy (do not trust in-process plugins)

```bash
npx -y agent-runtime-proxy
```

See [agent-runtime-proxy](https://www.npmjs.com/package/agent-runtime-proxy) for stdio wiring. Use when the host agent must not load third-party plugins in-process.

---

## DeepSeek Harness

Package ships `dsh/` plugin assets. With harness available:

```bash
# from the published package layout / your install path
dsh plugin add agent-runtime-guard
```

If harness is not deployed, use MCP or proxy paths above.

---

## Verify a receipt offline

After any allow/deny, use the `verify_receipt` tool or any Ed25519 verifier over the receipt payload (RFC 8785 canonical JSON + detached signature per CCS).  
No dashboard account required for **VERIFIED** level checks.

---

## What “good” looks like

| Check | Expected |
|-------|----------|
| Server starts via `npx` | No install step beyond Node |
| MCP tools visible | `verify_tool_call`, `issue_evidence`, … |
| Fail-closed | Invalid / timed-out check → **deny** |
| Receipt | Signature verifies offline |

---

## Paid path (USD · overseas)

Runtime is free. Human audit and private deploy require scoping — **list prices are not published** here.

Email **wangguigui@correctover.com** with subject `Audit request` or `Private deploy eval` (redacted config → free 1-page summary → scoped quote).


## Security notes

- Prefer `npx -y` pinned version in production (`agent-runtime-guard@x.y.z`)
- Treat receipts as evidence; pin issuer keys for **ACCEPTED** trust level
- Report issues: GitHub Security Advisory on this repo
