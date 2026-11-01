# Agent Runtime Guard vs other layers

Short positioning for reviewers and list maintainers.

## One sentence

**Pre-execution, local, fail-closed tool-call interception with offline-verifiable Ed25519 receipts.**

## Layer map

| Layer | Typical tools | Question answered |
|-------|---------------|-------------------|
| Discovery / posture | Reco, Pluto, Zenity-class | What agents exist and what can they reach? |
| Config scanners | correctover-scan, mcp-guard scanners | Is this MCP/agent config risky before it runs? |
| Egress / proxy firewalls | Pipelock, gateway products | What leaves the network boundary? |
| **Runtime tool-call guard** | **agent-runtime-guard**, HOL Guard-class | **Can this specific tool call execute now?** |
| Kernel / sandbox | eBPF MCP sandboxes | Can the process make this syscall? |

## vs Pipelock-class egress firewalls

| | Agent Runtime Guard | Pipelock-class |
|--|---------------------|----------------|
| Primary surface | MCP / tool-call arguments | Mediated HTTP, WS, MCP, tunnels |
| Install | `npx` MCP server | Binary / proxy topology |
| Receipts | Ed25519 per decision | Mediator-signed action receipts |
| Best when | Agent already has MCP tools attached | You control egress path |

Complementary: proxy stops bulk exfil on the wire; we stop the bad tool call before it runs.

## vs config-only scanners

Scanners find bad configs. We enforce at call time. Use both.

## vs discovery platforms

Discovery does not block a single `curl|sh`. We do not map your SaaS agent estate. Use both.

## Public proof assets

- npm: `npx -y agent-runtime-guard`
- Census data: [m[mcp-atlas-census](https://github.com/DSHCorrectover/mcp-atlas-census) (229,827 tools, CC0)
- Standard draft: [draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/)

## Not claims we make

- Not “blocks 100% of attacks”
- Not a full SaaS posture platform
- Not an IETF standard (personal Internet-Draft only)
