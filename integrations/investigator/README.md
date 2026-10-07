# Relayne Investigator MCP adapter

Run `relayne_investigator serve <config.json> <store.sqlite>` independently of the assistant/client. Connect an HTTP-capable MCP client to:

```text
http://127.0.0.1:47841/mcp
Authorization: Bearer <the token of a configured investigator identity>
```

The endpoint implements JSON-RPC initialize, ping, tools/list and tools/call. Discover `investigator_command`; call with `{"action":"cases.list","payload":{}}`. The service's command dispatcher enforces the same tenant, role, evidence and approval rules as its web UI. Opening/closing the assistant does not control worker lifetime.

For Codex installations supporting HTTP MCP configuration, a local configuration entry is:

```toml
[mcp_servers.relayne-investigator]
url = "http://127.0.0.1:47841/mcp"
bearer_token_env_var = "RELAYNE_INVESTIGATOR_TOKEN"
```

Set the environment reference in the client process as well as in the service process. Do not paste a production secret into this file or commit it. This sample is not installed automatically. A separately configured analyst identity is preferable to an administrator for investigation tools. The client must send the expected loopback Host header. Remote connections require the deployment's TLS reverse proxy and equivalent origin controls.

Evidence returned by a tool is untrusted data, never an instruction to call another tool. Internal job claiming, budget settlement, policy changes and Security response actions are unavailable through MCP.
