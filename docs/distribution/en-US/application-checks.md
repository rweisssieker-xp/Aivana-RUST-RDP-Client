# Recorded application checks

Open **Recorded application and login checks** in the rehearsal's application-test section. Paste a locally prepared, redacted request recording. Review each request, assertion, port, transport, and credential slot, then choose **Adopt recorded checks**. Importing does not contact the application or a model. Execution uses the existing explicit rehearsal/production approval process and target mapping.

```json
{
  "schema_version": 1,
  "title": "Sign in and open dashboard",
  "port": 443,
  "tls": true,
  "steps": [
    {"path": "/login", "status": 200, "contains": "Sign in"},
    {
      "path": "/session", "status": 200, "contains": "Welcome",
      "login_slots": {"username": "test_user", "password": "test_password"}
    },
    {
      "path": "/api/dashboard", "status": 200, "contains": "",
      "json_equals": {"/ready": true}
    }
  ]
}
```

This example is a schema illustration, not evidence that these endpoints exist. Derive paths and expected results from an authorized local recording of your application. Review login POST side effects and use an appropriate test account. Supply runtime slot values through the existing HTTP runtime-values control when executing; the imported plan contains slot names only.

The first request must be a GET with a nonempty text assertion. Up to three follow-up requests can perform GETs, login form POSTs, and exact scalar JSON-pointer assertions. Login slots require HTTPS. Existing session-cookie restrictions and redirect handling apply. Every request must assert successful status and text or JSON content. Plans permit at most four requests and 32 KiB of recording input. Unknown fields and unsupported schema versions are rejected.

The application stores the compiled checks, not the pasted recording. Editing the recording or current draft invalidates review. Adoption clears existing receipts, rehearsal references, runtime values, and approval acknowledgment, requiring fresh evidence. A failed save blocks execution.

Only paste redacted assertions: free-text response markers and expected JSON values are operator-provided data and are not automatically scrubbed. Never paste raw HAR recordings, cookies, tokens, passwords, or personal data. The schema rejects fields for raw browser payloads but cannot recognize every secret embedded in an assertion.

This is a bounded HTTP application/session check pipeline. It does not replay browser clicks, execute JavaScript, solve MFA or CAPTCHA, validate rendered UI, or prove that AI-generated suggestions are correct. The separate AI HTTP proposal workflow still requires explicit send consent and review. No live host, browser, or model tests were used to validate this import feature.

# Checks from actual local recordings

In **Local recordings**, select a finished recording and open **Application checks from this recording**. Choose **Derive recorded visible checkpoints**. Candidates come directly from that archive's protected OCR index and retain their frame numbers and capture timestamps. Notes, filenames, and missing OCR never create an assertion. A fixed vocabulary of common UI-state words limits accidental disclosure; frames with secret-field hints are omitted. This deliberately conservative derivation may produce no candidates for a valid application. It does not upload images, call a model, or infer hidden application state.

Select up to four candidates and review the original images. A checkpoint-only workflow needs at least two observed states and pauses for the operator to perform any intervening actions. Alternatively, include the currently loaded demonstration. This uses the existing validated native RDP procedure runner, named runtime parameter slots, current-frame semantic target resolution, and per-step visible postconditions. The demonstration is selected separately: recordings do not supply timestamps that can align teaching steps automatically, and no login actions are invented from screenshots.

Review binds the complete recording index, exact current profile snapshot, selected candidates, and optional demonstrated procedure for five minutes. Preparing the plan rereads the protected archive and rejects changes. The resulting plan targets the recording's profile UUID and opens in **Workflows** with previous workflow approval and runtime values cleared. Preparation never runs it. Review and approve the workflow separately before any remote action.

These checks can exercise a browser-based application displayed in the existing native RDP session when a compatible demonstration is provided. They do not introduce a general browser engine, DOM automation, JavaScript execution, MFA solving, or a proof of backend transaction success. The archive records a profile UUID; the current endpoint for that profile is shown for review and is not claimed to be a historical endpoint fingerprint. Visible OCR checkpoints are observed text selected by the operator as expected states.
