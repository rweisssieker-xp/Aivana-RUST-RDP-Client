# Optional enterprise identity for the team API

The team API can validate RS256 JWT bearer credentials from one administrator-configured HTTPS OIDC issuer. Existing team tokens remain supported. There is no trust in proxy identity headers, automatic user provisioning, or role assignment from token role/group claims.

Set `RELAYNE_TEAM_OIDC_CONFIG` to an administrator-controlled JSON file before starting the team server. Example (replace issuer, audience and subjects with the values from your identity provider):

```json
{
  "issuer": "https://identity.example/realms/company",
  "audience": "relayne-team-api",
  "bindings": [
    { "sub": "explicit-operator-subject", "role": "operator" },
    { "sub": "explicit-viewer-subject", "role": "viewer" }
  ],
  "required_claims": { "token_use": "access" }
}
```

`required_claims` is optional and provider-specific; configure a discriminator where the provider distinguishes access tokens from other token types. This example's `token_use` is not a universal OIDC claim. The audience must identify this API, not a generic unrelated application. Configure `admin` only for subjects that should administer the entire team server. Protect the file against writes from untrusted accounts.

The server retrieves discovery metadata at the issuer's `.well-known/openid-configuration`, verifies the returned issuer exactly, and retrieves keys only from an HTTPS JWKS URL on the same origin. Redirects are rejected. This deliberately limits providers with cross-origin JWKS; such providers require a separately reviewed allowlist extension. JWT-supplied key URLs are never fetched. Only RSA RS256 verification keys are accepted, with signature validation by ring (2048–8192-bit RSA). The JWT must have a known unique `kid`, exact issuer, matching audience, a required unexpired `exp`, and `nbf` no later than the current time when present. There is no clock-skew grace period.

JWKS refresh after five minutes and on unknown key IDs; refresh attempts are limited to once per minute. Failed/stale key refresh fails authentication. Provider HTTP responses are capped at one MiB with five-second timeouts. JWTs are capped at 16 KiB. No bearer token is logged or persisted.

Bindings are reread and validated before each enterprise request and immediately before collaboration operator permissions are checked. Removing a subject, changing its role to viewer, deleting the config, or making it invalid therefore removes execution permission without creating/revoking fake local tokens. Stable collaboration/audit actors use the reserved `oidc:` namespace derived from issuer and subject. Local token issuance rejects this namespace. Provider-side logout/revocation is not introspected: a signed JWT otherwise remains valid until expiry; use short-lived tokens and remove local bindings for immediate application-side denial.

The Team screen accepts a team token or an enterprise JWT in its masked credential input. It also supports explicit browser sign-in using a configured HTTPS issuer, public client ID, API scopes, and an optional provider-specific `audience` parameter. Register a public/native application with Authorization Code + PKCE S256 and the loopback redirect `http://127.0.0.1:<ephemeral-port>/oauth/callback`. The provider must permit the dynamic port for its registered native application. No client secret is accepted or stored.

Only pressing the browser-login button starts discovery. The GUI opens the validated authorization URL in the system browser, where the provider handles credentials and any MFA/OTP. Discovery's issuer must match exactly; authorization and token endpoints must be HTTPS on the same origin, without redirects. PKCE uses 32 random bytes and S256; state is independently random. The callback listens only on an ephemeral IPv4 loopback port, checks method/Host/path, rejects duplicate parameters and incorrect state, and validates the response issuer when present (requiring it when discovery advertises that extension). It waits at most 120 seconds and can be cancelled. No browser cookies are read.

The code is exchanged once with its verifier and exact redirect URI. Only the token response's `access_token` with Bearer token type is used; `id_token` and refresh tokens are ignored. This API requires a JWT access token. The resulting token is held only in the masked runtime field and is immediately checked by the Team API through the normal snapshot request. Provider-specific audience/resource conventions beyond the optional `audience` parameter must be expressed through supported API scopes or require an explicit integration extension. No generic ID-token fallback or token persistence is provided. The initial team store still requires explicit bootstrap. REST role checks continue to apply to authenticated identities.

Validation includes synthetic RSA-signed tokens with correct and incorrect issuer, audience, subject, expiry, not-before, provider claims, signature, key type and algorithm. `tests/fixtures/oidc-synthetic-key.json` is a newly generated test-only RSA key, never a production credential. No real identity provider or gateway login is needed for those tests.

Sources: [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [JWT claims specification](https://www.rfc-editor.org/rfc/rfc7519), [JWT security best practices](https://www.rfc-editor.org/rfc/rfc8725), [OAuth for native applications](https://www.rfc-editor.org/rfc/rfc8252), [PKCE](https://www.rfc-editor.org/rfc/rfc7636).
