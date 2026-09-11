# Aivana gateway TLS patch

Upstream: `ironrdp-tls` 0.2.2 from crates.io (Devolutions/IronRDP).

`src/native_tls.rs` enables native certificate-chain and hostname validation and
SNI. Upstream's helper accepts invalid certificates by default, which is unsuitable
for the RD Gateway HTTP Basic authentication used by `ironrdp-mstsgu` 0.0.1.
Gateway certificates must be trusted by the operating system and match the gateway
DNS name. There is no gateway certificate bypass or trust-on-first-use path.

The application selects this native-tls backend for the gateway. Target RDP TLS
continues through the application's existing separate certificate policy.

The Rustls/stub variants are upstream code and are not enabled by the application's
gateway dependency. Do not switch TLS backends without auditing their verifier.
