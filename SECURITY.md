# Security Policy

Porthole is a read-only inspection tool: it opens a single outbound TLS
connection to the domain you give it, reads back the certificate chain and
negotiated parameters, and renders them. It does not run a server, store
credentials, or persist any data between runs.

## Reporting a vulnerability

If you find a security issue (e.g. a certificate validity check that
accepts something it shouldn't, or a way to trigger unsafe behavior via a
malicious server response), please open a GitHub issue on this repository
with reproduction steps.
