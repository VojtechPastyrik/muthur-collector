# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability, please report it responsibly.

Email: vojtech@pastyrik.dev

## Scope

- PII redaction bypass (sensitive data leaking through to central)
- Token leakage in logs or error messages
- K8s RBAC escalation via collector service account
- Protobuf deserialization issues

## Out of scope

- Vulnerabilities in upstream dependencies (report to the respective projects)
