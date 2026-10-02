# Security

This project is a lab and educational AI SOC platform. It is not represented as fully secure, enterprise-certified, or production-proof.

## Boundaries

- Response execution is simulation-only. Database constraints require `execution_mode=simulation`.
- Production configuration requires bearer authentication, explicit CORS origins, disabled API documentation, and explicit startup migration.
- Secrets are masked by `Secret` stringification and are not included in effective configuration output.
- Requests receive request IDs, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.
- Failed authentication is rate-limited per client address. Forwarded addresses are trusted only for configured proxies.
- `/health`, `/ready`, and `/version` are minimal public operational endpoints. Other API routes require authentication.

The route inventory regression is in [tests/test_phase10_routes.py](../tests/test_phase10_routes.py). Security verification is run with `python -m tests.verify`.

TLS termination belongs to the deployment or reverse-proxy layer. The Docker setup does not pretend to provide TLS. Backups are currently unencrypted and must be protected by the deployment environment.
