# Deployment

The production-oriented files are `Dockerfile`, `docker-compose.yml`, `frontend/Dockerfile`, and `frontend/nginx.conf`.

```powershell
$env:API_AUTH_TOKEN = '<runtime-secret-at-least-32-characters>'
docker compose up --build
```

The backend entrypoint explicitly checks configuration, refuses a newer schema, runs migrations, verifies the resulting schema, and starts Uvicorn with exactly one worker. SQLite uses the named `soc-data` volume; do not put this volume on a network filesystem or mount only `soc.db`, because WAL and SHM files must remain beside it.

The backend runs as UID 10001, read-only with a writable `/data` volume and `/tmp` tmpfs. Containers drop all capabilities and set `no-new-privileges`. The frontend uses an unprivileged nginx image, serves SPA deep links, and proxies `/api/` to the backend.

TLS is intentionally outside these containers and belongs at the deployment/reverse-proxy layer. Horizontal backend replication is not supported by the current SQLite architecture.
