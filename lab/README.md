# Lab Environment

Vulnerable targets for local pipeline testing. All services join the
pre-existing `scan-net` Docker network so pipeline scanners can reach
them by hostname.

| Service    | Host port | Internal hostname | Purpose              |
|------------|-----------|-------------------|----------------------|
| DVWA       | 4280      | `dvwa`            | PHP/MySQL vuln app   |
| Juice Shop | 3000      | `juice-shop`      | Node.js vuln app     |

## Prerequisites

Create the external network once (skip if it already exists):

```bash
docker network create scan-net
```

## Start the lab

```bash
docker compose -f lab/docker-compose.lab.yml up -d
```

## Stop the lab

```bash
docker compose -f lab/docker-compose.lab.yml down
```

## Stop and remove all data (full reset)

```bash
docker compose -f lab/docker-compose.lab.yml down -v
```

## Verify targets are reachable

```bash
curl -sI http://localhost:4280 | head -1   # DVWA
curl -sI http://localhost:3000 | head -1   # Juice Shop
```

## Notes

- DVWA database data is stored in the `dvwa-data` compose-managed volume.
  Running `down -v` will delete it; the next `up` re-initialises from scratch.
- To run Katana against an internal target: the pipeline default is `scan-net`.
  Override with `KATANA_NETWORK=host` for real external targets.
