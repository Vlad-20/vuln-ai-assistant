# Lab Environment

Vulnerable targets for local pipeline testing. All services join the
pre-existing `scan-net` Docker network so pipeline scanners can reach
them by hostname.

| Service        | Host port | Internal hostname | Purpose                     |
|----------------|-----------|-------------------|-----------------------------|
| DVWA           | 4280      | `dvwa`            | PHP/MySQL vuln app           |
| Juice Shop     | 3000      | `juice-shop`      | Node.js/Express vuln app     |
| WordPress 5.0  | 8081      | `vulnerable-wp`   | Known-vulnerable WP install  |

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

## First-time WordPress initialisation (required once)

WordPress requires a one-time setup wizard before it serves a usable site.
After the lab starts, visit:

```
http://localhost:8081
```

Complete the install wizard with any credentials (e.g. admin / admin123).
The wizard writes to the `wp-data` Docker volume, which persists across
`down` / `up` cycles. You only need to do this once per volume lifetime.

**Scan behaviour before initialisation:** WPScan can still detect the
WordPress version from `readme.html` and the generator meta tag even before
the wizard completes, so a partial scan is possible. However, the REST API
(`/wp-json/wp/v2`) returns a redirect to the wizard until the install is
done — the app-version probe will find no version string until initialisation
is complete.

## Verify targets are reachable

```bash
curl -sI http://localhost:4280 | head -1   # DVWA
curl -sI http://localhost:3000 | head -1   # Juice Shop
curl -sI http://localhost:8081 | head -1   # WordPress
```

## Scan targets in the pipeline

```
juice-shop:3000     # Juice Shop
vulnerable-wp       # WordPress (port 80 is default)
dvwa                # DVWA
```

## Expected enrichment behaviour by target

| Target       | Enrichment CVEs | Notes                                              |
|--------------|-----------------|----------------------------------------------------|
| Juice Shop   | 0               | OWASP intentional vuln app — not indexed in NVD    |
| WordPress    | 50+             | WordPress 5.0 has 50 CVEs; KEV hit on CVE-2020-11738 |
| DVWA         | 0               | Same as Juice Shop — educational app, not in NVD   |

## Notes

- DVWA and WordPress database data are stored in compose-managed volumes
  (`dvwa-data`, `wp-data`). Running `down -v` deletes them; the next `up`
  re-initialises from scratch.
- To run Katana against an internal target: the pipeline default is `scan-net`.
  Override with `KATANA_NETWORK=host` for real external targets.
- WordPress 5.0 is intentionally old. Do not expose port 8081 to the internet.
