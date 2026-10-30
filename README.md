# Xray Node.js Gateway

This project packages Xray-core behind a small Node.js HTTP and WebSocket
gateway. It is intended to run as a Docker container on a platform such as
Cloudways Velocity, where HTTPS is terminated by the platform and the
application receives traffic on the `PORT` environment variable.

## Project Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds the Node.js 22 Alpine image and starts the service. |
| `package.json` | Defines the runtime dependency and build/start scripts. |
| `build-xray.js` | Downloads and installs the pinned Xray Linux binary during the image build. |
| `server.js` | Generates the Xray configuration, starts Xray, proxies HTTP/WebSocket traffic, and serves the dashboard. |

## How It Works

1. Docker installs the production dependency `adm-zip`.
2. `npm run build` downloads Xray-core `25.12.8` for Linux `x64` or `arm64`.
3. `server.js` creates a temporary Xray configuration with four loopback
   inbounds.
4. Node.js forwards HTTP requests and WebSocket upgrades from the public port
   to the matching local Xray inbound.
5. Xray forwards permitted traffic through the `freedom` outbound and blocks
   private/reserved IP ranges and BitTorrent traffic.

The public HTTPS proxy should forward these paths without rewriting them:

| Protocol | WebSocket path | Local Xray port |
| --- | --- | ---: |
| VLESS | `/vless_zhuofan` | `14016` |
| VMess | `/vmess_zhuofan` | `23456` |
| Trojan | `/trojan-ws_zhuofan` | `25432` |
| Shadowsocks | `/ss-ws_zhuofan` | `30300` |
| VLESS XHTTP | `/xhttp_zhuofan` | `14443` |

The Xray inbounds listen only on `127.0.0.1`; clients must connect through
the public HTTPS/WebSocket endpoint, not directly to these local ports.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Public Node.js listen port. Cloudways normally supplies this. |
| `XRAY_BIN` | `./bin/xray` | Optional path to an existing Xray binary. |
| `XRAY_LOGLEVEL` | `warning` | Xray log level. |
| `EXPOSE_PASS` | unset | Set to `true` to expose `/pass`. Keep disabled in production. |
| `DEBUG_LOGS` | unset | Set to `true` to expose `/logs`. Keep disabled in production. |
| `XRAY_VERSION` | `25.12.8` | Docker build argument defined by `Dockerfile`. Note that the current downloader pins the same version in `build-xray.js`. |
| `DASHBOARD_USERNAME` | `admin` | Dashboard login username. |
| `DASHBOARD_PASSWORD` | unset | Required dashboard login password. Set a strong secret. |
| `GATEWAY_CONFIG_FILE` | `/app/data/gateway-config.json` | Optional path for persisted UUID and paths. |

The UUID and path suffix are currently constants in `server.js`. They are not
used when no saved dashboard configuration exists. After the first dashboard
update, the values are persisted in `GATEWAY_CONFIG_FILE`. Mount `/app/data`
as persistent storage if settings must survive container replacement.
If the configured path is not writable, the service falls back to
`/tmp/zftunnel-config.json` and records a warning; those settings will not
survive container replacement.

## Dashboard

Open `/dashboard` on the deployed domain. The dashboard requires the
`DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` environment variables and uses
an HttpOnly, SameSite session cookie. It provides:

- UUID and individual WebSocket path editing
- Xray restart after saving a valid configuration
- VLESS, VMess, Trojan, Shadowsocks, and VLESS XHTTP connection URIs
- A QR code button beside each URI, opening the code in a dialog
- Authenticated log polling every three seconds
- Current network information, runtime status, uptime, and inbound ports
- Traffic counter for uploaded, downloaded, and active proxied data

Set these values in Cloudways before deployment, for example:

```text
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=<long-random-password>
```

Do not put the password in the repository or in a public URL. The dashboard
must be used through HTTPS in production.

## Local Docker Usage

Build and run the image:

```sh
docker build -t xray-nodejs-gateway .
docker run --rm -p 3000:3000 -e PORT=3000 xray-nodejs-gateway
```

Check the public application root:

```sh
curl http://127.0.0.1:3000/
```

The root endpoint returns the service landing page. Unknown paths return
`404`. The `/pass` and `/logs` endpoints return `404` unless their respective
explicit environment flags are enabled.

## Cloudways Velocity Deployment

The application is deployed at:

`https://enterprise.nulledbytes.com`

Use the repository `https://github.com/emp-zf/caas/` as the deployment source.

1. Configure the service to build from the repository's `Dockerfile`.
2. Ensure the platform forwards its assigned `PORT` to the container.
3. Configure the domain and HTTPS reverse proxy to forward WebSocket upgrade
   requests and preserve the four paths listed above.
4. Set `DASHBOARD_USERNAME` and a strong `DASHBOARD_PASSWORD`.
5. Mount persistent storage at `/app/data` if dashboard changes must survive
   redeployments.
6. Deploy or restart the container after each repository change.
7. Verify `/` and `/dashboard`, then test a WebSocket client using a generated
   URI.
8. Keep `EXPOSE_PASS` and `DEBUG_LOGS` unset.

The Docker image runs `npm start`, which executes `node server.js`. No separate
Nginx configuration or entrypoint script is required by the current build.
The container runs as the unprivileged `node` user; `/app/data` is prepared with
the correct ownership for persisted dashboard settings.

## Operational Notes

- Node.js `22` or newer is required.
- The build needs outbound HTTPS access to download the Xray release from
  GitHub.
- `server.js` validates the generated Xray configuration before starting the
  Xray process. If validation fails, the Node.js diagnostics server remains
  online and records the failure in its logs.
- The service keeps up to 200 recent runtime log lines in memory.
- On `SIGTERM` or `SIGINT`, the server stops accepting requests, terminates
  Xray, and removes its temporary configuration file.
- The Xray binary is downloaded during image build and is not committed to the
  repository.

## Security Checklist

- Replace the hardcoded UUID before production use.
- Set a strong `DASHBOARD_PASSWORD` and rotate it periodically.
- Persist `/app/data` only on protected storage with restrictive permissions.
- Do not enable `/pass` or `/logs` on a public deployment.
- Restrict repository and deployment access as appropriate.
- Keep the Xray version current and review release changes before upgrading.
- Confirm that the Cloudways proxy preserves WebSocket upgrades and does not
  expose the local Xray ports.
- Monitor logs and resource usage because WebSocket connections can remain
  open for a long time.

## License

No license file is currently included. Add an explicit license before
redistributing this project.
