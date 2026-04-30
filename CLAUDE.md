# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build (embeds version from git tag and build date)
make

# Run all tests
make test

# Run a single test or package
go test -v ./pkg/worker/...
go test -v -run TestFunctionName ./pkg/config/...
```

The binary accepts `-c <path>` for config file (defaults to `config.yaml`) and `-v` for version info.

## Architecture

`certwarden-client` is a daemon that periodically fetches TLS certificates and private keys from a [CertWarden](https://github.com/gregtwallace/certwarden) server and writes them to disk. On certificate change it can run an arbitrary shell command (e.g. to reload a service).

### Startup flow

`main` → `config.Load` → `logger.SetupLogging` → `app.Run`

`app.Run` builds one `worker.CertJob` per configured certificate, hands them to `scheduler.NewJobManager`, then blocks on SIGINT/SIGTERM.

### Job lifecycle (`pkg/scheduler/jobmanager.go`)

At startup, up to 5 workers pull jobs from a channel and run each job's **bootstrap phase**: call `job.Run` and retry with exponential backoff (1 s → 1 min, with jitter) until it succeeds. After a successful bootstrap the job is registered with `gocron` to repeat on its `RunInterval`.

### Per-job execution (`pkg/worker/worker.go`)

`CertJob.Run` is the core loop for one certificate:
1. Fetch the requested content from the CertWarden API (`pkg/api/api.go`), using `X-Api-Key` auth.
2. Load the existing file from disk (returns empty if missing).
3. Compare old vs new using `compareKeys` / `compareCertificates` (SHA256 fingerprint multiset equality for certs, serialized PKCS8 byte equality for keys).
4. Write to disk only if changed (or if no existing file), using `saveToFile` / `saveCertKeyChainToFile`. In split mode, `saveCertKeyChainToFile` writes two files derived from the path prefix.
5. If the file changed and `OnRefreshCmd` is set, run it via `bash -c`.

The combined auth token for multi-part downloads (cert+key) is `certAPIToken + "." + keyAPIToken`.

### Certificate kinds

Configured via `kind:` in YAML. Each kind maps to a CertWarden API endpoint and a default filename pattern:

| kind | API path | default filename |
|---|---|---|
| `privatekey` | `/privatekeys/` | `<name>_privkey.pem` |
| `certificate` | `/certificates/` | `<name>_fullchain.pem` |
| `privatecertchain` | `/privatecertchains/` | `<name>_keyfullchain.pem` |
| `pfx` | `/pfx/` | `<name>_bundle.p12` |
| `privatecert` | `/privatecerts/` | `<name>_keycert.pem` |
| `certrootchain` | `/certrootchains/` | `<name>_rootchain.pem` |

### Split mode

When `splitKeyAndCert: true` is set on a certificate entry, the key and certificate are written to separate files instead of a single combined file. Only supported for `privatecert` and `privatecertchain` kinds. `filenamePrefix` is used as a path prefix: the key is saved as `<prefix>_privkey.pem` and the cert as `<prefix>_fullchain.pem` (`privatecertchain`) or `<prefix>_cert.pem` (`privatecert`). If `filenamePrefix` is unset, files are saved without a prefix (e.g. `privkey.pem` / `fullchain.pem`) directly in `storePath`. Setting `filename` has no effect when `splitKeyAndCert: true`. The private key file always has its permissions masked with `& 0740` to restrict access below what `permissions` specifies.

### Config (`pkg/config/config.go`)

Two-level YAML: `global` block (defaults for all certs) and a `certificates` list. Per-certificate values override globals. `refreshPeriod` and `jobTimeout` accept any string parseable by `fortio.org/duration` (e.g. `1w2d3h`). `permissions` is an octal integer (e.g. `0640`). The only required field is `global.certWardenURL`.

`filename` sets the output filename explicitly. `filenamePrefix` sets a prefix used to build the default filename (`<prefix>_<kind-default>`); when `splitKeyAndCert: true`, `filenamePrefix` is also used to derive the per-file names. `filename` takes precedence over `filenamePrefix` for non-split mode.

### Packaging

CI (`.gitlab-ci.yml`) builds Debian packages for amd64 and arm64 using `debuild` and publishes them to the GitLab generic package registry on every git tag. The `debian/` directory contains standard Debian packaging files including a systemd unit and sysusers entry for a dedicated `certwarden-client` system user.