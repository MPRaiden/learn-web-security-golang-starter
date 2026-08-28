# Bearly Secure

Bearly Secure is the intentionally vulnerable starter app for Learn Web Security in Go. It's a tiny plushie shop built with Go, `net/http`, and SQLite.

> [!IMPORTANT]
>
> This README describes the freshly cloned starter project from lesson 1.2. Course assignments will change the app's behavior, but this file remains a reference for the initial baseline.

## Requirements

- Go 1.27.0 or newer

## Run the Starter

Seed the local database:

```sh
go run ./cmd/seed
```

Start the app at <http://localhost:3030>:

```sh
go run ./cmd/server
```

## Attacker Lab

In another terminal, start the browser-based attacker lab at <http://localhost:4040>:

```sh
go run ./cmd/attackerlab
```

It runs as a separate process and stays on a separate origin so you can explore cross-origin browser security behavior.

## Project Checks

Run the test suite:

```sh
go test ./...
```

Check static analysis:

```sh
go vet ./...
```

You can restore the deterministic starter data at any time with `go run ./cmd/seed`.

## Baseline Features

- Public storefront with product listing, search, detail pages, and reviews
- Account creation, login, logout, password reset, and session cookies
- Account profiles, order history, review management, and tax-document uploads
- Authenticated shopping cart and checkout with simulated PawPal and Acorn integrations
- Support and admin areas for order, tax-document, and product workflows
- JSON product and order APIs
- Browser attacker lab and embedded shipping widget
- Deterministic local order-assistant simulation
- SQLite seed data, local file storage, and JSON-lines application logs
- Single-stage container build that runs the Go source directly

## Security Warning

Bearly Secure is deliberately unsafe. It contains exploitable authentication, authorization, injection, browser-security, data-exposure, infrastructure, and operational weaknesses for course exercises.

Do not deploy it or use its security patterns in a real application. Its credentials, integrations, payments, and third-party services are local simulations that use fake data only.

## Baseline Structure

- `cmd/server`: starts Bearly Secure
- `cmd/attackerlab`: starts the attacker lab
- `cmd/seed`: resets the deterministic SQLite data
- `internal/`: contains application behavior
- `internal/database/`: contains migrations, sqlc queries, and seed data
- `internal/httpserver/`: composes the HTTP server and middleware
- `internal/auth/`: contains authentication, session, TOTP, passkey, and access-control helpers
- `internal/integrations/`: contains simulated external-service integrations
- `internal/uploads/`: contains upload metadata, middleware, and archive extraction
- `web/`: contains server-rendered templates and static assets
- `attacker-lab/`: contains the browser attacker lab assets
- `data/uploads/`: contains local uploads and the seeded sample tax exemption PDF
- `data/bulk-tax-documents/`: receives documents extracted from support ZIP imports
- `Dockerfile`: defines the initial single-stage container image
