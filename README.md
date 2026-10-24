# Roast Report (self-hosted)

A personal coffee log: wishlist, pantry, what you're brewing now, and past roasts, with
photos, cup-by-cup ratings, price per cup / per 100g, tasting notes and stats.

This is the self-hosted edition. It runs as one small container with its own accounts and
an SQLite database, so there is nothing to sign up for and no external services.

## Quick start (Portainer)

1. Push this repo to GitHub. The included workflow builds the image automatically
   (`ghcr.io/<your-username>/roast-report:latest`).
2. Make the package public (GitHub profile -> Packages -> roast-report -> Package settings ->
   Change visibility), so Portainer can pull it without credentials.
3. Edit `docker-compose.yml`: replace `YOUR_GITHUB_USERNAME` with your username.
4. In Portainer: **Stacks -> Add stack -> Web editor**, paste the file, **Deploy the stack**.
5. Open `http://<server-ip>:8085` and create an account.

## Settings

Set these under `environment:` in the compose file.

| Variable        | Default | What it does                                                        |
|-----------------|---------|---------------------------------------------------------------------|
| `ALLOW_SIGNUP`  | `true`  | Set to `false` to stop anyone creating new accounts                 |
| `COOKIE_SECURE` | `false` | Set to `true` only when you serve the app over HTTPS                |
| `TRUST_PROXY`   | `false` | Set to `true` behind a reverse proxy so rate limiting sees real IPs |
| `TZ`            | (UTC)   | Container time zone, e.g. `Europe/London`                           |

## Accounts

Each user has their own username, password and coffee list. If someone forgets a password,
open the container's console in Portainer (Containers -> roast-report -> Console, shell `/bin/sh`)
and run:

```sh
node server.js list-users
node server.js reset-password <username> <new-password>
node server.js delete-user <username>
```

## Your data

Everything lives in one SQLite file inside the `roast-report-data` volume
(`/data/roastreport.db`). Updating or redeploying the stack does not touch it.

- **Update to a newer version:** Portainer -> Stacks -> roast-report -> *Pull and redeploy*.
- **Back up:** stop the stack and copy the volume, or snapshot it with TrueNAS.

## Your logo

Drop your own `logo.webp` into the `public/` folder before building. If there isn't one, a
simple placeholder badge is shown instead.

## Running without Docker

Needs Node.js 22.13 or newer. There are no dependencies to install.

```sh
node server.js          # http://localhost:8080, data in ./data
```

## What's in the repo

| File                                  | Purpose                                         |
|---------------------------------------|-------------------------------------------------|
| `server.js`                           | Web server, accounts, per-user storage          |
| `public/index.html`                   | The app                                         |
| `public/login.html`                   | Sign-in / create account page                   |
| `Dockerfile`                          | Builds the image                                |
| `docker-compose.yml`                  | The file you paste into Portainer               |
| `.github/workflows/docker-publish.yml`| Builds and publishes the image on every push    |
