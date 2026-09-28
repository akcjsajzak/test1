# Installation on Debian

`web-auth-auditor` runs on a recent Debian/Ubuntu system with Node.js 20+ and a
Chromium build. Installation is reproducible via `npm ci` and a lockfile.

## 1. System packages

```bash
sudo apt-get update
# Node.js 20+ (via NodeSource, or your preferred method)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Chromium and its runtime libraries. Either the distro package …
sudo apt-get install -y chromium               # Debian: provides /usr/bin/chromium
# … or on Ubuntu:
# sudo apt-get install -y chromium-browser
```

The auditor auto-detects a Chromium executable in this order:

1. `browser.executablePath` from the config,
2. `$PLAYWRIGHT_CHROMIUM_EXECUTABLE` or `$CHROMIUM_PATH`,
3. `/opt/pw-browsers/chromium` (Playwright cache),
4. `/usr/bin/chromium`, `/usr/bin/chromium-browser`, `/usr/bin/google-chrome`.

If none is found, it falls back to Playwright's browser registry (see step 3b).

## 2. Install the project

```bash
git clone <your-fork-or-copy> web-auth-auditor
cd web-auth-auditor
npm ci          # reproducible install from package-lock.json (also builds)
```

`npm ci` runs the `prepare` script, which compiles TypeScript to `dist/`.

### 3a. Using a system Chromium (recommended on servers)

Point the config at it (or rely on auto-detection):

```yaml
browser:
  executablePath: "/usr/bin/chromium"
```

### 3b. Using Playwright-managed Chromium

If you prefer Playwright to manage the browser binary:

```bash
npx playwright install --with-deps chromium
```

This installs Chromium and its OS dependencies into Playwright's cache; the
auditor then finds it automatically (leave `browser.executablePath` unset).

## 4. Headless / sandbox notes

- The engine launches with `--no-sandbox --disable-dev-shm-usage` so it works in
  containers and CI. On a hardened multi-user host, prefer running it as an
  unprivileged, dedicated user.
- For visible debugging, pass `--headful` on the CLI (requires an X server /
  Xvfb).

## 5. Verify the installation

Run the bundled vulnerable test app and scan it:

```bash
# Terminal 1 — start the fixture app
PORT=4123 npm run test:app

# Terminal 2 — scan it
USER_A_SESSION=token_user_a USER_B_SESSION=token_user_b ADMIN_SESSION=token_admin \
  node dist/cli.js scan --config examples/localhost.yaml --output ./results
```

(Or simply run `npm test`, which starts the app in-process and asserts the
expected findings end to end.)
