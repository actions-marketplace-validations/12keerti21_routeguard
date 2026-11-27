# routeguard

**Find broken authorisation in Express, Go and Python APIs before attackers do.**

routeguard reads your Express, Go or Python code without running it. It maps every route to the checks that protect
it, then flags the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
risks that general code scanners miss. The biggest of these is one user reaching another user's data.

```
$ routeguard ./my-api

METHOD  PATH                 MIDDLEWARE   AUTH  ROLE  WHERE
GET     /api/orders/:id      auth         ✅     ❌     routes/orders.js:12
DELETE  /api/users/:id       auth, admin  ✅     ✅     routes/users.js:40
...

[HIGH] BOLA  GET /api/orders/:id  (services/order.service.js:18)
  API1:2023 Broken Object Level Authorization
  findById via getOrder uses an id from the URL, and nothing on the way checks it against the caller.
  Fix: scope the query to the caller: findOne({ _id: id, owner: req.user._id }).
```

## Why

Tools like Semgrep and Bearer are good at injection and secrets. Authorisation bugs are different:
the code looks fine line by line, and the flaw is a check that is *missing*. On a deliberately
vulnerable API, Semgrep found 1 of 9 bugs, Bearer found none and routeguard found 6 ([benchmark](https://github.com/12keerti21/routeguard/blob/main/benchmark.md)).

## What it checks

| OWASP API 2023 | Check |
|---|---|
| API1 Broken Object Level Authorization | A record is loaded or changed by a URL id, and nothing on the way checks it belongs to the caller. Follows the id into service functions. |
| API2 Broken Authentication | JWT algorithm confusion, `alg: none`, ignored expiry, signing keys in the code |
| API3 Broken Object Property Level Authorization | Whole request bodies written to records (`new User(req.body)`), `isAdmin` taken from the client, whole user records sent back |
| API4 Unrestricted Resource Consumption | Login, OTP, reset and sign-up routes with no rate limit |
| API5 Broken Function Level Authorization | Admin, debug, metrics and log routes with no role check; shared data any user can change |
| API6 Unrestricted Access to Sensitive Business Flows | Checkout, coupon, booking and review flows with nothing against bots |
| API7 Server Side Request Forgery | The server fetches a URL the client chose |
| API8 Security Misconfiguration | CORS open to any origin with credentials, stack traces in responses, missing security headers |
| API9 Improper Inventory Management | Old or development copies of an endpoint with weaker checks, routes missing from the OpenAPI spec |
| API10 Unsafe Consumption of APIs | Third-party responses stored, run or redirected to without validation; plain-http calls; API keys in URLs |

## Use it

```bash
npx routeguard-cli <path-to-your-api>
```

Or install it with `npm install -g routeguard-cli` and run `routeguard`. From a clone of this repo:

```bash
cd tool && npm install
node bin/cli.js <path-to-your-api>                 # table and findings
node bin/cli.js <path-to-your-api> --json          # machine-readable
node bin/cli.js <path-to-your-api> --sarif         # for GitHub code scanning
node bin/cli.js <path-to-your-api> --fail-on HIGH  # exit 2 only on HIGH findings
```

Requires Node 20 or later, and no Go toolchain. It reads:

- **Express**: JavaScript and TypeScript, `require` and `import`, monorepos and package.json `#imports`.
- **Decorator controllers**: NestJS `@Controller` (with `@UseGuards`, `@Public`, `APP_GUARD` and
  `setGlobalPrefix`), routing-controllers and n8n's `@RestController`.
- **Go**: Gin, Echo, Fiber, chi, gorilla/mux, httprouter and `net/http` (including Go 1.22 patterns such
  as `"GET /items/{id}"`). Routers are followed through groups, sub-routers, mounts, routers kept in
  struct fields and routers passed to other packages; middleware is read from `Use`, group arguments,
  wrapped handlers (`auth(h)`) and wrapped muxes (`auth(mux)`), and auth checks made first thing in a
  handler count too.
- **Python**: Flask (blueprints, `add_url_rule`, Flask-RESTful and RESTX resources, MethodView, and
  connexion's OpenAPI `operationId` routes), FastAPI (`include_router` prefixes, router and route
  dependencies, `Depends` and `Annotated` parameters, class-based controllers) and Django with Django REST
  Framework (`ROOT_URLCONF`, `include`, routers and ViewSets, `@action`, generic views, permission
  classes and `DEFAULT_PERMISSION_CLASSES`, login and permission decorators and mixins).

Go and Python are parsed with tree-sitter, so no Go or Python install is needed, and a repository with
several languages gets all of them.

### Confirm findings against a running app

Static analysis says where a check *looks* missing. `verify` proves it: it replays routes against a
running test instance as two real users and compares the answers.

```bash
npx routeguard-cli verify ./my-api --base-url http://localhost:3000 --config verify.json
```

```json
{
  "users": {
    "owner": { "login": { "path": "/api/login", "body": { "email": "alice@test.local", "password": "${ALICE_PASSWORD}" }, "token": "token" } },
    "other": { "headers": { "Authorization": "Bearer ${BOB_TOKEN}" } }
  },
  "routes": { "/api/cards/:id": { "id": "7" } }
}
```

- **Ids are found for you.** For a route like `/notes/:id`, routeguard reads `GET /notes` as both users
  and picks an id only the owner sees, so the test uses a record that is really the owner's. Nested
  routes are filled one level at a time. Ids in `params` (by name) or `routes` (per route) win, and
  `"discover": false` turns this off. When the only id is one both users can list, a matching answer is
  reported as inconclusive, since reading a shared record may be allowed.
- `owner` owns the ids in `params`; `other` is a second ordinary user. `${NAME}` reads environment
  variables, so passwords stay out of the file.
- Every route that takes an id, and every operator route a static finding flagged, is requested as the
  owner, as the other user and with no credentials.
- Verdicts: **CONFIRMED** (someone got in who should not), **PUBLIC** (open to anyone and the code asks
  for no login), **PROTECTED** (the other user was refused), **INCONCLUSIVE**, **SKIPPED** (no id given).
- Reads only by default. `--allow-writes` also replays PUT, PATCH, DELETE and POST: use a disposable
  test environment.

**Logins with several steps, one-time codes and DPoP.** A user's `login` can be a list of steps: each
can `save` values from its answer for the next step (`{{name}}`), and `{{prompt:label}}` asks for a
value such as an emailed code when the run reaches it. Set `"dpop": true` for apps that bind tokens to a
client key (RFC 9449): routeguard keeps a key per user and signs a fresh proof for every request.
`dpopOrigin` is the origin the app expects in the proof, when it differs from `--base-url`.

```json
{
  "dpopOrigin": "http://localhost:5173",
  "users": {
    "owner": {
      "dpop": true,
      "login": [
        { "path": "/api/v1/auth/login", "body": { "email": "alice@test.local", "password": "${ALICE_PASSWORD}" }, "save": { "lt": "login_token" } },
        { "path": "/api/v1/auth/login/verify", "body": { "login_token": "{{lt}}", "otp": "{{prompt:Code emailed to Alice}}" }, "token": "access_token" }
      ]
    }
  }
}
```

Prompts read from the terminal, or one answer per line from standard input when another program runs
the check. Two users getting the same *empty* answer is reported as inconclusive, not as a leak.
Set `"cookie": "token"` on a user when the app also reads the token from a cookie of that name.

**Probes beyond access control.** After the replay, `verify` checks the rest of the list on the running
app. These only read, and always run:

| Probe | OWASP | What it does |
|---|---|---|
| CORS | API8 | Sends a foreign `Origin`. Confirmed when the app echoes it with `Allow-Credentials: true`. |
| Security headers | API8 | Looks for `X-Powered-By`, a missing `nosniff`, and missing HSTS on https. |
| Data exposure | API3 | Looks for secret fields (`password`, `passwordHash`, `apiKey`, `resetToken`…) in the real answers. Reports the field names, never the values. |
| Error leaks | API8 | Requests id routes with a malformed id and looks for stack traces and database driver errors. |
| Forged JWT | API2 | Sends the owner's token with `alg: none`, and with a changed claim and the old signature. Confirmed when either is accepted. |
| Development routes | API9 | Requests the routes the scan flagged as development-only, without credentials. |

Two probes send requests that can have effects, so they run only when asked:

- `--probe-rate-limits` (API4): sends 20 wrong logins for a made-up account to each login, OTP and
  reset route the scan flagged. Protected when the app answers 429, 423 or `Retry-After`.
- `--probe-ssrf` (API7): starts a listener on this machine and sends its URL, as the owner, in the
  field the scan found the server fetching (as JSON, then as a form). Confirmed when the app calls it.
  When the app runs in Docker, add `--canary-host host.docker.internal` (or `canaryHost` in the config).

### In GitHub Actions

```yaml
name: routeguard
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 20
      - id: routeguard
        uses: 12keerti21/routeguard@v2
        with:
          path: .
          fail-on: HIGH
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        if: always()
        with:
          sarif_file: ${{ steps.routeguard.outputs.sarif-file }}
```

Findings appear on the pull request and under **Security → Code scanning**.

### Silence a reviewed finding

Put a comment in the three lines above the route:

```js
// the share id is unguessable and is the key
// routeguard-ignore BOLA
router.get("/shared/:shareId", getSharedNote)
```

Leave out the rule name to silence every rule for that route.

## How it works

1. **Map the routes.** Parses every source file and follows `app.use` and `router.use` mounts, so each
   route gets its full path and every middleware in front of it, including middleware applied to a
   whole path or router.
2. **Read the handlers.** Finds each route's handler, even in another file, a controller object or a
   wrapper like `catchAsync(...)`.
3. **Follow the data.** For object-level checks, traces the URL id from the handler into the
   services it calls. It looks for the caller (`req.user`, `c.Get("userID")`, `ctx.Value(userKey)`)
   limiting that id along the way: in the query, in a comparison, or in a check such as
   `canEdit(user, course)`.
4. **Report.** Each finding has a severity, the OWASP category, the file and line, and a fix.

## Limits

- Static analysis trusts what a check returns. If `canEdit()` itself has a logic bug, only `verify` against a running app will show it.
- Probes only see what the sampled routes return: a clean result means none of those leaked, not that no route does.
- Static analysis cannot know an id is unguessable. Capability links need a `routeguard-ignore` comment.
- Express, decorator controllers, Go and Python only for now. Fastify, Koa and hapi get a warning instead of results.
- Python routes registered through a project's own routing layer, or added dynamically, may be missed.
- Go routes registered from data at runtime, or through a project's own routing layer, may be missed or left with an unresolved `<prefix>`.

## Results

Tested on deliberately vulnerable APIs, 18 open-source Express apps (about 1,950 routes), 14 Go apps
(about 3,150 routes) and 14 Python apps (about 2,080 routes). See
[benchmark.md](https://github.com/12keerti21/routeguard/blob/main/benchmark.md).

## Development

```bash
cd tool && npm test
```

Tests run every check against a small fixture app that has a vulnerable and a safe version of each
pattern.
