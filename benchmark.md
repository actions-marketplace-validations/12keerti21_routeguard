# Benchmark

How well routeguard finds real authorisation bugs, and how much noise it makes on well-built apps.

## 1. Existing scanners miss authorisation bugs

[VAmPI](https://github.com/erev0s/VAmPI) is a deliberately vulnerable API with nine documented bugs.
Each was checked by hand, then scanned with Semgrep (`p/security-audit` and `p/owasp-top-ten`, 233 rules)
and Bearer (88 rules).

| Bug | OWASP API 2023 | Semgrep | Bearer | routeguard |
|---|---|---|---|---|
| Any user reads another user's book secret | API1 BOLA | ❌ | ❌ | ✅ |
| Register as admin with `"admin": true` | API3 Mass assignment | ❌ | ❌ | ✅ |
| Change another user's password | API1 BOLA | ❌ | ❌ | ✅ |
| SQL injection in user lookup | API8 Injection | ❌ | ❌ | ❌ (not an authorisation check) |
| Debug endpoint lists every user and password | API3 Data exposure | ❌ | ❌ | ✅ |
| User and password enumeration | API2 Broken authentication | ❌ | ❌ | ❌ |
| Regex denial of service on email update | API4 Resource consumption | ❌ | ❌ | ❌ |
| No rate limit on login | API4 Resource consumption | ❌ | ❌ | ✅ |
| Weak JWT signing key | API2 Broken authentication | ✅ | ❌ | ✅ |
| **Found** | | **1 of 9** | **0 of 9** | **6 of 9** |

routeguard reads VAmPI's routes from its OpenAPI spec (connexion) and also flags `app.run(debug=True)`.
Run live, `verify` confirmed the book BOLA (a second user read the first user's book), the password
leak on the debug endpoint, a Python traceback on a malformed id, and the missing login limit.

## 2. routeguard on vulnerable Express APIs

Bugs documented by each project, and whether routeguard reports them.

| Target | Documented bug | Found |
|---|---|---|
| [vulnerable-rest-api](https://github.com/bnematzadeh/vulnerable-rest-api) | BOLA on `GET /api/users/:name` and `PUT /api/users/:id` | ✅ |
| | Function-level authorisation on book and author create, edit and delete | ✅ |
| | Mass assignment on `POST /api/users` | ✅ |
| | SSRF on `PUT /api/users/:id` | ✅ |
| | Old development copy of `GET /api/users` without auth | ✅ |
| [APIGOAT](https://yusufarbc.github.io/apigoat) | API1 BOLA on file routes | ✅ |
| | API3 property-level authorisation and `isAdmin` from the body | ✅ |
| | API5 function-level authorisation on books | ✅ |
| | API6 unthrottled bookings | ✅ |
| | API7 SSRF on `/weather` | ✅ |
| | API8 open CORS and a debug endpoint | ✅ |
| | API10 third-party data relayed unchecked | ✅ |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | View another user's basket | ✅ |
| | Exposed metrics | ✅ |
| | SSRF through the profile image URL | ✅ |
| | Forged coupons (no limit on coupon redemption) | ✅ |
| | Brute-forceable login | ✅ |

Bugs routeguard also found that the projects do not list:

- vulnerable-rest-api: any signed-in user can delete any user; logs and a key are served without auth;
  login and sign-up return the password hash; JWT verification accepts both RS256 and HS256 (algorithm
  confusion); the admin login has no rate limit.
- APIGOAT: an API key written into a URL.
- Juice Shop: checking out another user's basket, and editing another user's basket items.

## 3. Static findings confirmed at runtime

`routeguard verify` against a live OWASP Juice Shop (Docker), with two ordinary customer accounts:

| Route | Verdict |
|---|---|
| `GET /rest/basket/:id` | CONFIRMED: the second user reads the first user's basket (static BOLA finding confirmed) |
| `GET /api/Users/:id` | CONFIRMED: the second user reads the first user's account (missed by static analysis: generic handler) |
| `GET /metrics`, `/rest/admin/application-configuration`, `/rest/admin/application-version` | CONFIRMED: reachable with no credentials (static BFLA findings confirmed) |
| `GET /api/Addresss/:id`, `GET /api/Cards/:id` | PROTECTED: the second user is refused (static analysis agreed) |
| Product reviews, delivery methods, order tracking, recycling | PUBLIC: open by design |

Fourteen routes replayed, including the static scan, in under a second.

The probes on the same run, with `--probe-rate-limits --probe-ssrf`:

| Probe | Verdict |
|---|---|
| Forged JWT | CONFIRMED: a token with `alg: none` is accepted |
| SSRF | CONFIRMED: `POST /profile/image/url` fetched the URL sent in `imageUrl` |
| Rate limits | CONFIRMED: 20 wrong logins in a row on `/rest/user/login` and three passkey routes, none limited |
| Error leaks | CONFIRMED: a malformed id on `GET /api/Recycles/:id` returns a parser error |
| CORS | PUBLIC: `*` without credentials |
| Security headers | PROTECTED: `nosniff` set, framework not named |

## 4. Noise on real applications

Eighteen open-source Express apps, most of them well maintained. A good result here is few findings,
and HIGH findings that hold up when read by hand.

| App | Routes | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| [Overleaf](https://github.com/overleaf/overleaf) | 502 | 2 | 4 | 13 |
| [Ghost](https://github.com/TryGhost/Ghost) | 336 | 0 | 0 | 4 |
| [Directus](https://github.com/directus/directus) | 307 | 0 | 0 | 4 |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (vulnerable on purpose) | 124 | 8 | 9 | 6 |
| [NodeBB](https://github.com/NodeBB/NodeBB) | 118 | 1 | 4 | 2 |
| [hackathon-starter](https://github.com/sahat/hackathon-starter) | 103 | 0 | 1 | 1 |
| [Actual Budget](https://github.com/actualbudget/actual) (sync server) | 70 | 1 | 2 | 4 |
| [Kutt](https://github.com/thedevs-network/kutt) | 63 | 0 | 0 | 2 |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | 56 | 0 | 0 | 3 |
| [HedgeDoc 1.x](https://github.com/hedgedoc/hedgedoc) | 56 | 0 | 1 | 5 |
| [Verdaccio](https://github.com/verdaccio/verdaccio) | 55 | 0 | 0 | 3 |
| [Etherpad](https://github.com/ether/etherpad-lite) | 40 | 1 | 0 | 8 |
| [mongo-express](https://github.com/mongo-express/mongo-express) | 32 | 0 | 0 | 1 |
| [AfterAcademy backend](https://github.com/afteracademy/nodejs-backend-architecture-typescript) | 30 | 0 | 0 | 2 |
| [RealWorld example](https://github.com/gothinkster/node-express-realworld-example-app) | 20 | 0 | 1 | 3 |
| [node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) | 15 | 0 | 0 | 1 |
| [express-rest-boilerplate](https://github.com/danielfsousa/express-rest-boilerplate) | 15 | 0 | 4 | 3 |
| [bulletproof-nodejs](https://github.com/santiq/bulletproof-nodejs) | 6 | 0 | 2 | 2 |
| **Total** | **1,948** | **13** | **28** | **67** |

Every HIGH and MEDIUM outside Juice Shop was read by hand:

| Finding | Verdict |
|---|---|
| Overleaf: `/debug/events` and `/metrics` without auth on internal services | Real. Safe only while those services stay off the public network. |
| Actual: `/metrics` (memory and uptime) without auth | Real, low impact |
| Etherpad: the admin API's OpenAPI spec is public | Real, low impact |
| Boilerplates and RealWorld: login, sign-up and reset routes with no rate limit | Real |
| hackathon-starter: a search term placed into a fixed API host's URL | Real, low impact |
| Overleaf: first-admin setup with no rate limit | Real, low impact: it works once |
| NodeBB: error objects returned by the asset minifier | Real, low impact |
| NodeBB: `/api/config` is public | By design: the browser client needs it |
| NodeBB: login and registration with no rate limiter | Arguable: NodeBB locks accounts after failed attempts instead |
| Actual: bank-sync steps any signed-in user can run | Arguable: depends on multi-user mode |
| Overleaf and NodeBB: development routes (Overleaf's `/dev/csrf`, a NodeBB debug route) | By design: development only |
| HedgeDoc: redirect to the URL GitHub's API returns | Fair, though the provider is trusted |

No HIGH or MEDIUM finding was a plain false positive. Scanning all 18 apps (1,948 routes) takes about 12 seconds on a laptop.

Not included: Wiki.js 3 is built on Fastify, and routeguard says so and stops trusting its own results
there; Habitica registers its routes through its own framework, so only a handful are visible.

## 5. Go

The same checks on Go: deliberately vulnerable apps, then open-source ones.

**A vulnerable `net/http` API** (in `tool/test/fixtures/go/nethttp`, standard library only) with seven
planted bugs and a safe twin of the main one. The static scan found all seven and left the safe route
alone. Run in Docker, `verify` with `--probe-rate-limits --probe-ssrf` confirmed every one of them:

| Bug | Static | Runtime |
|---|---|---|
| Any user reads any order (`GET /api/orders/{id}`) | BOLA | CONFIRMED: the second user got the first user's order |
| Password hash in `GET /api/me` | DATA_EXPOSURE | CONFIRMED: `passwordHash` in the answer |
| Server fetches `?url=` | SSRF | CONFIRMED: the listener was called |
| Origin echoed with credentials | CORS (HIGH) | CONFIRMED |
| Stack trace on a malformed id | ERROR_LEAK | CONFIRMED: a goroutine trace in the answer |
| Token signature never checked | (not visible statically) | CONFIRMED: an `alg: none` token was accepted |
| `/dev/vars` left in | NON_PROD_ROUTE | CONFIRMED: answers anyone |
| Login with no limiter | RATE_LIMIT | CONFIRMED: 20 wrong logins, none limited |

**Vulnerable and example apps.** On OWASP crAPI's Go service, routeguard flags the coupon flows
(business logic) and the post lookup by id. The Gin, Echo and Fiber RealWorld examples come out with
their login rate limit and a few public lookups; the Gin one checks authorship before every edit, and
routeguard agrees.

**Open-source Go apps:**

| App | Framework | Routes | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| [Gitea](https://github.com/go-gitea/gitea) | chi (own wrapper) | 1,222 | 5 | 16 | 178 |
| [Mattermost](https://github.com/mattermost/mattermost) | gorilla/mux | 843 | 23 | 2 | 59 |
| [Vikunja](https://github.com/go-vikunja/vikunja) | Echo | 202 | 9 | 3 | 16 |
| [listmonk](https://github.com/knadh/listmonk) | Echo | 191 | 2 | 0 | 13 |
| [PhotoPrism](https://github.com/photoprism/photoprism) | Gin | 183 | 1 | 0 | 51 |
| [Woodpecker CI](https://github.com/woodpecker-ci/woodpecker) | Gin | 182 | 4 | 3 | 21 |
| [Miniflux](https://github.com/miniflux/v2) | net/http | 179 | 0 | 5 | 3 |
| [Gotify](https://github.com/gotify/server) | Gin | 46 | 2 | 1 | 6 |
| [Gin RealWorld](https://github.com/gothinkster/golang-gin-realworld-example-app) | Gin | 27 | 0 | 1 | 3 |
| [Echo RealWorld](https://github.com/xesina/golang-echo-realworld-example-app) | Echo | 20 | 0 | 2 | 3 |
| [Fiber RealWorld](https://github.com/alpody/golang-fiber-realworld-example-app) | Fiber | 20 | 0 | 4 | 3 |
| [ntfy](https://github.com/binwiederhier/ntfy) | net/http | 13 | 0 | 0 | 12 |
| [OWASP crAPI](https://github.com/OWASP/crAPI) (community service) | gorilla/mux | 11 | 0 | 4 | 4 |
| [memos](https://github.com/usememos/memos) | net/http (mostly gRPC) | 11 | 0 | 0 | 5 |

| Finding | Verdict |
|---|---|
| Mattermost, Vikunja, Woodpecker: `/debug/pprof` and `/metrics` without a role check | Real while those listeners are reachable; most are behind a setting |
| Mattermost: `GET /redirect_location` makes a HEAD request to a client URL | Mitigated: it runs only with link previews on, through an HTTP client built to refuse internal addresses |
| Mattermost: `/system/e2e/*` test helpers | Real routes, disabled unless testing is switched on |
| Gitea: Actions artifact routes and LFS verify reading by run or repo id | Arguable: a runner token or LFS token gates them, checked deeper than routeguard follows |
| listmonk, Gotify: `config` routes with no role check | Arguable: per-user plugin or client config |
| Miniflux: `GET /v1/feeds/{feedID}` returns the feed's basic-auth password | Real, low impact: the owner gets back the credentials they saved for that feed |
| Woodpecker: a CLI helper that echoes any origin with credentials | Real code, but in the CLI's local login helper, not the server |

Scanning all 14 Go apps (about 3,150 routes) takes about 30 seconds on a laptop. Routes behind a
setting (`if setting.EnablePprof { ... }`) are reported LOW and say which setting.

## 6. Python

Flask (with blueprints, Flask-RESTful and connexion), FastAPI and Django REST Framework.

**Deliberately vulnerable apps.** VAmPI: 6 of 9 (section 1). we45's Vulnerable Flask App: both
customer lookups by id (one by URL, one by an id in the JSON body), the card numbers they return, a JWT
decoded without verifying the signature and a secret key in the code. OWASP crAPI's Django workshop:
the documented mechanic-report BOLA (`?report_id=`), service requests any mechanic can change, a JWT
decoded without verification and `debug=True`. The Django RealWorld example: articles any user can
update and comments any user can delete, both known gaps in that example.

**Open-source Python apps:**

| App | Framework | Routes | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| [NetBox](https://github.com/netbox-community/netbox) | Django REST Framework | 948 | 0 | 1 | 3 |
| [Mealie](https://github.com/mealie-recipes/mealie) | FastAPI | 285 | 0 | 4 | 4 |
| [CTFd](https://github.com/CTFd/CTFd) | Flask | 245 | 2 | 0 | 7 |
| [Healthchecks](https://github.com/healthchecks/healthchecks) | Django | 178 | 0 | 1 | 9 |
| [Redash](https://github.com/getredash/redash) | Flask-RESTful | 126 | 1 | 4 | 5 |
| [Paperless-ngx](https://github.com/paperless-ngx/paperless-ngx) | Django REST Framework | 110 | 0 | 2 | 3 |
| [Wagtail](https://github.com/wagtail/wagtail) | Django | 62 | 0 | 0 | 3 |
| [Full Stack FastAPI Template](https://github.com/tiangolo/full-stack-fastapi-template) | FastAPI | 23 | 0 | 3 | 1 |
| [Django RealWorld](https://github.com/gothinkster/django-realworld-example-app) | Django REST Framework | 21 | 4 | 2 | 2 |
| [FastAPI RealWorld](https://github.com/nsidnev/fastapi-realworld-example-app) | FastAPI | 19 | 0 | 1 | 2 |

| Finding | Verdict |
|---|---|
| CTFd: `app.run(debug=True)` in `serve.py` and `wsgi.py` | Real, but only when started by hand for development |
| Redash: `GET /api/config` without auth | By design: the browser client needs it |
| Redash: query API keys in alert and dashboard answers | Arguable: users with access to the query may use its key |
| FastAPI template, Mealie, Paperless, NetBox: login, reset and TOTP routes with no rate limit | Real or arguable: some limit at the proxy |

Every HIGH and MEDIUM was read by hand; none was a plain false positive. The rules know the patterns
these apps use to stay safe: DRF querysets restricted in a base view, repositories built per group,
`get_by_id_and_org(id, current_org)`, `require_admin_or_owner(record.user_id)`, ownership comparisons,
object permission classes, signed badge links and settings-guarded debug views. Scanning the ten apps
(2,081 Python routes across all fourteen targets) takes about 8 seconds.


## 7. Nine more open-source APIs

Nine apps not used while building routeguard, scanned with 2.1.0 and read by hand. 2.1.0 reported
about 60 HIGH findings across them; every one was a routeguard false positive, and 2.1.1 fixes them.

| App | Language | Routes | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| [n8n](https://github.com/n8n-io/n8n) | TypeScript (decorator controllers) | 1,106 | 8 | 14 | 31 |
| [Baserow](https://github.com/baserow/baserow) | Python (DRF) | 807 | 0 | 16 | 18 |
| [Plane](https://github.com/makeplane/plane) | Python (DRF) | 712 | 0 | 19 | 10 |
| [Label Studio](https://github.com/HumanSignal/label-studio) | Python (DRF) | 297 | 0 | 0 | 1 |
| [Gogs](https://github.com/gogs/gogs) | Go (flamego) | 277 | 0 | 9 | 68 |
| [Navidrome](https://github.com/navidrome/navidrome) | Go (chi) | 179 | 0 | 3 | 55 |
| [linkding](https://github.com/sissbruecker/linkding) | Python (Django) | 68 | 0 | 0 | 2 |
| [PocketBase](https://github.com/pocketbase/pocketbase) | Go | 54 | 0 | 0 | 11 |
| [Parse Server](https://github.com/parse-community/parse-server) | JavaScript | 5 | 0 | 0 | 1 |

What 2.1.0 got wrong, and 2.1.1 now handles:

- Go: flamego and macaron routers, PocketBase's own router, method calls resolved by receiver and
  struct field type (so an app's `store.GetByID` is followed, not taken as a raw database read),
  optional auth middleware.
- Python: a hard-coded `SECRET_KEY` replaced by a production settings file, a discarded
  `jwt.decode`, CORS with an origin allow-list, ownership checks delegated to helpers.
- Express: client calls in promise chains (`return api.get(...)`) read as routes, CORS set up only
  in development code.
- All languages: health and version probes, `GET /metrics` (now MEDIUM), writes keyed only by UUIDs
  (now MEDIUM).

Since then routeguard also reads decorator controllers (NestJS `@Controller`, routing-controllers,
n8n's `@RestController`, with `@Param`, `@CurrentUser`, `@UseGuards`, `@Public` and global guards)
and Django urlconfs built from splatted lists, reassigned `urlpatterns` and `decorate_urlpatterns`.
That took n8n from 49 to 1,106 routes, Plane from 63 to 712 and linkding from 2 to 68.

n8n's 8 HIGHs: `GET /rest/debug/multi-main-setup` skips auth on purpose and is worth a look; the
two dynamic-credential BOLAs are false positives (a middleware checks a token, but its name does not
say so); the five BFLAs come from route names (`/agents/system`, `/gateway/config`) and are
arguable. Most remaining MEDIUMs are login, reset and verification routes with no rate limit, which these apps
may limit at the proxy. The Navidrome BOLAs are false positives: the ownership check sits behind a
repository interface routeguard does not follow. The Gogs BOLAs and BFLAs are not yet confirmed
either way.

**Coverage gaps.** Parse Server registers its routes through its own router classes, so only 5 are
mapped, and PocketBase routes lack their `/api` prefix. Findings on those two apps cover only the
routes routeguard maps.
