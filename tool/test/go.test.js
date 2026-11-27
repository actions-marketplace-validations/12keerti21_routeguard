import { test } from "node:test"
import assert from "node:assert/strict"
import { mapGoRoutes } from "../src/go/mapper.js"
import { GO_RULES } from "../src/go/rules.js"
import { goAppRules } from "../src/go/app.js"
import { bfla } from "../src/rules/bfla.js"
import { rateLimit } from "../src/rules/rateLimit.js"
import { inventory } from "../src/rules/inventory.js"

const fixture = name => new URL(`./fixtures/go/${name}`, import.meta.url).pathname

async function scan(name) {
	const routes = await mapGoRoutes(fixture(name))
	const byRoute = new Map(routes.map(r => [`${r.method} ${r.path}`, r]))
	const findings = [
		...routes.flatMap(r => [...GO_RULES, bfla, rateLimit].map(rule => rule(r)).filter(Boolean)),
		...inventory(routes, fixture(name)),
		...goAppRules(routes)
	]
	const has = (rule, route) => findings.some(f => f.rule === rule && (route === undefined || f.route === route))
	return { routes, byRoute, findings, has }
}

test("gin: groups, Use order, routers passed to other packages, and route middleware", async () => {
	const { byRoute } = await scan("gin")
	assert.deepEqual([...byRoute.keys()].sort(), [
		"DELETE /api/orders/:id",
		"GET /api/admin/stats",
		"GET /api/metrics",
		"GET /api/orders/:id",
		"GET /api/orders/:id/safe",
		"GET /api/profile",
		"POST /api/login",
		"PUT /api/profile"
	])
	// Use comes after /login, so login stays public
	assert.equal(byRoute.get("POST /api/login").auth, false)
	assert.equal(byRoute.get("GET /api/orders/:id").auth, true)
	assert.equal(byRoute.get("GET /api/admin/stats").role, true)
})

test("gin: BOLA through a helper, scoped queries, mass assignment and secrets in answers", async () => {
	const { has } = await scan("gin")
	assert.ok(has("BOLA", "GET /api/orders/:id"))
	assert.ok(has("BOLA", "DELETE /api/orders/:id"), "the id reaches Delete inside removeOrder")
	assert.ok(!has("BOLA", "GET /api/orders/:id/safe"), "the query is scoped to the caller")
	assert.ok(has("MASS_ASSIGNMENT", "PUT /api/profile"))
	assert.ok(has("DATA_EXPOSURE", "GET /api/profile"))
	assert.ok(has("BFLA", "GET /api/metrics"))
	assert.ok(!has("BFLA", "GET /api/admin/stats"))
	assert.ok(has("RATE_LIMIT", "POST /api/login"))
})

test("echo: route middleware after the handler, SSRF input and CORS with credentials", async () => {
	const { byRoute, findings, has } = await scan("echo")
	assert.equal(byRoute.get("GET /v1/fetch").auth, true)
	assert.equal(byRoute.get("GET /v1/public").auth, false)
	const ssrf = findings.find(f => f.rule === "SSRF")
	assert.deepEqual(ssrf.input, { in: "query", name: "url" })
	assert.ok(findings.some(f => f.rule === "CORS" && f.severity === "HIGH"))
	assert.ok(!has("BOLA"))
})

test("chi: Route closures, With, Mount of a router built in another function, and raw SQL", async () => {
	const { byRoute, has } = await scan("chi")
	assert.ok(byRoute.has("GET /internal/health"))
	assert.equal(byRoute.get("DELETE /api/docs/{docID}").role, true)
	assert.ok(has("BOLA", "GET /api/docs/{docID}"))
})

test("gorilla/mux: subrouters, Methods(), regex params and an ownership comparison", async () => {
	const { byRoute, has } = await scan("mux")
	assert.ok(byRoute.has("GET /api/items/{id}"))
	assert.ok(byRoute.has("GET /api/items/{id}/owner"), "{id:[0-9]+} becomes {id}")
	assert.ok(!byRoute.has("OPTIONS /api/items/{id}"), "the CORS preflight is not a second endpoint")
	assert.ok(!has("BOLA", "GET /api/items/{id}"), "item.OwnerID != user.ID guards it")
})

test("fiber: group middleware, a repository method, and a JWT key in the code", async () => {
	const { byRoute, findings, has } = await scan("fiber")
	assert.equal(byRoute.get("GET /api/invoices/:invoiceId").auth, true)
	assert.ok(has("BOLA", "GET /api/invoices/:invoiceId"))
	assert.ok(findings.some(f => f.rule === "JWT" && f.severity === "HIGH"))
})

test("net/http: method patterns, wrapped handlers and a wrapped mux", async () => {
	const { byRoute, findings, has } = await scan("nethttp")
	assert.equal(byRoute.get("GET /api/orders/{id}").auth, true)
	assert.equal(byRoute.get("POST /api/login").auth, false)
	assert.ok(has("BOLA", "GET /api/orders/{id}"), "an in-memory store read by the id")
	assert.ok(!has("BOLA", "GET /api/notes/{id}"), "note.UserID != userID guards it")
	assert.ok(has("DATA_EXPOSURE", "GET /api/me"))
	assert.ok(has("SSRF", "GET /api/avatar"))
	assert.ok(has("NON_PROD_ROUTE", "GET /dev/vars"))
	assert.ok(findings.some(f => f.rule === "CORS" && f.severity === "HIGH"))
	assert.ok(findings.some(f => f.rule === "ERROR_LEAK" && f.severity === "MEDIUM"))
})

test("flamego: groups with trailing middleware, receivers typed through calls and fields, and checks in middleware bodies", async () => {
	const { byRoute, findings, has } = await scan("flamego")
	assert.equal(byRoute.get("DELETE /api/notes/{id}").auth, true, "f.Group(prefix, fn, requireAuthenticated)")
	assert.equal(byRoute.get("GET /-/metrics").auth, true, "MetricsFilter checks basic auth in its body")
	assert.ok(!has("BFLA", "GET /-/metrics"))
	assert.ok(!has("BOLA", "DELETE /api/passkeys/{id}"), "db.Passkeys() returns *PasskeysStore, whose DeleteByID takes the caller")
	assert.ok(findings.some(f => f.rule === "BOLA" && f.route === "DELETE /api/notes/{id}" && f.severity === "HIGH"))
	assert.ok(findings.some(f => f.rule === "BOLA" && f.route === "DELETE /api/uploads/{uuid}" && f.severity === "MEDIUM"), "a random UUID is hard to reach")
	assert.ok(!has("BOLA", "DELETE /api/playlists/{id}"), "the playlists struct behind the Playlists interface compares the owner")
	const unverified = findings.filter(f => f.rule === "JWT").map(f => f.severity).sort()
	assert.deepEqual(unverified, ["LOW", "MEDIUM"], "reading the kid is a step before verification; reading claims is not")
})

test("PocketBase-style router: Bind on a group and on a single route", async () => {
	const { byRoute, findings } = await scan("pbrouter")
	assert.equal(byRoute.get("GET /settings").role, true, "rg.Group(\"/settings\").Bind(RequireSuperuserAuth())")
	assert.equal(byRoute.get("GET /backups").role, true, "rg.GET(...).Bind(RequireSuperuserAuth())")
	assert.equal(byRoute.get("GET /health").auth, false)
	assert.ok(findings.every(f => f.severity !== "HIGH"))
})

test("a directory with no Go files maps no Go routes", async () => {
	const routes = await mapGoRoutes(new URL("./fixtures/app", import.meta.url).pathname)
	assert.equal(routes.length, 0)
})
