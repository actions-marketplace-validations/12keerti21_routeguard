import { test } from "node:test"
import assert from "node:assert/strict"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { mapRoutes } from "../src/mapper.js"
import { bola } from "../src/rules/bola.js"
import { bfla } from "../src/rules/bfla.js"
import { misconfig } from "../src/rules/misconfig.js"

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/express-extra")
const routes = mapRoutes(root)
const byRoute = new Map(routes.map(r => [`${r.method} ${r.path}`, r]))
const findings = [...routes.flatMap(r => [bola, bfla].map(rule => rule(r)).filter(Boolean)), ...misconfig(root)]
const find = (rule, route) => findings.find(f => f.rule === rule && f.route === route)

test("HTTP client calls are not routes, a route in a return statement is", () => {
	assert.ok(![...byRoute.keys()].some(k => k.includes("/admin/")), "client.get(url, config) in a frontend service")
	assert.ok(byRoute.has("GET /university/*"), "return webRouter.get(path, handler)")
})

test("an auth middleware factory with a scope counts as a role check", () => {
	const route = byRoute.get("POST /internal/credentials/resolve")
	assert.equal(route.auth, true)
	assert.equal(route.role, true)
	assert.equal(find("BFLA", "POST /internal/credentials/resolve"), undefined)
})

test("public handshakes, metrics, HEAD reads and random UUIDs", () => {
	assert.equal(find("BFLA", "GET /system/ping"), undefined)
	assert.equal(find("BFLA", "GET /metrics").severity, "MEDIUM")
	assert.equal(find("BOLA", "HEAD /items/:id"), undefined, "HEAD is a read, like GET")
	assert.equal(find("BOLA", "DELETE /api/uploads/:uuid").severity, "MEDIUM")
})

test("CORS used only in development, and * with credentials, are LOW", () => {
	const cors = findings.filter(f => f.rule === "CORS")
	assert.equal(cors.length, 2)
	assert.ok(cors.every(f => f.severity === "LOW"))
	assert.ok(cors.some(f => /development/.test(f.message)))
	assert.ok(cors.some(f => /browsers refuse/.test(f.message)))
})

test("decorator controllers: n8n's @RestController and NestJS @Controller", () => {
	const decorated = mapRoutes(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/decorators"))
	const get = key => decorated.find(r => `${r.method} ${r.path}` === key)
	const found = (rule, route) => decorated.map(r => [bola, bfla].map(f => f(r))).flat().find(f => f?.rule === rule && f.route === route)
	assert.equal(get("GET /rest/tags").role, true, "@GlobalScope under /rest")
	assert.equal(get("POST /rest/tags/login").auth, false, "skipAuth")
	assert.ok(get("POST /rest/tags/login").middleware.includes("rateLimit"))
	assert.equal(get("DELETE /scim/v2/Users/:id").role, true, "route options imported from another file")
	assert.equal(found("BOLA", "DELETE /rest/tags/:tagId").severity, "HIGH", "@Param is the id")
	assert.equal(found("BOLA", "DELETE /rest/tags/own/:tagId"), undefined)
	assert.equal(get("GET /api/notes/:id").auth, true, "setGlobalPrefix and @UseGuards")
	assert.equal(found("BOLA", "GET /api/notes/:id"), undefined, "@CurrentUser() is the caller")
	assert.ok(found("BOLA", "DELETE /api/notes/:id"))
	assert.equal(get("GET /api/status/health").auth, false, "@Public() skips the APP_GUARD")
	assert.equal(get("GET /api/status/me").auth, true, "APP_GUARD covers the rest")
})
