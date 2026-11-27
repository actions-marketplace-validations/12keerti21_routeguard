import { test } from "node:test"
import assert from "node:assert/strict"
import { mapPyRoutes } from "../src/py/mapper.js"
import { PY_RULES } from "../src/py/rules.js"
import { pyAppRules } from "../src/py/app.js"
import { bfla } from "../src/rules/bfla.js"
import { rateLimit } from "../src/rules/rateLimit.js"

const fixture = name => new URL(`./fixtures/py/${name}`, import.meta.url).pathname

async function scan(name) {
	const routes = await mapPyRoutes(fixture(name))
	const byRoute = new Map(routes.map(r => [`${r.method} ${r.path}`, r]))
	const findings = [...routes.flatMap(r => [...PY_RULES, bfla, rateLimit].map(rule => rule(r)).filter(Boolean)), ...pyAppRules(routes)]
	const has = (rule, route) => findings.some(f => f.rule === rule && (route === undefined || f.route === route))
	return { routes, byRoute, findings, has }
}

test("flask: blueprints registered in create_app, decorators as middleware, converters as params", async () => {
	const { byRoute } = await scan("flask")
	assert.ok(byRoute.has("GET /api/notes/{note_id}"), "<int:note_id> becomes {note_id} under the blueprint's prefix")
	assert.equal(byRoute.get("POST /api/login").auth, false)
	assert.equal(byRoute.get("GET /api/notes/{note_id}").auth, true)
	assert.equal(byRoute.get("DELETE /api/checked/notes/{note_id}").middleware.some(m => /in handler/.test(m)), false, "an ownership check is not a login check")
})

test("flask: BOLA, scoped queries, ownership checks, mass assignment, secrets, SSRF and app settings", async () => {
	const { findings, has } = await scan("flask")
	assert.ok(has("BOLA", "GET /api/notes/{note_id}"))
	assert.ok(!has("BOLA", "GET /api/safe/notes/{note_id}"), "filter_by(user_id=current_user.id)")
	assert.ok(!has("BOLA", "DELETE /api/checked/notes/{note_id}"), "note.user_id != current_user.id")
	assert.ok(has("MASS_ASSIGNMENT", "POST /api/users"))
	assert.ok(has("DATA_EXPOSURE", "GET /api/me"))
	assert.deepEqual(findings.find(f => f.rule === "SSRF").input, { in: "query", name: "url" })
	assert.ok(has("BFLA", "GET /api/admin/stats"))
	assert.ok(findings.some(f => f.rule === "CORS" && f.severity === "HIGH"))
	assert.ok(findings.some(f => f.rule === "JWT" && f.severity === "HIGH"), "SECRET_KEY in the code")
})

test("fastapi: include_router prefixes, router dependencies, Annotated dependencies", async () => {
	const { byRoute, has } = await scan("fastapi")
	assert.equal(byRoute.get("GET /api/items/{item_id}").auth, true, "user: CurrentUser")
	assert.equal(byRoute.get("GET /api/items/public/list").auth, false)
	assert.equal(byRoute.get("GET /api/admin/users/{user_id}").role, true, "APIRouter(dependencies=[Depends(get_current_superuser)])")
	assert.ok(has("BOLA", "GET /api/items/{item_id}"))
	assert.ok(!has("BOLA", "DELETE /api/items/{item_id}"), "item.owner_id != user.id")
	assert.ok(!has("BOLA", "GET /api/admin/users/{user_id}"))
	assert.ok(has("SSRF", "GET /api/items/fetch/remote"))
})

test("django: ROOT_URLCONF, include, DRF routers, default permissions, AllowAny and the admin site", async () => {
	const { byRoute, findings, has } = await scan("django")
	assert.equal(byRoute.get("ALL /admin").role, true)
	assert.equal(byRoute.get("GET /api/public").auth, false, "AllowAny overrides the default")
	assert.equal(byRoute.get("GET /api/orders/{pk}").auth, true, "DEFAULT_PERMISSION_CLASSES")
	for (const m of ["GET", "PUT", "PATCH", "DELETE"]) assert.ok(byRoute.has(`${m} /api/orders/{pk}`))
	assert.ok(has("BOLA", "GET /api/orders/{pk}"), "ModelViewSet over Order.objects.all()")
	assert.ok(has("BOLA", "DELETE /api/orders/{pk}"))
	assert.ok(!has("BOLA", "GET /api/invoices/{pk}"), "get_queryset filters by request.user")
	assert.ok(has("BOLA", "GET /api/orders/{pk}/receipt"), "get_object_or_404(Order, pk=pk)")
	assert.ok(findings.some(f => f.rule === "CORS" && f.severity === "HIGH"))
	assert.ok(findings.some(f => f.rule === "ERROR_LEAK" && /DEBUG/.test(f.message)))
})

test("drf: delegated checks, a urls.py reached through include, replaced secrets, allow-listed CORS and format-only jwt.decode", async () => {
	const { byRoute, findings, has } = await scan("drf")
	assert.ok(!has("BOLA", "DELETE /integrations/{integration_id}"), "Action.do(request.user, integration) gets the caller with the record")
	assert.ok(has("BOLA", "DELETE /notes/{note_id}"))
	assert.ok(has("BOLA", "DELETE /links/{link_id}"))
	assert.ok(!byRoute.has("DELETE /{link_id}"), "the included urls.py is kept only under its prefix")
	const secret = findings.find(f => f.rule === "JWT" && /SECRET_KEY/.test(f.message))
	assert.equal(secret.severity, "LOW", "prod.py reads SECRET_KEY from the environment")
	assert.ok(!findings.some(f => f.rule === "CORS"), "the origin is checked against settings first")
	assert.ok(!findings.some(f => /signature/.test(f.message)), "a decode whose result nobody reads decides nothing")
})

test("django: splatted and reassigned urlpatterns, decorate_urlpatterns, membership checks and parent lookups", async () => {
	const { byRoute, findings, has } = await scan("django-site")
	assert.ok(byRoute.has("PATCH /api/boards/{anchor}/assets/{pk}"), "[*board_urls] from an imported urlpatterns, kept after urlpatterns = [debug] + urlpatterns")
	assert.equal(byRoute.get("ALL /admin/bulk/{model_name}/{pk}").role, true, "decorate_urlpatterns(urlpatterns, require_admin_access)")
	assert.equal(byRoute.get("PATCH /api/projects/{pk}").role, true, "@allow_permission on a ViewSet action")
	assert.ok(!has("BOLA", "DELETE /api/projects/{pk}"), "ProjectMember.objects.filter(member=request.user, project_id=pk).exists()")
	assert.ok(!has("BOLA", "PATCH /api/boards/{anchor}/assets/{pk}"), "the asset is the caller's; the board is a public parent")
	assert.ok(has("BOLA", "DELETE /api/boards/{anchor}/assets/{pk}"))
	assert.ok(!has("BOLA", "GET /api/assets/{asset_id}"), "bookmark_read(request, asset.bookmark_id) checks the owner")
	assert.equal(findings.find(f => f.rule === "SSRF").severity, "MEDIUM", "both URLs the variable can hold have a fixed host")
})

test("a directory with no Python files maps no Python routes", async () => {
	assert.equal((await mapPyRoutes(new URL("./fixtures/app", import.meta.url).pathname)).length, 0)
})
