import path from "node:path"
import { listSpecFiles } from "../spec.js"

// leftover versions and environments: /v1 next to /v2, /dev, /beta, /old (debug and internal are BFLA's)
// environment names only, near the top of the path: /dev/csrf, /api/test/x. "/stage", "/temp" and
// "/flush/old" are usually feature names
const NON_PROD = /^(dev|develop|development|test|testing|staging|sandbox|deprecated)$/i
const VERSION = /^v\d+$/i

const strength = route => (route.role ? 2 : route.auth ? 1 : 0)
const STRENGTH = ["no auth", "auth", "auth and a role"]
// /api/v1/users/:id and /api/v2/users/:userId are the same endpoint
// one app's /x and another app's /x in the same monorepo are not copies of each other
const shape = route => `${route.rootFile ?? ""} ${shapePath(route)}`
const shapePath = route => `${route.method} ${route.path.split("/").filter(s => !VERSION.test(s)).map(s => (/^[:{]/.test(s) ? ":p" : s.toLowerCase())).join("/")}`

// API9: endpoints nobody tracks, which keep old or weaker rules
export function inventory(routes, root) {
	const findings = []

	// the same endpoint registered more than once, one copy guarded less than another
	const byShape = new Map()
	// only routes whose full path is known: a router mounted inside a function (mountMcp(app)) has no prefix here
	// catch-alls (/{*any}, *) exist in most apps and are not copies of one endpoint
	// a path with an unresolved <part> could be anything, so it is not compared
	for (const r of routes.filter(r => r.anchored && !/[*<]/.test(r.path))) {
		if (!byShape.has(shape(r))) byShape.set(shape(r), [])
		byShape.get(shape(r)).push(r)
	}
	for (const copies of byShape.values()) {
		const distinct = [...new Map(copies.map(r => [`${r.file}:${r.line}`, r])).values()]
		if (distinct.length < 2) continue
		const strongest = distinct.reduce((a, b) => (strength(b) > strength(a) ? b : a))
		for (const weaker of distinct.filter(r => strength(r) < strength(strongest))) {
			findings.push({
				rule: "SHADOW_ROUTE",
				owasp: "API9:2023 Improper Inventory Management",
				// a signed-in copy may scope records itself (a session API next to an API-key one)
				severity: weaker.auth ? "MEDIUM" : "HIGH",
				route: `${weaker.method} ${weaker.path}`,
				where: `${weaker.file}:${weaker.line}`,
				message: `Another copy of this endpoint (${strongest.file}:${strongest.line}) requires ${STRENGTH[strength(strongest)]}; this one requires ${STRENGTH[strength(weaker)]}, so callers can go around the check.`,
				fix: "Remove the older or development copy, or give it the same middleware."
			})
		}
	}

	// /dev/..., /beta/..., /old/...
	for (const r of routes) {
		const segment = r.path.split("/").filter(s => s && !/^(api|v\d+)$/i.test(s)).slice(0, 2).find(s => NON_PROD.test(s))
		if (!segment) continue
		findings.push({
			rule: "NON_PROD_ROUTE",
			owasp: "API9:2023 Improper Inventory Management",
			severity: r.auth ? "LOW" : "MEDIUM",
			route: `${r.method} ${r.path}`,
			where: `${r.file}:${r.line}`,
			message: `"/${segment}" looks like a development or retired endpoint that is still mounted.`,
			fix: "Remove it from production builds, or mount it only when NODE_ENV is development."
		})
	}

	// routes the API's own OpenAPI spec does not list
	const spec = listSpecFiles(root)
	if (spec.paths.size > 0) {
		const documented = p => spec.paths.has(p.replace(/:(\w+)/g, ":p").replace(/\{\w+\}/g, ":p").toLowerCase())
		// a spec served under /b2b/v2 describes that API only, not the whole app
		const inScope = r => !spec.basePath || r.path.toLowerCase().startsWith(spec.basePath.toLowerCase())
		const missing = routes.filter(r => inScope(r) && !documented(r.path) && !documented(r.path.slice(spec.basePath.length)))
		const unique = [...new Map(missing.map(r => [`${r.method} ${r.path}`, r])).values()]
		if (unique.length) {
			const [first] = unique
			findings.push({
				rule: "UNDOCUMENTED",
				owasp: "API9:2023 Improper Inventory Management",
				severity: "LOW",
				route: `${unique.length} route${unique.length > 1 ? "s" : ""}`,
				where: `${first.file}:${first.line}`,
				message: `Not in ${spec.files.map(f => path.relative(root, f)).join(", ")}: ${unique.slice(0, 8).map(r => `${r.method} ${r.path}`).join(", ")}${unique.length > 8 ? ", …" : ""}.`,
				fix: "Document the routes or remove them; an endpoint nobody knows about is one nobody reviews.",
				undocumented: unique.map(r => `${r.method} ${r.path}`)
			})
		}
	}
	return findings
}
