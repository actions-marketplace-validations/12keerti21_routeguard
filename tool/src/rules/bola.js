import path from "node:path"
import { walk, isMemberNode } from "../mapper.js"
import { traceRoute } from "../flow.js"
import { RECORD_ACCESS, checksBodyCredential, dbCalls, decoratedParams, handlerParams, hasRole, isMember, whereOf } from "./handler.js"

// /:courseId, /:pk, /:slug, /:username name a record; /:provider, /:chunk, /:lang do not
const RECORD_PARAM = /(id|ids|uuid|guid|pk|key|slug|code|token|hash|ref|no|num|number|name|user|email|handle|sid)$/i
const SECRET_PARAM = /token|code|hash|secret|otp|nonce|signature|key|session/i

// names that carry a value from req.params: const id = req.params.id, const { id } = req.params
function paramDerivedNames(fn, req) {
	const names = new Set(decoratedParams(fn).ids)
	walk(fn.body, node => {
		if (node.type !== "VariableDeclarator" || !node.init) return
		const fromParams =
			isMember(node.init, req, "params") ||
			(isMemberNode(node.init) && isMember(node.init.object, req, "params"))
		if (!fromParams) return
		if (node.id.type === "Identifier") names.add(node.id.name)
		if (node.id.type === "ObjectPattern")
			node.id.properties.forEach(p => p.value?.type === "Identifier" && names.add(p.value.name))
	})
	return names
}

function usesParam(node, req, derived) {
	let found = false
	walk(node, n => {
		if (isMemberNode(n) && isMember(n.object, req, "params")) found = true
		if (n.type === "Identifier" && derived.has(n.name)) found = true
	})
	return found
}

// API1: a record is fetched or changed by a client-supplied id, and the handler never
// compares it with the caller, so any signed-in user can reach anyone's record
export function bola(route) {
	if (!/[:{]/.test(route.path) || !route.fn || hasRole(route)) return null
	// an unauthenticated read is usually a public catalogue on purpose (books, products)
	if (!route.auth && (route.method === "GET" || route.method === "HEAD")) return null
	// a webhook receiver proves the sender by a signature in the request, not by a session
	if (!route.auth && /\/webhooks?(\/|$)/i.test(route.path)) return null
	// /reset/:token, /verify/:code: an unguessable secret in the URL is the authorisation
	const params = route.path.match(/[:{](\w+)/g)?.map(p => p.slice(1)) ?? []
	if (params.length && params.every(p => SECRET_PARAM.test(p))) return null
	if (!params.some(p => RECORD_PARAM.test(p))) return null

	const { req } = handlerParams(route.fn)
	const derived = paramDerivedNames(route.fn, req)
	const calls = dbCalls(route.fn, RECORD_ACCESS).filter(c => c.node.arguments.some(a => usesParam(a, req, derived)))
	if (checksBodyCredential(route.fn)) return null

	// follow the id into the services it reaches; the caller must limit it somewhere on the way
	const trace = traceRoute(route)
	if (trace.scoped === true || (trace.scoped === null && trace.trusted)) return null
	if (trace.scoped === null && calls.length === 0) return null
	const at = trace.at
	const via = at?.chain.length ? ` via ${at.chain.join(" → ")}` : ""

	const write = ["PUT", "PATCH", "DELETE"].includes(route.method)
	return {
		rule: "BOLA",
		owasp: !route.auth
			? "API1/API2: no auth at all"
			: write
				? "API1:2023 BOLA, or API5:2023 BFLA if this is a shared record only admins should change"
				: "API1:2023 Broken Object Level Authorization",
		// a signed-in user who must already know a random UUID: real, but hard to reach
		severity: !route.auth || (write && !randomIds(route)) ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: at ? `${path.relative(route.root, at.file)}:${at.line}` : whereOf(route, calls[0].line),
		message: `${at?.method ?? calls.map(c => c.method).join(", ")}${via} uses an id from the URL, and nothing on the way checks it against the caller.`,
		fix: "If the record has an owner, scope the query to the caller: findOne({ _id: id, owner: req.user._id }). If it is shared, add a role check such as [auth, admin]."
	}
}

const randomIds = route => {
	const params = (route.path.match(/[:{<](?:\w+:)?(\w+)/g) ?? []).map(p => p.replace(/^[:{<](\w+:)?/, ""))
	return params.length > 0 && params.filter(p => RECORD_PARAM.test(p)).every(p => /uuid|guid/i.test(p))
}
