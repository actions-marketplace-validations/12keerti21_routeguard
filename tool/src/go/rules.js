// The per-route OWASP checks for Go handlers. Path-only checks (rate limits, business flows,
// operator paths, inventory) are shared with the Express rules.
import path from "node:path"
import { walk, field, lineOf, calleeName, calleeObject, args, paramsOf, stringValue, baseType, qualType } from "./ast.js"
import { traceGo, DB_WRITE, CARRIER_TYPE } from "./flow.js"

const RECORD_PARAM = /(id|ids|uuid|guid|pk|key|slug|code|token|hash|ref|no|num|number|name|user|email|handle|sid)$/i
const SECRET_PARAM = /token|code|hash|secret|otp|nonce|signature|key|session/i
const SENSITIVE_FIELD = /^(is_?admin|admin|role|roles|permissions?|is_?verified|verified|credit|credits|balance|owner|owner_?id|user_?id|tenant_?id|org_?id|is_?staff|is_?superuser)$/i
const SECRET_FIELD = /^(password|passwd|password_?hash|hashed_?password|pass_?hash|salt|secret|client_?secret|api_?key|private_?key|refresh_?token|reset_?token|otp|otp_?secret|totp_?secret|mfa_?secret|two_?factor_?secret|ssn)$/i
const BIND = /^(ShouldBind\w*|Bind\w*|BodyParser|Decode|Unmarshal|DecodeJSON|ReadJSON|ParseBody)$/
const SAVE_CALL = /^(Create|Save|Insert|InsertOne|Updates|Update|UpdateOne|Upsert|CreateInBatches)$|^(Create|Save|Update|Insert|Add|Register|Upsert|Edit|Patch)[A-Z](?!\w*(Audit|Event|Log|Metric|Param|Header|Field|Error|Context))/
const RESPOND = /^(JSON|IndentedJSON|JSONP|PureJSON|SecureJSON|AsciiJSON|JSONPretty|Encode|WriteJSON|RespondJSON|RespondWithJSON|SendJSON|Render|JSONResponse|OK)$/i
const CLIENT_CALL = /^(Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)$/
const URL_CHECK = /allow|whitelist|safe.?url|is.?safe|validate.?url|is.?allowed|trusted|permitted|check.?url|valid.?host/i
const FIXED_HOST = /^https?:\/\/[^/%{}]+\//i
const INPUT_READ = /^(Query|DefaultQuery|GetQuery|PostForm|DefaultPostForm|FormValue|PostFormValue|QueryParam|FormParam|FormValue|QueryValue)$/

const SHAPED = /sanitiz|strip|redact|clean|without|public|safe|omit|clear|scrub|mask|hide|copy|toDTO|toResponse|serializ|present/i
const where = (route, file, line) => `${path.relative(route.root, file)}:${line}`
const hasRole = route => route.role

// every field of a struct, embedded ones included
function fieldsOf(ctx, typeName, file, seen = new Set()) {
	const struct = ctx.structOf(typeName, file)
	if (!struct || seen.has(struct)) return []
	seen.add(struct)
	return struct.fields.flatMap(f => (f.embedded ? fieldsOf(ctx, f.embedded, struct.file, seen) : [f]))
}
const marshalsItself = (ctx, typeName) => (ctx.methods.get("MarshalJSON") ?? []).some(m => m.recv === baseType(typeName))

// the types of a handler's variables: var u User, u := &User{}, u, err := svc.Get(id)
function localTypes(fn, ctx) {
	const local = { types: new Map(), funcs: new Map() }
	for (const p of paramsOf(fn.node)) if (p.name) local.types.set(p.name, qualType(p.type))
	walk(field(fn.node, "body"), n => {
		if (n.type === "var_spec" && field(n, "type")) for (const id of n.namedChildren.filter(c => c.type === "identifier")) local.types.set(id.text, qualType(field(n, "type").text))
		if (n.type === "short_var_declaration") {
			const left = field(n, "left").namedChildren
			const right = field(n, "right").namedChildren
			right.forEach((r, i) => {
				if (!left[i]) return
				const type = ctx.typeOf(r, local, fn.file)
				if (type) local.types.set(left[i].text, type)
			})
		}
	})
	return local
}

const targetOf = arg => (arg?.type === "unary_expression" ? arg.namedChildren[0] : arg)

// API1
export function bolaGo(route) {
	if (!/[:{]/.test(route.path) || !route.go.fn || hasRole(route)) return null
	if (!route.auth && (route.method === "GET" || route.method === "HEAD")) return null
	const params = route.path.match(/[:{](\w+)/g)?.map(p => p.slice(1)) ?? []
	if (params.length && params.every(p => SECRET_PARAM.test(p))) return null
	// /hooks/{id}: an incoming webhook is reached by its unguessable id, which is the credential
	if (/\/(hooks?|webhooks?|callbacks?)\//i.test(route.path) && !route.auth) return null
	// a signed URL or a capability check in front: the link itself is the credential
	if (route.middleware.some(m => /signed_?url|signature|hmac|capabilit|has_?uuid|verify_?sig/i.test(m))) return null
	if (!params.some(p => RECORD_PARAM.test(p))) return null
	const trace = traceGo(route)
	if (trace.scoped !== false) return null
	const { at } = trace
	const write = ["PUT", "PATCH", "DELETE"].includes(route.method)
	const via = at.chain.length ? ` via ${at.chain.join(" → ")}` : ""
	return {
		rule: "BOLA",
		owasp: !route.auth ? "API1/API2: no auth at all" : write ? "API1:2023 BOLA, or API5:2023 BFLA if this is a shared record only admins should change" : "API1:2023 Broken Object Level Authorization",
		// a signed-in user who must already know a random UUID: real, but hard to reach
		severity: !route.auth || (write && !randomIds(route)) ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: `${at.file}:${at.line}`,
		message: `${at.method}${via} uses an id from the URL, and nothing on the way checks it against the caller.`,
		fix: 'If the record has an owner, scope the query to the caller: db.Where("id = ? AND user_id = ?", id, userID).First(&order). If it is shared, add a role check to the route.'
	}
}

// API5: a signed-in user changes shared data the handler never ties to them
export function bflaGo(route) {
	if (!route.auth || route.method === "GET" || /[:{]/.test(route.path) || !route.go.fn || hasRole(route)) return null
	const { fn } = route.go
	const writes = []
	let identity = false
	walk(field(fn.node, "body"), n => {
		if (n.type !== "call_expression") return
		const name = calleeName(n)
		if (/^(Create|Save|Insert|InsertOne|InsertMany|CreateInBatches)$/.test(name)) writes.push({ name, line: lineOf(n) })
		if (/user|claims|session|principal|caller|doer|account/i.test(n.text.split("(")[0]) || /"(user\w*|uid|claims|session)"/i.test(args(n)[0]?.text ?? "")) identity = true
	})
	if (writes.length === 0 || identity || /user|claims|session|doer/i.test(field(fn.node, "body").text.match(/c\.(Get|MustGet|Locals)\([^)]*\)|ctx\.\w+|Value\([^)]*\)/g)?.join(" ") ?? "")) return null
	return {
		rule: "BFLA",
		owasp: "API5:2023 Broken Function Level Authorization",
		severity: "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: where(route, fn.file, writes[0].line),
		message: `Any signed-in user can ${writes.map(w => w.name).join(", ")} here, and the new record is not tied to them, so this looks like shared data with no role check.`,
		fix: "Add a role check to the route, or store the caller as the owner if users should own these records."
	}
}

// API3: privileged fields filled from the request body and saved
export function massAssignmentGo(route) {
	const { fn, ctx } = route.go
	if (!fn || route.method === "GET") return null
	const local = localTypes(fn, ctx)
	const body = field(fn.node, "body")
	const bound = []
	walk(body, n => {
		if (n.type !== "call_expression" || !BIND.test(calleeName(n))) return
		// json.Unmarshal(raw, &x) on a third-party answer is not the request body
		if (calleeName(n) === "Unmarshal" && !/body|Body|req|request|data|payload|raw/.test(args(n)[0]?.text ?? "")) return
		const target = targetOf(args(n).at(-1))
		if (target?.type !== "identifier") return
		const type = local.types.get(target.text)
		const sensitive = fieldsOf(ctx, type, fn.file).filter(f => !f.hidden && (SENSITIVE_FIELD.test(f.name) || SENSITIVE_FIELD.test(f.json)))
		if (sensitive.length) bound.push({ name: target.text, type, sensitive, line: lineOf(n), bind: calleeName(n) })
	})
	for (const b of bound) {
		// x.Role = "user" after binding puts the server back in charge of that field
		const reset = new Set()
		let saved = null
		walk(body, n => {
			if (n.type === "assignment_statement") {
				for (const l of field(n, "left").namedChildren) if (l.type === "selector_expression" && l.namedChildren[0].text === b.name) reset.add(field(l, "field").text)
			}
			// if category.UserId != c.Params.UserId { 403 }: the field is checked, not trusted
			if (n.type === "binary_expression" && /^(==|!=)$/.test(field(n, "operator")?.text ?? ""))
				for (const side of [field(n, "left"), field(n, "right")]) if (side?.type === "selector_expression" && side.namedChildren[0].text === b.name) reset.add(field(side, "field").text)
			if (n.type === "call_expression" && SAVE_CALL.test(calleeName(n)) && args(n).some(a => targetOf(a)?.text === b.name)) saved ??= { name: calleeName(n), line: lineOf(n) }
		})
		const open = b.sensitive.filter(f => !reset.has(f.name))
		if (!saved || open.length === 0) continue
		return {
			rule: "MASS_ASSIGNMENT",
			owasp: "API3:2023 Broken Object Property Level Authorization",
			severity: hasRole(route) ? "LOW" : "HIGH",
			route: `${route.method} ${route.path}`,
			where: where(route, fn.file, b.line),
			message: `${b.bind}() fills a ${b.type} from the request body, including ${open.map(f => f.json).join(", ")}, and ${saved.name}() saves it, so a client chooses its own privileges.`,
			fix: `Bind into a request struct with only the fields a client may set, or tag the privileged fields json:"-".`
		}
	}
	return null
}

// API3: records with password hashes or secrets sent back whole
export function dataExposureGo(route) {
	const { fn, ctx } = route.go
	if (!fn) return null
	const local = localTypes(fn, ctx)
	// user.Sanitize(), sanitizeUser(u), u.ToPublic(): the secrets are stripped first
	const shaped = new Set()
	walk(field(fn.node, "body"), n => {
		if (n.type !== "call_expression" || !SHAPED.test(calleeName(n))) return
		const object = calleeObject(n)
		if (object?.type === "identifier") shaped.add(object.text)
		for (const a of args(n)) if (targetOf(a)?.type === "identifier") shaped.add(targetOf(a).text)
	})
	// for _, u := range users { u.Sanitize() }: the list is shaped too
	walk(field(fn.node, "body"), n => {
		if (n.type !== "for_statement") return
		const range = n.namedChildren.find(c => c.type === "range_clause")
		if (!range) return
		const loopVars = field(range, "left")?.namedChildren.map(c => c.text) ?? []
		if (loopVars.some(v => shaped.has(v))) shaped.add(field(range, "right")?.text)
	})
	// share.Password = "": the secret is cleared before the answer
	const cleared = new Set()
	walk(field(fn.node, "body"), n => {
		if (n.type !== "assignment_statement") return
		const right = field(n, "right").namedChildren[0]?.text
		if (!['""', "nil", "''"].includes(right)) return
		for (const l of field(n, "left").namedChildren) if (l.type === "selector_expression") cleared.add(field(l, "field").text)
	})
	let hit = null
	walk(field(fn.node, "body"), n => {
		if (hit || n.type !== "call_expression" || !RESPOND.test(calleeName(n))) return
		for (const value of payloadValues(args(n).at(-1))) {
			if (shaped.has(targetOf(value)?.text)) continue
			const type = value.type === "composite_literal" ? qualType(field(value, "type").text) : local.types.get(targetOf(value)?.text)
			if (!type || marshalsItself(ctx, type)) continue
			const secrets = fieldsOf(ctx, type, fn.file).filter(f => !f.hidden && !cleared.has(f.name) && (SECRET_FIELD.test(f.name) || SECRET_FIELD.test(f.json)))
			if (secrets.length) {
				hit = { type, secrets, line: lineOf(n), call: calleeName(n) }
				return
			}
		}
	})
	if (!hit) return null
	// login answers hand out tokens on purpose
	const secrets = /login|signin|token|auth|refresh|session/i.test(route.path) ? hit.secrets.filter(f => !/token/i.test(f.name)) : hit.secrets
	if (secrets.length === 0) return null
	return {
		rule: "DATA_EXPOSURE",
		owasp: "API3:2023 Broken Object Property Level Authorization",
		severity: !route.auth ? "HIGH" : hasRole(route) ? "LOW" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: where(route, fn.file, hit.line),
		message: `The whole ${hit.type} goes to the client through ${hit.call}(), and its ${secrets.map(f => f.name).join(", ")} field${secrets.length > 1 ? "s have" : " has"} no json:"-" tag.`,
		fix: `Tag secret fields json:"-", or answer with a response struct that leaves them out.`
	}
}

// gin.H{"user": u} and []User: the values that end up in the JSON
function payloadValues(node) {
	if (!node) return []
	if (node.type === "composite_literal" && /\bH$|map\[/.test(field(node, "type")?.text ?? "")) {
		const out = []
		walk(field(node, "body"), n => {
			if (n.type === "keyed_element") out.push(...payloadValues(n.namedChildren.at(-1)?.namedChildren?.[0] ?? n.namedChildren.at(-1)))
			return n.type === "literal_value" && n !== field(node, "body") ? false : undefined
		})
		return out
	}
	if (node.type === "literal_element") return payloadValues(node.namedChildren[0])
	return [node]
}

// API7: the server fetches a URL the client chose
export function ssrfGo(route) {
	const { fn, ctx } = route.go
	if (!fn) return null
	const local = localTypes(fn, ctx)
	const body = field(fn.node, "body")
	const carriers = new Set(paramsOf(fn.node).filter(p => p.name && CARRIER_TYPE.test(p.type)).map(p => p.name))
	const tainted = new Map()
	const boundVars = new Map()
	// what in the handler holds client input, and under which name the client sends it
	const inputOf = node => {
		let found = null
		walk(node, n => {
			if (found) return false
			if (n.type === "identifier" && tainted.has(n.text)) found = tainted.get(n.text)
			if (n.type === "call_expression" && INPUT_READ.test(calleeName(n))) {
				const object = calleeObject(n)
				const fromRequest = object && (carriers.has(object.text) || /URL\.Query\(\)|Request\(\)|Form$/.test(object.text))
				const name = stringValue(args(n)[0], ctx.consts)
				if (fromRequest && name) found = { in: /Query|QueryParam|GetQuery|QueryValue/.test(calleeName(n)) ? "query" : "body", name }
			}
			if (n.type === "call_expression" && calleeName(n) === "Get" && /URL\.Query\(\)$/.test(calleeObject(n)?.text ?? "")) {
				const name = stringValue(args(n)[0], ctx.consts)
				if (name) found = { in: "query", name }
			}
			if (n.type === "selector_expression" && boundVars.has(n.namedChildren[0].text)) {
				const f = fieldsOf(ctx, boundVars.get(n.namedChildren[0].text), fn.file).find(x => x.name === field(n, "field").text)
				if (f) found = { in: "body", name: f.json }
			}
		})
		return found
	}
	const hits = []
	let checked = false
	walk(body, n => {
		if (n.type === "call_expression" && BIND.test(calleeName(n))) {
			const target = targetOf(args(n).at(-1))
			if (target?.type === "identifier" && local.types.get(target.text)) boundVars.set(target.text, local.types.get(target.text))
		}
		if (n.type === "short_var_declaration" || n.type === "assignment_statement") {
			const left = field(n, "left").namedChildren
			field(n, "right").namedChildren.forEach((r, i) => {
				const input = inputOf(r)
				if (input && left[i]?.type === "identifier") tainted.set(left[i].text, input)
			})
		}
		if (n.type !== "call_expression") return
		const name = calleeName(n)
		if (URL_CHECK.test(name) && args(n).some(a => inputOf(a))) checked = true
		if (!CLIENT_CALL.test(name)) return
		const object = calleeObject(n)?.text ?? ""
		if (!/^http$|client|Client|resty|R\(\)/.test(object)) return
		const urlArg = args(n)[name === "NewRequest" ? 1 : name === "NewRequestWithContext" ? 2 : 0]
		const input = urlArg && inputOf(urlArg)
		if (input) hits.push({ call: n, arg: urlArg, input, client: `${object}.${name}` })
	})
	if (hits.length === 0 || checked) return null
	const [hit] = hits
	const literal = hit.arg.type === "call_expression" ? stringValue(args(hit.arg)[0]) : hit.arg.type === "binary_expression" ? stringValue(field(hit.arg, "left")) : null
	const fixed = literal !== null && FIXED_HOST.test(literal)
	return {
		rule: "SSRF",
		owasp: "API7:2023 Server Side Request Forgery",
		severity: fixed ? "MEDIUM" : "HIGH",
		route: `${route.method} ${route.path}`,
		where: where(route, fn.file, lineOf(hit.call)),
		message: fixed
			? `${hit.client}() puts client input into a fixed host's URL, so the client can change the path or add parameters.`
			: `${hit.client}() requests a URL the client controls, so the server can be sent to internal hosts or 169.254.169.254.`,
		fix: fixed
			? "Escape the value (url.PathEscape) and validate it against what the API expects."
			: "Allow only known hosts: parse with url.Parse, check the hostname against an allow-list, and block private and link-local addresses (or dial through a guarded net.Dialer).",
		input: hit.input
	}
}

export const GO_RULES = [bolaGo, bflaGo, massAssignmentGo, dataExposureGo, ssrfGo]

const randomIds = route => {
	const params = (route.path.match(/[:{<](?:\w+:)?(\w+)/g) ?? []).map(p => p.replace(/^[:{<](\w+:)?/, ""))
	return params.length > 0 && params.filter(p => RECORD_PARAM.test(p)).every(p => /uuid|guid/i.test(p))
}
