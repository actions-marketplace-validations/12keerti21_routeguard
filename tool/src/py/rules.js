// The per-route OWASP checks for Python views. Path-only checks (rate limits, business flows,
// operator paths, inventory) are shared with the Express rules.
import path from "node:path"
import { walk, field, lineOf, pyString, callName, callObject, posArgs, kwarg, pyParams, items } from "./ast.js"
import { tracePy, querysetScoped } from "./flow.js"

const RECORD_PARAM = /(id|ids|uuid|guid|pk|key|slug|code|token|hash|ref|no|num|number|name|user|email|handle|sid|title)$/i
const SECRET_PARAM = /token|code|hash|secret|otp|nonce|signature|key|session|uidb64/i
const SENSITIVE_FIELD = /^(is_?admin|admin|role|roles|permissions?|is_?verified|verified|credit|credits|balance|owner|owner_?id|user_?id|tenant_?id|org_?id|is_?staff|is_?superuser|superuser|groups|user_permissions|is_?active)$/i
const SECRET_FIELD = /^(password|passwd|password_?hash|hashed_?password|pass_?hash|salt|secret|client_?secret|api_?key|private_?key|refresh_?token|reset_?token|otp|otp_?secret|totp_?secret|mfa_?secret|two_?factor_?secret|ssn|ccn|cc_?num(ber)?|card_?number|credit_?card|cvv|cvc)$/i
// request bodies: request.json, request.get_json(), request.form, request.data, json.loads(request.body)
const BODY = /request\.(json|get_json\(\)|form|data|values|POST|body)|json\.loads\(\s*request|await request\.json\(\)/
const OBJECT_PERMISSION = /Owner|Object|Author|Creator|Self|IsAdmin|ModelPermissions|DjangoObject|Staff|Superuser/i
const URL_CHECK = /allow|whitelist|safe_?url|is_?safe|validate_?url|is_?allowed|trusted|permitted|check_?url|valid_?host/i
const FIXED_HOST = /^https?:\/\/[^/{}%]+\//i
const CLIENT = /^(requests|httpx|session|client|http|urllib\.request|urllib3|aiohttp|s|sess)$|session|client|http/i

const where = (route, file, line) => `${path.relative(route.root, file)}:${line}`
const hasRole = route => route.role

// API1
export function bolaPy(route) {
	// the id may come in the body or the query instead: {"id": 5}, ?order_id=5
	const bodyIds = route.py.fn?.node ? requestIds(route.py.fn.node) : []
	if ((!/\{\w+\}/.test(route.path) && !bodyIds.length) || hasRole(route)) return null
	if (!route.auth && (route.method === "GET" || route.method === "HEAD")) return null
	const params = route.path.match(/\{(\w+)\}/g)?.map(p => p.slice(1, -1)) ?? []
	if (params.length && params.every(p => SECRET_PARAM.test(p))) return null
	// /badge/{badge_key}/{signature}: an unguessable key or signature in a public link is its credential
	if (!route.auth && params.some(p => /(^|_)(key|signature|hmac|secret|nonce|token)$/i.test(p))) return null
	if (!params.some(p => RECORD_PARAM.test(p)) && !bodyIds.length) return null
	if (/\/(hooks?|webhooks?|callbacks?|ping)\//i.test(route.path) && !route.auth) return null
	// password recovery, e-mail verification, invites: public flows by design; the rate-limit check covers them
	if (!route.auth && /password|recover|reset|forgot|verif|confirm|activat|unsubscribe|invit|magic|signup|register/i.test(route.path)) return null
	if (route.middleware.some(m => OBJECT_PERMISSION.test(m) && !/^IsAuthenticated/.test(m))) return null
	const { fn, cls, action } = route.py
	const write = ["PUT", "PATCH", "DELETE"].includes(route.method)
	const finding = (at, message) => ({
		rule: "BOLA",
		owasp: !route.auth ? "API1/API2: no auth at all" : write ? "API1:2023 BOLA, or API5:2023 BFLA if this is a shared record only admins should change" : "API1:2023 Broken Object Level Authorization",
		// a signed-in user who must already know a random UUID: real, but hard to reach
		severity: !route.auth || (write && !randomIds(route)) ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: at,
		message,
		fix: "Limit the query to the caller (Model.objects.get(pk=pk, owner=request.user), filter_by(id=id, user_id=current_user.id)), or add an object-level permission such as IsOwner."
	})
	// a DRF generic action: get_object() looks the record up in queryset or get_queryset()
	if (fn?.generic && cls && ["retrieve", "update", "partial_update", "destroy"].includes(fn.generic)) {
		const scoped = drfScoped(route)
		if (scoped !== false) return null
		return finding(`${path.relative(route.root, cls.file)}:${lineOf(cls.node)}`, `${cls.name}.${fn.generic} (DRF) finds the record by the URL in a queryset that is not limited to the caller, and no object permission checks it.`)
	}
	if (!fn?.node) return null
	const trace = tracePy(route, bodyIds)
	// self.get_object() in an overridden action: the DRF queryset decides
	if (trace.scoped !== false) {
		if (cls && /get_object\(/.test(fn.node.text) && drfScoped(route) === false && ["GET", "PUT", "PATCH", "DELETE"].includes(route.method))
			return finding(where(route, fn.file, lineOf(fn.node)), `${cls.name}.${action ?? route.method.toLowerCase()} calls get_object() on a queryset that is not limited to the caller, and no object permission checks it.`)
		return null
	}
	const via = trace.at.chain.length ? ` via ${trace.at.chain.join(" → ")}` : ""
	const source = params.length ? "the URL" : "the request"
	return finding(`${trace.at.file}:${trace.at.line}`, `${trace.at.method}()${via} uses an id from ${source}, and nothing on the way checks it against the caller.`)
}

// ids the view reads from the request: content["id"], request.json.get("order_id"), request.args.get("id")
const ID_KEY = /^(id|pk|uuid|\w+_id|\w+Id)$/
function requestIds(fn) {
	const bodyVars = new Set()
	const out = []
	walk(field(fn, "body"), n => {
		if (n.type === "assignment" && field(n, "left")?.type === "identifier" && /request\.(json|get_json\(\)|form|data|args|values|GET|POST|query_params)$|get_json\([^)]*\)$/.test(field(n, "right")?.text ?? "")) bodyVars.add(field(n, "left").text)
		const src = n.type === "subscript" ? n.namedChildren[0] : n.type === "call" && callName(n) === "get" ? callObject(n) : null
		const keyNode = n.type === "subscript" ? n.namedChildren[1] : n.type === "call" ? posArgs(n)[0] : null
		if (!src) return
		const key = pyString(keyNode)
		if (key && ID_KEY.test(key) && (bodyVars.has(src.text) || /request\.(json|form|data|args|values|GET|POST|query_params)$|get_json\([^)]*\)$/.test(src.text))) out.push(key)
	})
	return [...new Set(out)]
}

// a DRF view's queryset: false when it is neither filtered by the caller nor guarded per object
function drfScoped(route) {
	const { cls, ctx } = route.py
	const perms = route.middleware
	if (perms.some(m => OBJECT_PERMISSION.test(m) && !/^IsAuthenticated/.test(m))) return true
	const getQs = ctx.classMethod(cls, "get_queryset")
	const getObj = ctx.classMethod(cls, "get_object")
	const text = [getQs?.node.text, getObj?.node.text].filter(Boolean).join("\n")
	if (/request\.user|current_user|self\.request\.user|\.user\b/.test(text)) return true
	if (/check_object_permissions|PermissionDenied|has_perm/.test(text)) return true
	if (querysetScoped(cls, ctx)) return true
	if (!ctx.classAttr(cls, "queryset") && !getQs) return null
	return false
}

// API5: a signed-in user changes shared data the view never ties to them
export function bflaPy(route) {
	if (!route.auth || route.method === "GET" || /\{\w+\}/.test(route.path) || hasRole(route)) return null
	const fn = route.py.fn
	if (!fn?.node) return null
	const writes = []
	walk(field(fn.node, "body"), n => {
		if (n.type === "call" && /^(create|add|insert|insert_one|bulk_create)$/.test(callName(n)) && /session|db|objects|collection|crud|repo/.test(callObject(n)?.text ?? "")) writes.push({ name: callName(n), line: lineOf(n) })
	})
	if (writes.length === 0) return null
	if (/request\.user|current_user|g\.user|get_jwt_identity|user_id|owner|author|created_by/.test(fn.node.text)) return null
	if (pyParams(fn.node).some(p => /user/i.test(p.name))) return null
	return {
		rule: "BFLA",
		owasp: "API5:2023 Broken Function Level Authorization",
		severity: "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: where(route, fn.file, writes[0].line),
		message: `Any signed-in user can ${writes.map(w => w.name).join(", ")} here, and the new record is not tied to them, so this looks like shared data with no role check.`,
		fix: "Add a role check (an admin-only permission or decorator), or store the caller as the owner if users should own these records."
	}
}

// API3: privileged fields set from the request body
export function massAssignmentPy(route) {
	const fn = route.py.fn
	if (!fn?.node || route.method === "GET") return null
	const body = field(fn.node, "body")
	const bodyVars = new Set()
	const privileged = new Map()
	let hit = null
	walk(body, n => {
		if (hit) return false
		if (n.type === "assignment") {
			const left = field(n, "left")
			const right = field(n, "right")
			if (left?.type === "identifier" && right && BODY.test(right.text)) bodyVars.add(left.text)
			// admin = request_data["admin"]: a privileged value the client chose
			const key = right?.type === "subscript" ? pyString(right.namedChildren[1]) : right?.type === "call" && callName(right) === "get" ? pyString(posArgs(right)[0]) : null
			if (left?.type === "identifier" && key && SENSITIVE_FIELD.test(key) && (bodyVars.has(rootOf(right)) || BODY.test(right.text))) privileged.set(left.text, key)
		}
		if (n.type !== "call") return
		const name = callName(n)
		// User(**request.json), obj.update(**data)
		for (const a of field(n, "arguments")?.namedChildren ?? []) {
			if (a.type === "dictionary_splat" && (BODY.test(a.text) || bodyVars.has(a.namedChildren[0]?.text))) {
				if (/^[A-Z]/.test(name) || /^(update|create|insert|from_dict|bulk_create)$/.test(name)) hit = { line: lineOf(n), what: `${field(n, "function").text}(**body)`, privileged: false }
			}
			// User(admin=admin), User(is_admin=data["is_admin"])
			// project.invite(user, role=...): granting someone else a role is the inviter's job, not self-promotion
			if (a.type === "keyword_argument" && SENSITIVE_FIELD.test(field(a, "name").text) && !/invite|add_member|grant|assign|share/i.test(name)) {
				const v = field(a, "value")
				// admin = True after "if request_data['admin']": the value still comes from the client
				const k = field(a, "name").text
				const fromBody = [...bodyVars].some(b => new RegExp(`${b}\\[['"]${k}['"]\\]|${b}\\.get\\(['"]${k}['"]|['"]${k}['"]\\s+in\\s+${b}`).test(body.text))
				if (privileged.has(v.text) || BODY.test(v.text) || bodyVars.has(rootOf(v)) || (v.type === "identifier" && fromBody)) hit = { line: lineOf(n), what: `${field(n, "function").text}(${field(a, "name").text}=…)`, privileged: true, field: field(a, "name").text }
			}
		}
		// for k, v in data.items(): setattr(obj, k, v)
		if (name === "setattr" && n.parent && /for\s+\w+\s*,\s*\w+\s+in\s+(\w+)\.items\(\)/.test(enclosingFor(n)?.text ?? "")) {
			const src = enclosingFor(n).text.match(/in\s+(\w+)\.items\(\)/)[1]
			if (bodyVars.has(src) || BODY.test(src)) hit = { line: lineOf(n), what: "setattr() for every key in the body", privileged: false }
		}
	})
	if (!hit) return null
	return {
		rule: "MASS_ASSIGNMENT",
		owasp: "API3:2023 Broken Object Property Level Authorization",
		severity: hasRole(route) ? "LOW" : hit.privileged || /user|account|member|register|signup|profile/i.test(route.path) ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: where(route, fn.file, hit.line),
		message: hit.privileged ? `${hit.field} is taken from the request body in ${hit.what}, so a client chooses its own privileges.` : `${hit.what} copies the whole request body onto a record, so a client can set any field, including role or admin flags.`,
		fix: "Copy only the fields a client may set (a schema or serializer with an explicit field list), and set privileged fields on the server."
	}
}
const rootOf = node => {
	let n = node
	while (n && (n.type === "subscript" || n.type === "attribute" || n.type === "call")) n = n.namedChildren[0]
	return n?.text ?? null
}
const enclosingFor = node => {
	for (let n = node.parent; n; n = n.parent) {
		if (n.type === "for_statement") return n
		if (n.type === "function_definition") return null
	}
	return null
}

// API3: secrets sent back: a dict with the password, obj.__dict__, or a serializer with every field
export function dataExposurePy(route) {
	const { fn, ctx, cls } = route.py
	if (!fn?.node && !cls) return null
	const hits = []
	const seen = new Set()
	// the view and what it calls, two levels deep
	const visit = (node, file, depth) => {
		if (!node || depth > 2 || seen.has(node.id)) return
		seen.add(node.id)
		walk(field(node, "body") ?? node, n => {
			if (n.type === "pair") {
				const key = pyString(field(n, "key"))
				const value = field(n, "value")
				// "password": user.password, not "secret": book.secret_content
				if (key && SECRET_FIELD.test(key) && value?.type === "attribute" && SECRET_FIELD.test(field(value, "attribute").text)) hits.push({ file, line: lineOf(n), what: `"${key}": ${value.text}` })
			}
			if (n.type === "call" && /^(model_to_dict|vars)$/.test(callName(n)) && /return|jsonify|Response|JsonResponse/.test(n.parent?.parent?.text?.slice(0, 40) ?? "")) hits.push({ file, line: lineOf(n), what: `${callName(n)}(…) of a whole record`, weak: true })
			if (n.type === "call" && depth < 2) {
				const found = ctx.lookup(field(n, "function")?.text ?? "", file)
				if (found?.node?.type === "function_definition") visit(found.node, found.file, depth + 1)
			}
		})
	}
	if (fn?.node) visit(fn.node, fn.file, 0)
	// a DRF serializer with fields = "__all__" on a model that has secret fields
	const serializer = cls ? ctx.classAttr(cls, "serializer_class") : null
	if (serializer) {
		const s = ctx.lookup(serializer.text, cls.file)
		const meta = s?.node ? field(s.node, "body")?.namedChildren.find(c => c.type === "class_definition" && field(c, "name").text === "Meta") : null
		if (meta && /fields\s*=\s*['"]__all__['"]/.test(meta.text)) {
			const model = meta.text.match(/model\s*=\s*([\w.]+)/)?.[1]
			const m = model ? ctx.lookup(model, s.file) : null
			const secret = m?.attrs ? [...m.attrs.keys()].find(k => SECRET_FIELD.test(k)) : null
			if (secret && !/exclude|write_only|extra_kwargs/.test(meta.text)) hits.push({ file: s.file, line: lineOf(meta), what: `${serializer.text} with fields = "__all__", which includes ${secret}` })
		}
	}
	const strong = hits.filter(h => !h.weak)
	if (!strong.length) return null
	if (/login|signin|token|auth|refresh|session/i.test(route.path) && strong.every(h => /token/i.test(h.what))) return null
	const [hit] = strong
	return {
		rule: "DATA_EXPOSURE",
		owasp: "API3:2023 Broken Object Property Level Authorization",
		severity: !route.auth ? "HIGH" : hasRole(route) ? "LOW" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: where(route, hit.file, hit.line),
		message: `A secret goes back in the answer: ${hit.what}.`,
		fix: "Leave secret fields out of responses: list the fields you return, or mark them write_only / exclude them in the serializer."
	}
}

// API7: the server fetches a URL the client chose
export function ssrfPy(route) {
	const { fn } = route.py
	if (!fn?.node) return null
	const body = field(fn.node, "body")
	const tainted = new Map()
	// FastAPI query parameters: def fetch(url: str)
	const pathParams = route.path.match(/\{(\w+)\}/g)?.map(p => p.slice(1, -1)) ?? []
	for (const p of pyParams(fn.node)) if (p.name && !pathParams.includes(p.name) && /^(str|HttpUrl|AnyUrl|AnyHttpUrl|Optional\[str\]|str \| None)$/.test(p.type) && route.framework === "fastapi") tainted.set(p.name, { in: "query", name: p.name })
	const inputOf = node => {
		let found = null
		walk(node, n => {
			if (found) return false
			if (n.type === "identifier" && tainted.has(n.text)) found = tainted.get(n.text)
			// request.args.get("url"), request.json["url"], request.GET.get("url"), request.data.get("url")
			const src = n.type === "call" && callName(n) === "get" ? callObject(n) : n.type === "subscript" ? n.namedChildren[0] : null
			const keyNode = n.type === "call" ? posArgs(n)[0] : n.type === "subscript" ? n.namedChildren[1] : null
			if (src && /request\.(args|values|GET|query_params)$/.test(src.text)) {
				const k = pyString(keyNode)
				if (k) found = { in: "query", name: k }
			} else if (src && /request\.(json|form|data|POST)$|get_json\(\)$/.test(src.text)) {
				const k = pyString(keyNode)
				if (k) found = { in: "body", name: k }
			}
		})
		return found
	}
	const hits = []
	let checked = false
	const values = new Map()
	walk(body, n => {
		if (n.type === "assignment") {
			const left = field(n, "left")
			if (left?.type === "identifier" && field(n, "right")) values.set(left.text, field(n, "right"))
			const input = field(n, "right") && inputOf(field(n, "right"))
			if (left?.type === "identifier" && input) tainted.set(left.text, input)
		}
		if (n.type !== "call") return
		const name = callName(n)
		if (URL_CHECK.test(name) && posArgs(n).some(a => inputOf(a))) checked = true
		const object = callObject(n)?.text ?? ""
		const isClient = (/^(get|post|put|patch|delete|head|request|stream)$/.test(name) && CLIENT.test(object) && !/request$|self$|args|form|json|GET|POST|data|dict|kwargs|headers|cache|os\.environ|config|settings/.test(object)) || /^(urlopen|urlretrieve)$/.test(name)
		if (!isClient) return
		const urlArg = name === "request" ? posArgs(n)[1] ?? kwarg(n, "url") : posArgs(n)[0] ?? kwarg(n, "url")
		const input = urlArg && inputOf(urlArg)
		if (input) hits.push({ call: n, arg: urlArg, input, client: `${object ? object + "." : ""}${name}` })
	})
	if (!hits.length || checked) return null
	const [hit] = hits
	// url = f"https://api.host/{q}" if q else f"https://api.host/", then requests.get(url)
	const leadOf = (arg, depth = 0) => {
		if (!arg || depth > 3) return [""]
		if (arg.type === "identifier" && values.has(arg.text)) return leadOf(values.get(arg.text), depth + 1)
		if (arg.type === "parenthesized_expression") return leadOf(arg.namedChildren[0], depth + 1)
		if (arg.type === "conditional_expression") return [arg.namedChildren[0], arg.namedChildren[2]].flatMap(x => leadOf(x, depth + 1))
		if (arg.type === "string") return [arg.text.replace(/^[fFrRbB]*['"]/, "")]
		if (arg.type === "binary_operator") return [pyString(field(arg, "left")) ?? ""]
		return [""]
	}
	const fixed = leadOf(hit.arg).every(lead => FIXED_HOST.test(lead))
	return {
		rule: "SSRF",
		owasp: "API7:2023 Server Side Request Forgery",
		severity: fixed ? "MEDIUM" : "HIGH",
		route: `${route.method} ${route.path}`,
		where: where(route, fn.file, lineOf(hit.call)),
		message: fixed
			? `${hit.client}() puts client input into a fixed host's URL, so the client can change the path or add parameters.`
			: `${hit.client}() requests a URL the client controls, so the server can be sent to internal hosts or 169.254.169.254.`,
		fix: fixed ? "Quote the value (urllib.parse.quote) and validate it against what the API expects." : "Allow only known hosts: parse the URL, check the hostname against an allow-list, and block private and link-local addresses.",
		input: hit.input
	}
}

export const PY_RULES = [bolaPy, bflaPy, massAssignmentPy, dataExposurePy, ssrfPy]

const randomIds = route => {
	const params = (route.path.match(/[:{<](?:\w+:)?(\w+)/g) ?? []).map(p => p.replace(/^[:{<](\w+:)?/, ""))
	return params.length > 0 && params.filter(p => RECORD_PARAM.test(p)).every(p => /uuid|guid/i.test(p))
}
