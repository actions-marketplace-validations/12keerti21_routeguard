// Maps the routes of a Python API: Flask (blueprints, Flask-RESTful and RESTX, MethodView, connexion
// OpenAPI specs), FastAPI (routers, include_router, dependencies) and Django with Django REST Framework
// (urlpatterns, include, routers, ViewSets, permission classes).
import { existsSync, readFileSync, readdirSync } from "node:fs"
import path from "node:path"
import { classify, ignoredRules } from "../mapper.js"
import { initPy, listPyFiles, parsePy, walk, field, lineOf, pyString, callName, callObject, posArgs, kwarg, pyParams, items } from "./ast.js"

const VERBS = ["get", "post", "put", "patch", "delete", "head", "options"]
// middleware and decorators that run on a route but say nothing about who is calling
const NOT_ENFORCED = /get_db\b|generate_session|get_session|db_session|sessionmaker|SessionLocal|SessionDep|get_async_session|get_locale|translator|get_settings|pagination|optional|maybe|limit|throttle|cache|csrf|cors|gzip|logger|logging|log_request|access_log|trace|swagger|doc|deprecat|validate|schema|marshal|expect|response|inject|transaction|atomic|timer|metric|vary|never_cache|cached|etag|require_http_methods|require_(GET|POST|safe)|api_view|staticmethod|classmethod|property|wraps|response_model|db_session|with_session|use_kwargs|use_args|doc_|tags?$/i
const AUTH_NAME = /auth|login|logged|jwt|token|session|signed|current_?user|active_?user|require_?user|protect|bearer|api_?key|basic|oauth|oidc|keycloak|IsAuthenticated|permission|verified|get_current|requires/i
const ROLE_NAME = /staff_member_required|admin|superuser|staff|role|permission_required|IsAdminUser|DjangoModelPermissions|DjangoObjectPermissions|scope|privilege|owner_?required|roles?_required|group_required|user_passes_test|PermissionRequired|has_?perm|rbac|acl|moderator|manager/i
// DRF permission classes: AllowAny makes a view public whatever the defaults say
const PUBLIC_PERMISSION = /^(AllowAny|permissions\.AllowAny)$/
const READ_ONLY_OPEN = /OrReadOnly/

export function classifyPy(names, method = "GET") {
	const enforced = names.filter(n => !NOT_ENFORCED.test(n.replace(/\(.*$/, "")) || /login_required|permission_required|roles_required/.test(n))
	// IsAuthenticatedOrReadOnly lets reads through
	const applies = enforced.filter(n => !(READ_ONLY_OPEN.test(n) && ["GET", "HEAD", "OPTIONS"].includes(method)))
	const { auth, role } = classify(applies)
	const rolePy = role || applies.some(n => ROLE_NAME.test(n))
	return { auth: auth || rolePy || applies.some(n => AUTH_NAME.test(n)), role: rolePy }
}

const textOf = node => (node?.text ?? "?").replace(/\s+/g, " ")
const nameOf = node => {
	if (!node) return "?"
	if (node.type === "call") return nameOf(field(node, "function")) + (posArgs(node).length || field(node, "arguments")?.namedChildren.length ? `(${textOf(field(node, "arguments")).slice(1, -1).slice(0, 40)})` : "")
	const t = textOf(node)
	return t.length > 60 ? `${t.slice(0, 57)}…` : t
}

// "<int:pk>" → "{pk}", "(?P<pk>\d+)" → "{pk}", "^articles/?$" → "articles"
function normalisePath(p) {
	// each joined piece may carry its own ^ and $: "^api/" + "^documents/$"
	let s = p
		.replace(/\(\?P<(\w+)>(?:[^()]|\([^()]*\))*\)/g, "{$1}")
		.replace(/<(?:[a-z_]+:)?(\w+)>/g, "{$1}")
		.replace(/(^|\/)\^/g, "$1")
		.replace(/\$(?=\/|$)/g, "")
		.replace(/\/\?(?=\/|$)/g, "")
		.replace(/\\\./g, ".")
		.replace(/\\/g, "")
	s = s.replace(/\/+/g, "/")
	if (!s.startsWith("/")) s = `/${s}`
	return s.length > 1 ? s.replace(/\/$/, "") : s
}

export async function mapPyRoutes(root) {
	await initPy()
	const files = listPyFiles(root)
	const routes = []
	Object.defineProperty(routes, "frameworks", { value: {} })
	if (files.length === 0) return routes

	// modules by every dotted name they can be imported as: app/api/deps.py is app.api.deps, api.deps and deps
	const moduleFiles = new Map()
	for (const file of files) {
		const rel = path.relative(root, file).replace(/\.py$/, "").split(path.sep)
		if (rel.at(-1) === "__init__") rel.pop()
		for (let i = 0; i < rel.length; i++) {
			const name = rel.slice(i).join(".")
			if (name && !moduleFiles.has(name)) moduleFiles.set(name, file)
		}
	}

	const info = new Map()
	const classes = new Map()
	const functions = new Map()
	const constNodes = new Map()
	for (const file of files) {
		const tree = parsePy(file)
		if (!tree) continue
		const imports = new Map()
		const defs = new Map()
		const assigns = new Map()
		const rootNode = tree.rootNode
		const text = rootNode.text
		const fw = new Set()
		if (/^\s*(from|import)\s+flask\b/m.test(text)) fw.add("flask")
		if (/^\s*(from|import)\s+(fastapi|starlette)\b/m.test(text)) fw.add("fastapi")
		if (/^\s*(from|import)\s+(django|rest_framework)\b/m.test(text)) fw.add("django")
		if (/^\s*(from|import)\s+connexion\b/m.test(text)) fw.add("connexion")
		for (const f of fw) routes.frameworks[f] = (routes.frameworks[f] ?? 0) + 1
		const pkgParts = path.relative(root, path.dirname(file)).split(path.sep).filter(Boolean)
		const resolveModule = (mod, level) => {
			if (level) {
				const base = pkgParts.slice(0, pkgParts.length - (level - 1))
				return [...base, ...(mod ? mod.split(".") : [])].join(".")
			}
			return mod
		}
		for (const node of rootNode.namedChildren) collectTop(node)
		// imports inside functions too: create_app() often imports its blueprints there
		walk(rootNode, n => {
			if ((n.type === "import_from_statement" || n.type === "import_statement") && n.parent?.type !== "module") {
				const before = new Map(imports)
				collectTop(n)
				for (const [k, v] of before) imports.set(k, v)
				return false
			}
		})
		function collectTop(node) {
			if (node.type === "import_from_statement") {
				const modNode = field(node, "module_name")
				let level = 0
				let mod = modNode?.text ?? ""
				if (modNode?.type === "relative_import") {
					level = (mod.match(/^\.+/) ?? [""])[0].length
					mod = mod.replace(/^\.+/, "")
				}
				const full = resolveModule(mod, level)
				for (const n of node.namedChildren.filter(c => c !== modNode)) {
					if (n.type === "dotted_name") imports.set(n.text, { module: full, name: n.text })
					if (n.type === "aliased_import") imports.set(field(n, "alias").text, { module: full, name: field(n, "name").text })
				}
			} else if (node.type === "import_statement") {
				for (const n of node.namedChildren) {
					if (n.type === "dotted_name") imports.set(n.text.split(".")[0], { module: n.text.split(".")[0], name: null })
					if (n.type === "aliased_import") imports.set(field(n, "alias").text, { module: field(n, "name").text, name: null })
				}
			} else if (node.type === "decorated_definition") {
				const def = field(node, "definition")
				collectDef(def, node)
			} else if (node.type === "function_definition" || node.type === "class_definition") collectDef(node, null)
			else if (node.type === "expression_statement" && node.namedChildren[0]?.type === "assignment") {
				const a = node.namedChildren[0]
				const left = field(a, "left")
				const right = field(a, "right")
				if (left?.type === "identifier" && right) {
					assigns.set(left.text, right)
					if (!constNodes.has(left.text)) constNodes.set(left.text, right)
				}
			} else if (node.type === "if_statement" || node.type === "try_statement") {
				// imports and definitions inside if TYPE_CHECKING:, try/except ImportError
				for (const c of node.namedChildren) if (c.type === "block") c.namedChildren.forEach(collectTop)
				for (const c of node.namedChildren) if (/clause/.test(c.type)) c.namedChildren.filter(x => x.type === "block").forEach(b => b.namedChildren.forEach(collectTop))
			}
		}
		function collectDef(def, decorated) {
			const name = field(def, "name")?.text
			if (!name) return
			const entry = { node: def, decorated, file, name }
			defs.set(name, entry)
			if (def.type === "class_definition") {
				const attrs = new Map()
				const methods = new Map()
				for (const s of field(def, "body")?.namedChildren ?? []) {
					if (s.type === "expression_statement" && s.namedChildren[0]?.type === "assignment") {
						const a = s.namedChildren[0]
						if (field(a, "left")?.type === "identifier" && field(a, "right")) {
							attrs.set(field(a, "left").text, field(a, "right"))
							const v = field(a, "right")
							if (!constNodes.has(field(a, "left").text) && (v.type === "string" || v.type === "concatenated_string")) constNodes.set(field(a, "left").text, v)
						}
					}
					const fn = s.type === "decorated_definition" ? field(s, "definition") : s
					if (fn.type === "function_definition") methods.set(field(fn, "name").text, { node: fn, decorated: s.type === "decorated_definition" ? s : null, file })
				}
				entry.bases = (field(def, "superclasses")?.namedChildren ?? []).filter(c => c.type !== "keyword_argument").map(c => c.text)
				entry.attrs = attrs
				entry.methods = methods
				if (!classes.has(name)) classes.set(name, [])
				classes.get(name).push(entry)
			} else {
				if (!functions.has(name)) functions.set(name, [])
				functions.get(name).push(entry)
			}
		}
		info.set(file, { file, tree, imports, defs, assigns, fw })
	}

	// constants resolve on demand: API_V1_STR = "/api/v1" in a settings class works from anywhere
	const resolving = new Set()
	const consts = name => {
		const key = name.split(".").at(-1)
		const node = constNodes.get(key)
		if (!node || resolving.has(key)) return undefined
		resolving.add(key)
		const v = pyString(node, consts)
		resolving.delete(key)
		return v ?? undefined
	}

	// what a name means in a file: a def, a class, a module, or a module-level object
	function lookup(name, file, depth = 0) {
		const fi = info.get(file)
		if (!fi || depth > 6) return null
		const [head, ...rest] = name.split(".")
		if (rest.length === 0) {
			if (fi.defs.has(head)) return { kind: "def", ...fi.defs.get(head) }
			if (fi.assigns.has(head)) return { kind: "object", file, name: head, node: fi.assigns.get(head) }
		}
		const imp = fi.imports.get(head)
		if (imp) {
			if (imp.name) {
				// from x import y: y may be a module (x.y) or a name inside x
				const asModule = moduleFiles.get(`${imp.module}.${imp.name}`)
				if (asModule) return rest.length ? lookup(rest.join("."), asModule, depth + 1) : { kind: "module", file: asModule }
				const target = moduleFiles.get(imp.module)
				if (target) {
					const found = lookup(imp.name, target, depth + 1)
					if (found && rest.length && found.kind === "module") return lookup(rest.join("."), found.file, depth + 1)
					if (found && rest.length && found.kind === "def" && found.methods) return found.methods.get(rest[0]) ? { kind: "method", ...found.methods.get(rest[0]), cls: found } : null
					return rest.length ? null : found
				}
				return null
			}
			// import a.b.c as m / import a
			let mod = imp.module
			for (let i = 0; i <= rest.length; i++) {
				const f = moduleFiles.get([mod, ...rest.slice(0, i)].join("."))
				if (f && i === rest.length) return { kind: "module", file: f }
				if (f && i < rest.length) {
					const inner = lookup(rest.slice(i).join("."), f, depth + 1)
					if (inner) return inner
				}
			}
		}
		if (rest.length === 1 && fi.defs.get(head)?.methods) {
			const m = fi.defs.get(head).methods.get(rest[0])
			if (m) return { kind: "method", ...m, cls: fi.defs.get(head) }
		}
		return null
	}

	// a class and every base it has in the project, nearest first
	// tree-sitter hands out a new object for a node on every access, so nodes are compared by id
	function lineage(cls, seen = new Set()) {
		if (!cls || seen.has(cls.node.id)) return []
		seen.add(cls.node.id)
		const out = [cls]
		for (const b of cls.bases ?? []) {
			const found = lookup(b, cls.file)
			const target = found?.kind === "def" && found.methods ? found : (classes.get(b.split(".").at(-1)) ?? [])[0]
			if (target && target.node.id !== cls.node.id) out.push(...lineage(target, seen))
		}
		return out
	}
	const allBases = cls => [...new Set(lineage(cls).flatMap(c => [c.name, ...(c.bases ?? []).map(b => b.split(".").at(-1))]))]
	const classAttr = (cls, name) => lineage(cls).map(c => c.attrs?.get(name)).find(Boolean) ?? null
	const classMethod = (cls, name) => lineage(cls).map(c => c.methods?.get(name)).find(Boolean) ?? null

	// decorators of a def as names, the route decorators taken out
	const decoratorsOf = decorated => (decorated?.namedChildren ?? []).filter(c => c.type === "decorator").map(d => d.namedChildren[0])

	// a dependency or decorator as the names it brings: Depends(get_current_user) → get_current_user
	function dependencyNames(node, file) {
		const out = []
		walk(node, n => {
			if (n.type === "call" && /^(Depends|Security)$/.test(callName(n))) {
				const target = posArgs(n)[0]
				if (target) out.push(target.type === "call" ? nameOf(target) : textOf(target))
				return false
			}
		})
		return out
	}
	// a FastAPI parameter: user: CurrentUser, user = Depends(get_user), user: Annotated[User, Depends(get_user)]
	// user: PrivateUser = Depends(get_current_user) as a class attribute, here or in a base class
	const classDependencies = cls =>
		lineage(cls).flatMap(c => (field(c.node, "body")?.namedChildren ?? []).filter(x => x.type === "expression_statement").flatMap(x => dependencyNames(x, c.file)))
	const aliasCache = new Map()
	function paramDependencies(fn, file) {
		const out = []
		for (const p of pyParams(fn)) {
			if (p.default) out.push(...dependencyNames(p.default, file))
			if (p.type) {
				if (/Depends|Security/.test(p.type)) out.push(...dependencyNames(field(fn, "parameters").namedChildren.find(x => x.text.startsWith(p.name))))
				else {
					const alias = p.type.split(".").at(-1)
					if (!aliasCache.has(`${file}:${alias}`)) {
						const found = lookup(p.type, file)
						aliasCache.set(`${file}:${alias}`, found?.kind === "object" ? dependencyNames(found.node, found.file) : [])
					}
					out.push(...aliasCache.get(`${file}:${alias}`))
				}
			}
		}
		return out
	}

	// a body that clearly checks the caller, for names that say nothing
	const AUTH_BODY = /request\.user|current_user|get_jwt_identity|verify_jwt|jwt\.decode|Authorization|401|Unauthorized|abort\(\s*401|login_required|is_authenticated/
	const ROLE_BODY = /is_admin|is_superuser|is_staff|\.admin\b|role|403|Forbidden|abort\(\s*403|has_perm/
	function hintFor(name, file) {
		if (classifyPy([name]).auth || NOT_ENFORCED.test(name)) return null
		const found = lookup(name.replace(/\(.*$/, ""), file)
		const node = found?.node
		if (!node || !(found.kind === "def" || found.kind === "method")) return null
		const t = node.text
		return AUTH_BODY.test(t) ? (ROLE_BODY.test(t) && /403|Forbidden|admin|superuser|staff/.test(t) ? "checksRole" : "checksAuth") : null
	}
	const withHint = (name, file) => {
		const h = hintFor(name, file)
		return h ? `${name} (${h})` : name
	}

	// in-handler checks: if not current_user.is_admin: abort(403), request.user.has_perm(...)
	function handlerChecks(fn) {
		if (!fn) return []
		const found = []
		walk(field(fn, "body"), n => {
			if (n.type === "function_definition" || n.type === "class_definition") return false
			if (n.type === "if_statement") {
				const cond = field(n, "condition")?.text ?? ""
				const then = field(n, "consequence")?.text ?? ""
				const otherwise = field(n, "alternative")?.text ?? ""
				if (/is_admin|is_superuser|is_staff|\.admin\b|\.role\b|has_perm|has_role/.test(cond) && /403|Forbidden|PermissionDenied|abort|raise|401|Unauthorized|[Oo]nly [Aa]dmin/.test(then + otherwise)) found.push("admin check(in handler, role)")
				// if note.user_id != current_user.id: abort(403) is an ownership check, judged by the BOLA rule
				else if (!/[!=]=|\bis not\b/.test(cond) && /is_authenticated|current_user|request\.user|token|auth/i.test(cond) && /401|403|Unauthorized|Forbidden|[Nn]ot [Aa]uthenticated|login|abort|raise|redirect/.test(then)) found.push("login check(in handler)")
			}
			if (n.type === "call" && /^(verify_jwt_in_request|login_required|check_permissions|check_object_permissions|require_admin|has_perm|permission_required)$/.test(callName(n))) found.push(`${callName(n)}(in handler)`)
		})
		// resp = token_validator(request.headers.get("Authorization")); if "error" in resp: return ..., 401
		const body = field(fn, "body")?.text ?? ""
		const tokenCall = body.match(/\b(\w*(token|auth|jwt)\w*_?(validator|verify|required|check|decode|validate)\w*|verify_?(token|jwt|auth)\w*|decode_?(auth_?)?token|authenticate\w*)\s*\(/i)
		if (tokenCall && /\b401\b|Unauthorized|abort\(/.test(body)) found.push(`${tokenCall[1]}(in handler)`)
		return [...new Set(found)]
	}

	const add = (r, fnEntry, file, line, extra = {}) => {
		const method = r.method
		const middleware = [...r.middleware, ...(fnEntry?.node ? handlerChecks(fnEntry.node) : [])]
		const publicByPermission = r.public
		const { auth, role } = publicByPermission ? { auth: false, role: false } : classifyPy(middleware, method)
		const route = {
			method,
			path: normalisePath(r.path),
			middleware,
			auth,
			role,
			handler: r.handler,
			file: path.relative(root, file),
			line,
			framework: r.framework,
			anchored: r.anchored ?? true,
			lang: "py"
		}
		// def debug(): if app.config.get("SAFE_MODE") is True: ...: the view does nothing unless a setting is on
		const first = fnEntry?.node ? field(fnEntry.node, "body")?.namedChildren.find(c => c.type !== "expression_statement" || c.namedChildren[0]?.type !== "string") : null
		const bodyGuard = first?.type === "if_statement" && /config|settings|DEBUG|SAFE_MODE|getenv|environ|ENABLE|enabled/i.test(field(first, "condition")?.text ?? "") ? field(first, "condition").text.slice(0, 60) : null
		Object.defineProperties(route, {
			py: { value: { fn: fnEntry, ctx, ...extra, conditional: extra.conditional ?? bodyGuard } },
			root: { value: root },
			rootFile: { value: r.origin ?? root },
			ignored: { value: ignoredRules(file, line) },
			guards: { value: [] }
		})
		routes.push(route)
	}

	const ctx = { root, info, lookup, classes, functions, consts, lineage, classAttr, classMethod, allBases }

	// CTFdFlask(Flask), ApiExt(Api), UserAPIRouter(APIRouter): a project class standing for the framework one
	function ctorKind(name, file, kinds) {
		if (kinds.includes(name)) return { kind: name, cls: null }
		const found = lookup(name, file) ?? ((classes.get(name) ?? [])[0] ? { kind: "def", ...(classes.get(name) ?? [])[0] } : null)
		if (!found?.methods) return null
		const base = allBases(found).find(b => kinds.includes(b))
		return base ? { kind: base, cls: found } : null
	}

	mapFlask()
	mapFastApi()
	mapDjango()
	mapConnexion()

	// the same route reached twice (a file seen as a root and through an include) is kept once
	const seen = new Set()
	const unique = routes.filter(r => {
		const key = `${r.method} ${r.path} ${r.file}:${r.line}`
		if (seen.has(key)) return false
		seen.add(key)
		return true
	})
	// a urls.py mapped on its own before its parent's include reached it: keep the copy with the prefix
	const byView = new Map()
	for (const r of unique) byView.set(`${r.method} ${r.file}:${r.line}`, [...(byView.get(`${r.method} ${r.file}:${r.line}`) ?? []), r.path])
	const prefixed = unique.filter(r => r.framework !== "django" || !byView.get(`${r.method} ${r.file}:${r.line}`).some(p => p.length > r.path.length && p.endsWith(r.path)))
	routes.length = 0
	routes.push(...prefixed)
	Object.defineProperty(routes, "pyContext", { value: ctx })
	return routes

	// ---------- Flask ----------
	function mapFlask() {
		// app = Flask(...), bp = Blueprint(..., url_prefix=), api = Api(app, prefix=), ns = api.namespace(path=)
		const objects = new Map()
		const key = (file, name) => `${file}#${name}`
		const objectOf = (expr, file) => {
			if (!expr) return null
			if (expr.type === "identifier" || expr.type === "attribute") {
				const k = key(file, expr.text)
				if (objects.has(k)) return objects.get(k)
				const found = lookup(expr.text, file)
				if (found?.kind === "object") return objects.get(key(found.file, found.name)) ?? null
			}
			return null
		}
		for (const [file, fi] of info) {
			if (!fi.fw.has("flask") && !/Blueprint|Flask|Namespace|Api\w*\(/.test(fi.tree.rootNode.text)) continue
			walk(fi.tree.rootNode, n => {
				if (n.type !== "assignment") return
				const left = field(n, "left")
				const right = field(n, "right")
				if (left?.type !== "identifier" || right?.type !== "call") return
				const ctorName = callName(right)
				const ck = ctorKind(ctorName, file, ["Flask", "Blueprint", "Api", "Namespace"])
				const ctor = ctorName === "namespace" ? "namespace" : ck?.kind ?? ctorName
				if (ctor === "Flask") objects.set(key(file, left.text), { kind: "app", prefix: "", mw: [], file, origin: `${file}:${lineOf(n)}` })
				else if (ctor === "Blueprint") objects.set(key(file, left.text), { kind: "bp", prefix: pyString(kwarg(right, "url_prefix"), consts) ?? "", mw: [], file, parent: null })
				else if (ctor === "Api" && (posArgs(right).length || /flask_restful|flask_restx|flask_restplus/.test(fi.tree.rootNode.text) || ck?.cls)) {
					const target = posArgs(right)[0]
					objects.set(key(file, left.text), { kind: "api", prefix: pyString(kwarg(right, "prefix"), consts) ?? "", mw: (items(kwarg(right, "decorators"))).map(nameOf), file, parentExpr: target, parent: null })
				} else if (ctor === "Namespace" || ctor === "namespace") {
					const p = pyString(kwarg(right, "path"), consts) ?? `/${pyString(posArgs(right)[0], consts) ?? ""}`
					objects.set(key(file, left.text), { kind: "ns", prefix: p, mw: items(kwarg(right, "decorators")).map(nameOf), file, parent: ctor === "namespace" ? objectOf(callObject(right), file) : null })
				}
			})
		}
		// wiring: register_blueprint, Api(app), add_namespace, before_request
		for (const [file, fi] of info) {
			if (!fi.fw.has("flask")) continue
			walk(fi.tree.rootNode, n => {
				if (n.type !== "call") return
				const name = callName(n)
				const owner = objectOf(callObject(n), file)
				if (name === "register_blueprint" && owner) {
					const bp = objectOf(posArgs(n)[0], file)
					if (bp && bp !== owner) {
						bp.parent = owner
						const p = pyString(kwarg(n, "url_prefix"), consts)
						if (p !== null) bp.prefix = p
					}
				}
				if (name === "add_namespace" && owner) {
					const ns = objectOf(posArgs(n)[0], file)
					if (ns) {
						ns.parent = owner
						const p = pyString(kwarg(n, "path"), consts) ?? pyString(posArgs(n)[1], consts)
						if (p !== null) ns.prefix = p
					}
				}
				if (name === "init_app" && owner?.kind === "api") owner.parent = objectOf(posArgs(n)[0], file) ?? owner.parent
				if (/^before_(app_)?request$/.test(name) && owner) {
					const fnArg = posArgs(n)[0]
					if (fnArg) owner.mw.push(withHint(nameOf(fnArg), file))
				}
			})
		}
		for (const o of objects.values()) if (o.kind === "api" && !o.parent && o.parentExpr) o.parent = objectOf(o.parentExpr, o.file)
		// @bp.before_request def check(): ...
		for (const [file, fi] of info) {
			for (const def of fi.defs.values()) {
				for (const d of decoratorsOf(def.decorated)) {
					const target = d.type === "call" ? field(d, "function") : d
					if (target?.type === "attribute" && /^before_(app_)?request$/.test(field(target, "attribute").text)) {
						const owner = objectOf(field(target, "object"), file)
						if (owner) owner.mw.push(withHint(def.name, file))
					}
				}
			}
		}
		const chain = o => {
			const parts = []
			const mw = []
			let origin = null
			const seen = new Set()
			for (let x = o; x && !seen.has(x); x = x.parent) {
				seen.add(x)
				parts.unshift(x.prefix)
				mw.unshift(...x.mw)
				if (!x.parent) origin = x.origin ?? null
			}
			return { prefix: parts.join("/"), mw, anchored: Boolean(origin) || o.kind === "app", origin }
		}

		for (const [file, fi] of info) {
			if (!fi.fw.has("flask")) continue
			// decorated views: @bp.route("/x", methods=[...]), @app.get("/x")
			const visitDef = (def, decorated, cls) => {
				const decs = decoratorsOf(decorated)
				const routeDecs = []
				const others = []
				for (const d of decs) {
					const fn = d.type === "call" ? field(d, "function") : null
					const attr = fn?.type === "attribute" ? field(fn, "attribute").text : null
					const owner = fn?.type === "attribute" ? objectOf(field(fn, "object"), file) : null
					if (attr && (attr === "route" || VERBS.includes(attr)) && (owner || /app|bp|blueprint|api|views?|router/i.test(field(fn, "object").text)) && pyString(posArgs(d)[0], consts) !== null) routeDecs.push({ d, attr, owner })
					else others.push(d)
				}
				for (const { d, attr, owner } of routeDecs) {
					if (owner?.kind === "ns" || owner?.kind === "api") continue
					const methods = attr === "route" ? items(kwarg(d, "methods")).map(m => pyString(m, consts)?.toUpperCase()).filter(Boolean) : [attr.toUpperCase()]
					const { prefix, mw, anchored, origin } = owner ? chain(owner) : { prefix: "", mw: [], anchored: false }
					for (const method of methods.length ? methods : ["GET"]) {
						add({ method, path: `${prefix}/${pyString(posArgs(d)[0], consts)}`, middleware: [...mw, ...others.map(o => withHint(nameOf(o), file))], handler: def.name, framework: "flask", anchored, origin }, { node: def.node, file }, file, lineOf(d))
					}
				}
			}
			for (const def of fi.defs.values()) {
				if (def.node.type === "function_definition") visitDef(def, def.decorated)
				// @ns.route("/x") class Thing(Resource)
				if (def.node.type === "class_definition") {
					for (const d of decoratorsOf(def.decorated)) {
						const fn = d.type === "call" ? field(d, "function") : null
						if (fn?.type !== "attribute" || field(fn, "attribute").text !== "route") continue
						const owner = objectOf(field(fn, "object"), file)
						const paths = posArgs(d).map(a => pyString(a, consts)).filter(p => p !== null)
						if (!owner || !paths.length) continue
						resourceRoutes(def, paths, owner, file, lineOf(d))
					}
				}
			}
			// app.add_url_rule("/x", view_func=f, methods=[...]), api.add_resource(Thing, "/x")
			walk(fi.tree.rootNode, n => {
				if (n.type !== "call") return
				const name = callName(n)
				const owner = objectOf(callObject(n), file)
				if (name === "add_url_rule") {
					const rule = pyString(posArgs(n)[0], consts)
					const view = kwarg(n, "view_func") ?? posArgs(n)[2]
					if (rule === null || !view) return
					const methods = items(kwarg(n, "methods")).map(m => pyString(m, consts)?.toUpperCase()).filter(Boolean)
					// View.as_view("name"): one route per method the class handles
					if (view.type === "call" && callName(view) === "as_view") {
						const cls = lookup(callObject(view).text, file)
						if (cls?.methods) resourceRoutes(cls, [rule], owner, file, lineOf(n), methods)
						return
					}
					const target = lookup(view.text, file)
					const { prefix, mw, anchored, origin } = owner ? chain(owner) : { prefix: "", mw: [], anchored: false }
					const decs = target?.decorated ? decoratorsOf(target.decorated).map(d => withHint(nameOf(d), target.file)) : []
					for (const method of methods.length ? methods : ["GET"])
						add({ method, path: `${prefix}/${rule}`, middleware: [...mw, ...decs], handler: view.text, framework: "flask", anchored, origin }, target, file, lineOf(n))
				}
				if (/^add_\w*resource$/.test(name) && owner) {
					const cls = lookup(posArgs(n)[0]?.text ?? "", file)
					const paths = posArgs(n).slice(1).map(a => pyString(a, consts)).filter(p => p !== null)
					if (cls?.methods && paths.length) resourceRoutes(cls, paths, owner, file, lineOf(n))
				}
			})
		}

		// a Resource or MethodView: one route per HTTP method it defines
		function resourceRoutes(cls, paths, owner, file, line, only = []) {
			const { prefix, mw, anchored, origin } = owner ? chain(owner) : { prefix: "", mw: [], anchored: false }
			const classDecs = [...items(classAttr(cls, "method_decorators")), ...items(classAttr(cls, "decorators"))].map(d => withHint(nameOf(d), cls.file))
			const viewDecs = decoratorsOf(cls.decorated).filter(d => !/\.route$/.test(textOf(d.type === "call" ? field(d, "function") : d))).map(d => withHint(nameOf(d), cls.file))
			for (const verb of VERBS) {
				const m = classMethod(cls, verb)
				if (!m || (only.length && !only.includes(verb.toUpperCase()))) continue
				const decs = decoratorsOf(m.decorated).map(d => withHint(nameOf(d), m.file))
				for (const p of paths)
					add({ method: verb.toUpperCase(), path: `${prefix}/${p}`, middleware: [...mw, ...classDecs, ...viewDecs, ...decs], handler: `${cls.name}.${verb}`, framework: "flask", anchored, origin }, m, m.file, lineOf(m.node))
			}
		}
	}

	// ---------- FastAPI ----------
	function mapFastApi() {
		const objects = new Map()
		const key = (file, name) => `${file}#${name}`
		const objectOf = (expr, file) => {
			if (!expr) return null
			const k = key(file, expr.text)
			if (objects.has(k)) return objects.get(k)
			const found = lookup(expr.text, file)
			if (found?.kind === "object") return objects.get(key(found.file, found.name)) ?? null
			// from .routes import users; app.include_router(users.router)
			if (found?.kind === "module") return null
			return null
		}
		for (const [file, fi] of info) {
			if (!fi.fw.has("fastapi")) continue
			walk(fi.tree.rootNode, n => {
				if (n.type !== "assignment") return
				const left = field(n, "left")
				const right = field(n, "right")
				if (left?.type !== "identifier" || right?.type !== "call") return
				const ck = ctorKind(callName(right), file, ["FastAPI", "Starlette", "APIRouter"])
				if (!ck) return
				// a subclass that adds its own dependencies in __init__: UserAPIRouter → get_current_user
				const own = ck.cls ? dependencyNames(ck.cls.node, ck.cls.file) : []
				if (ck.kind !== "APIRouter") objects.set(key(file, left.text), { kind: "app", prefix: "", mw: [...own, ...dependencyNames(kwarg(right, "dependencies"), file)], file, origin: `${file}:${lineOf(n)}`, parents: [] })
				else objects.set(key(file, left.text), { kind: "router", prefix: pyString(kwarg(right, "prefix"), consts) ?? pyString(posArgs(right)[0], consts) ?? "", mw: [...own, ...dependencyNames(kwarg(right, "dependencies"), file)], file, parents: [] })
			})
		}
		// include_router(router, prefix=, dependencies=): a router can be included in several places
		const routerExpr = (expr, file) => {
			if (!expr) return null
			const direct = objectOf(expr, file)
			if (direct) return direct
			// users.router where users is an imported module
			if (expr.type === "attribute") {
				const mod = lookup(field(expr, "object").text, file)
				if (mod?.kind === "module") return objects.get(key(mod.file, field(expr, "attribute").text)) ?? null
			}
			return null
		}
		for (const [file, fi] of info) {
			if (!fi.fw.has("fastapi")) continue
			walk(fi.tree.rootNode, n => {
				if (n.type !== "call") return
				const name = callName(n)
				if (name !== "include_router" && name !== "mount") return
				const owner = routerExpr(callObject(n), file)
				const child = routerExpr(name === "mount" ? posArgs(n)[1] : posArgs(n)[0], file)
				if (!owner || !child || owner === child) return
				const prefix = pyString(name === "mount" ? posArgs(n)[0] : kwarg(n, "prefix"), consts) ?? ""
				child.parents.push({ parent: owner, prefix, mw: dependencyNames(kwarg(n, "dependencies"), file), conditional: settingGuard(n) })
			})
		}
		// every way down from an app to a router: [{ prefix, mw, origin }]
		const pathsTo = (o, seen = new Set()) => {
			if (seen.has(o)) return []
			seen.add(o)
			if (o.kind === "app") return [{ prefix: o.prefix, mw: [...o.mw], origin: o.origin, conditional: null }]
			if (!o.parents.length) return [{ prefix: o.prefix, mw: [...o.mw], origin: null, conditional: null }]
			return o.parents.flatMap(({ parent, prefix, mw, conditional }) =>
				pathsTo(parent, new Set(seen)).map(p => ({ prefix: `${p.prefix}/${prefix}/${o.prefix}`, mw: [...p.mw, ...mw, ...o.mw], origin: p.origin, conditional: conditional ?? p.conditional }))
			)
		}
		for (const [file, fi] of info) {
			if (!fi.fw.has("fastapi")) continue
			// @controller(router) class X: @router.get("/x") def m(self): the class's dependencies apply too
			const defs = [...fi.defs.values()].flatMap(d =>
				d.node.type === "class_definition" ? [...d.methods.values()].map(m => ({ ...m, name: field(m.node, "name").text, classDeps: classDependencies(d) })) : [d]
			)
			for (const def of defs) {
				if (def.node.type !== "function_definition") continue
				for (const d of decoratorsOf(def.decorated)) {
					const fn = d.type === "call" ? field(d, "function") : null
					if (fn?.type !== "attribute") continue
					const attr = field(fn, "attribute").text
					if (!VERBS.includes(attr) && attr !== "api_route") continue
					const owner = objectOf(field(fn, "object"), file)
					if (!owner) continue
					const p = pyString(posArgs(d)[0], consts) ?? pyString(kwarg(d, "path"), consts)
					if (p === null) continue
					const methods = attr === "api_route" ? items(kwarg(d, "methods")).map(m => pyString(m, consts)?.toUpperCase()).filter(Boolean) : [attr.toUpperCase()]
					const deps = [...dependencyNames(kwarg(d, "dependencies"), file), ...paramDependencies(def.node, file), ...(def.classDeps ?? [])].map(x => withHint(x, file))
					for (const via of pathsTo(owner))
						for (const method of methods.length ? methods : ["GET"])
							add({ method, path: `${via.prefix}/${p}`, middleware: [...via.mw.map(x => withHint(x, file)), ...deps], handler: def.name, framework: "fastapi", anchored: Boolean(via.origin), origin: via.origin }, { node: def.node, file }, file, lineOf(d), { conditional: via.conditional })
				}
			}
		}
	}

	// ---------- Django and DRF ----------
	function mapDjango() {
		const djangoFiles = [...info.values()].filter(fi => fi.fw.has("django"))
		if (!djangoFiles.length) return
		// ROOT_URLCONF and DRF's default permission classes from settings
		let rootConf = null
		let defaultPermissions = []
		for (const fi of info.values()) {
			const a = fi.assigns.get("ROOT_URLCONF")
			if (a && !rootConf) rootConf = pyString(a, consts)
			const rf = fi.assigns.get("REST_FRAMEWORK")
			if (rf?.type === "dictionary")
				for (const pair of rf.namedChildren.filter(c => c.type === "pair"))
					if (pyString(field(pair, "key")) === "DEFAULT_PERMISSION_CLASSES") defaultPermissions = items(field(pair, "value")).map(v => (pyString(v) ?? v.text).split(".").at(-1))
		}
		const done = new Set()
		const routers = new Map()
		const reachable = new Set()
		const expand = (file, prefix, mw, anchored, depth = 0) => {
			const fi = info.get(file)
			if (!fi || depth > 8 || done.has(`${file}|${prefix}`)) return
			done.add(`${file}|${prefix}`)
			reachable.add(file)
			collectRouters(file)
			const lists = []
			// urlpatterns = [...], and later urlpatterns = [debug] + urlpatterns or urlpatterns += router.urls
			// urlpatterns = decorate_urlpatterns(urlpatterns, require_admin_access) wraps every view
			const wrapped = []
			walk(fi.tree.rootNode, n => {
				if (n.type === "assignment" && field(n, "left")?.text === "urlpatterns") {
					const right = field(n, "right")
					if (right?.type === "call" && posArgs(right)[0]?.text === "urlpatterns") wrapped.push(...posArgs(right).slice(1).map(textOf))
					else lists.push(right)
				}
				if (n.type === "augmented_assignment" && field(n, "left")?.text === "urlpatterns") lists.push(field(n, "right"))
				if (n.type === "call" && callName(n) === "extend" && callObject(n)?.text === "urlpatterns") lists.push(posArgs(n)[0])
			})
			for (const list of lists) entries(list, file, prefix, [...mw, ...wrapped], anchored, depth)
		}
		const entries = (list, file, prefix, mw, anchored, depth) => {
			if (!list || depth > 8) return
			if (list.type === "binary_operator") {
				entries(field(list, "left"), file, prefix, mw, anchored, depth + 1)
				entries(field(list, "right"), file, prefix, mw, anchored, depth + 1)
				return
			}
			if (list.type === "attribute" && field(list, "attribute").text === "urls") {
				const r = routers.get(`${file}#${field(list, "object").text}`)
				if (r) routerRoutes(r, prefix, mw, anchored)
				return
			}
			if (list.type === "identifier") {
				// the list itself, already read from each assignment
				if (list.text === "urlpatterns") return
				const found = lookup(list.text, file)
				if (found?.kind === "object" && found.node.id !== list.parent?.id) entries(found.node, found.file, prefix, mw, anchored, depth + 1)
				return
			}
			for (const e of items(list)) {
				// [*router.urls, path(...)]
				if (e.type === "list_splat") {
					entries(e.namedChildren[0], file, prefix, mw, anchored, depth + 1)
					continue
				}
				if (e.type !== "call") continue
				const fn = callName(e)
				if (!/^(path|re_path|url)$/.test(fn)) continue
				const route = pyString(posArgs(e)[0], consts) ?? `<${textOf(posArgs(e)[0])}>`
				const view = posArgs(e)[1]
				if (!view) continue
				const full = `${prefix}/${route}`
				if (view.type === "call" && callName(view) === "include") {
					const target = posArgs(view)[0]
					const modName = pyString(target, consts)
					const tuple = target?.type === "tuple" ? target.namedChildren[0] : null
					if (modName) {
						const f = moduleFiles.get(modName)
						if (f) expand(f, full, mw, anchored, depth + 1)
					} else if (target?.type === "attribute" && field(target, "attribute").text === "urls") {
						const r = routers.get(`${file}#${field(target, "object").text}`) ?? (() => {
							const found = lookup(field(target, "object").text, file)
							return found?.kind === "object" ? (collectRouters(found.file), routers.get(`${found.file}#${found.name}`)) : null
						})()
						if (r) routerRoutes(r, full, mw, anchored)
						else if (/^admin\.site\.urls$/.test(textOf(target))) {
							add({ method: "ALL", path: full, middleware: [...mw, "django admin (staff_member_required)"], handler: "admin.site", framework: "django", anchored }, null, file, lineOf(e))
						} else {
							// a module's urls behind it
							const found = lookup(textOf(target).replace(/\.urls$/, ""), file)
							if (found?.kind === "module") expand(found.file, full, mw, anchored, depth + 1)
						}
					} else if (target?.type === "identifier" || target?.type === "attribute") {
						const found = lookup(target.text, file)
						if (found?.kind === "module") expand(found.file, full, mw, anchored, depth + 1)
						else if (found?.kind === "object") entries(found.node, found.file, full, mw, anchored, depth + 1)
					} else if (tuple || target?.type === "list") entries(tuple ?? target, file, full, mw, anchored, depth + 1)
					continue
				}
				// path("admin/", admin.site.urls): Django's admin, staff only
				if (/^admin\.site\.urls$/.test(textOf(view))) {
					add({ method: "ALL", path: full, middleware: [...mw, "django admin (staff_member_required)"], handler: "admin.site", framework: "django", anchored }, null, file, lineOf(e))
					continue
				}
				viewRoutes(view, file, full, mw, anchored, lineOf(e))
			}
		}
		// router = DefaultRouter(); router.register(r"articles", ArticleViewSet)
		function collectRouters(file) {
			const fi = info.get(file)
			if (!fi || fi.routersDone) return
			fi.routersDone = true
			walk(fi.tree.rootNode, n => {
				if (n.type === "assignment" && field(n, "right")?.type === "call" && /Router$/.test(callName(field(n, "right"))))
					routers.set(`${file}#${field(n, "left").text}`, { file, registrations: [], trailing: pyString(kwarg(field(n, "right"), "trailing_slash")) })
				if (n.type === "call" && callName(n) === "register") {
					const r = routers.get(`${file}#${callObject(n)?.text}`)
					if (r) r.registrations.push({ prefix: pyString(posArgs(n)[0], consts) ?? "", view: posArgs(n)[1], line: lineOf(n), file })
				}
			})
		}
		function routerRoutes(r, prefix, mw, anchored) {
			for (const reg of r.registrations) {
				const cls = lookup(reg.view?.text ?? "", reg.file)
				if (cls?.methods) viewSetRoutes(cls, `${prefix}/${reg.prefix}`, mw, anchored, reg.file, reg.line)
			}
		}
		const GENERIC = {
			ListAPIView: ["list"], CreateAPIView: ["create"], ListCreateAPIView: ["list", "create"], RetrieveAPIView: ["retrieve"], DestroyAPIView: ["destroy"], UpdateAPIView: ["update"],
			RetrieveUpdateAPIView: ["retrieve", "update"], RetrieveDestroyAPIView: ["retrieve", "destroy"], RetrieveUpdateDestroyAPIView: ["retrieve", "update", "destroy"],
			ListModelMixin: ["list"], CreateModelMixin: ["create"], RetrieveModelMixin: ["retrieve"], UpdateModelMixin: ["update"], DestroyModelMixin: ["destroy"],
			ModelViewSet: ["list", "create", "retrieve", "update", "destroy"], ReadOnlyModelViewSet: ["list", "retrieve"],
			ListView: ["get"], DetailView: ["get"], TemplateView: ["get"], RedirectView: ["get"], CreateView: ["get", "post"], UpdateView: ["get", "post"], DeleteView: ["get", "post"], FormView: ["get", "post"]
		}
		const ACTION = { list: ["GET", false], create: ["POST", false], retrieve: ["GET", true], update: ["PUT", true], partial_update: ["PATCH", true], destroy: ["DELETE", true] }
		const actionsOf = cls => {
			const bases = allBases(cls)
			const set = new Set(bases.flatMap(b => GENERIC[b] ?? []))
			for (const a of Object.keys(ACTION)) if (classMethod(cls, a)) set.add(a)
			if (set.has("update")) set.add("partial_update")
			return set
		}
		// permission_classes, authentication mixins and method_decorator(login_required) on a class
		function classGuards(cls) {
			const perms = classAttr(cls, "permission_classes")
			const names = perms ? items(perms).map(p => textOf(p).split(".").at(-1)) : null
			const mixins = allBases(cls).filter(b => /LoginRequired|PermissionRequired|UserPassesTest|Staff|Superuser|Admin|AccessMixin|Authenticated/i.test(b))
			const decs = decoratorsOf(cls.decorated).map(d => nameOf(d))
			const isDrf = allBases(cls).some(b => /APIView|ViewSet|GenericAPIView|Mixin$/.test(b))
			const effective = names ?? (isDrf ? defaultPermissions : [])
			return { names: [...effective, ...mixins, ...decs], public: Boolean(names && names.length && names.every(n => PUBLIC_PERMISSION.test(n))) }
		}
		function viewSetRoutes(cls, base, mw, anchored, file, line) {
			const lookupKwarg = pyString(classAttr(cls, "lookup_url_kwarg")) ?? pyString(classAttr(cls, "lookup_field")) ?? "pk"
			const guards = classGuards(cls)
			for (const action of actionsOf(cls)) {
				const [method, detail] = ACTION[action]
				const handler = classMethod(cls, action)
				add({ method, path: detail ? `${base}/{${lookupKwarg}}` : base, middleware: [...mw, ...guards.names, ...(handler ? decoratorsOf(handler.decorated).map(nameOf) : [])], public: guards.public, handler: `${cls.name}.${action}`, framework: "django", anchored }, handler ?? { cls, generic: action }, handler?.file ?? cls.file, handler ? lineOf(handler.node) : lineOf(cls.node), { cls, action, lookup: lookupKwarg })
			}
			// @action(detail=True, methods=["post"], url_path="publish")
			for (const c of lineage(cls)) {
				for (const [name, m] of c.methods ?? []) {
					const dec = decoratorsOf(m.decorated).find(d => d.type === "call" && callName(d) === "action")
					if (!dec) continue
					const detail = kwarg(dec, "detail")?.type === "true"
					const urlPath = pyString(kwarg(dec, "url_path")) ?? name
					const methods = items(kwarg(dec, "methods")).map(x => pyString(x)?.toUpperCase()).filter(Boolean)
					const extra = items(kwarg(dec, "permission_classes")).map(p => textOf(p).split(".").at(-1))
					const isPublic = extra.length > 0 && extra.every(n => PUBLIC_PERMISSION.test(n))
					for (const method of methods.length ? methods : ["GET"])
						add({ method, path: detail ? `${base}/{${lookupKwarg}}/${urlPath}` : `${base}/${urlPath}`, middleware: [...mw, ...(extra.length ? extra : guards.names), ...decoratorsOf(m.decorated).filter(d => d !== dec).map(nameOf)], public: isPublic || (!extra.length && guards.public), handler: `${cls.name}.${name}`, framework: "django", anchored }, m, m.file, lineOf(m.node), { cls, action: name, lookup: lookupKwarg })
				}
			}
		}
		function viewRoutes(view, file, full, mw, anchored, line) {
			// Cls.as_view()
			if (view.type === "call" && callName(view) === "as_view") {
				const cls = lookup(callObject(view).text, file)
				if (!cls?.methods) {
					add({ method: "ALL", path: full, middleware: [...mw], handler: textOf(callObject(view)), framework: "django", anchored }, null, file, line)
					return
				}
				// as_view({"get": "list"}) on a ViewSet
				const map = posArgs(view)[0]
				const guards = classGuards(cls)
				if (map?.type === "dictionary") {
					for (const pair of map.namedChildren.filter(c => c.type === "pair")) {
						const method = pyString(field(pair, "key"))?.toUpperCase()
						const action = pyString(field(pair, "value"))
						const handler = action ? classMethod(cls, action) : null
						if (method) add({ method, path: full, middleware: [...mw, ...guards.names, ...(handler ? decoratorsOf(handler.decorated).map(nameOf) : [])], public: guards.public, handler: `${cls.name}.${action}`, framework: "django", anchored }, handler ?? { cls, generic: action }, handler?.file ?? cls.file, handler ? lineOf(handler.node) : line, { cls, action, lookup: null })
					}
					return
				}
				const generic = actionsOf(cls)
				const verbs = new Set()
				for (const v of VERBS) if (classMethod(cls, v)) verbs.add(v)
				for (const a of generic) if (ACTION[a]) verbs.add(ACTION[a][0].toLowerCase())
				for (const a of generic) if (!ACTION[a]) verbs.add(a)
				for (const v of verbs) {
					if (v === "options" || v === "head") continue
					const action = [...generic].find(a => ACTION[a]?.[0] === v.toUpperCase())
					// destroy() overridden on a DestroyAPIView answers DELETE
					const handler = classMethod(cls, v) ?? (action ? classMethod(cls, action) : null)
					add({ method: v.toUpperCase(), path: full, middleware: [...mw, ...guards.names, ...(handler ? decoratorsOf(handler.decorated).map(nameOf) : [])], public: guards.public, handler: `${cls.name}.${v}`, framework: "django", anchored }, handler ?? { cls, generic: action }, handler?.file ?? cls.file, handler ? lineOf(handler.node) : line, { cls, action, lookup: null })
				}
				return
			}
			// a function view, with its decorators
			const target = lookup(view.text, file)
			const decs = target?.decorated ? decoratorsOf(target.decorated) : []
			const apiView = decs.find(d => d.type === "call" && callName(d) === "api_view")
			const allowed = decs.find(d => d.type === "call" && callName(d) === "require_http_methods")
			const fixed = decs.map(d => textOf(d)).find(t => /^require_(POST|GET|safe)$/.test(t))
			const methods = apiView ? items(posArgs(apiView)[0]).map(m => pyString(m)?.toUpperCase()).filter(Boolean) : allowed ? items(posArgs(allowed)[0]).map(m => pyString(m)?.toUpperCase()).filter(Boolean) : fixed ? [fixed === "require_POST" ? "POST" : "GET"] : ["ALL"]
			const permDec = decs.find(d => d.type === "call" && callName(d) === "permission_classes")
			const perms = permDec ? items(posArgs(permDec)[0]).map(p => textOf(p).split(".").at(-1)) : apiView ? defaultPermissions : []
			const others = decs.filter(d => d !== apiView && d !== permDec).map(d => withHint(nameOf(d), target?.file ?? file))
			const isPublic = permDec && perms.length > 0 && perms.every(n => PUBLIC_PERMISSION.test(n))
			for (const method of methods.length ? methods : ["GET"])
				add({ method, path: full, middleware: [...mw, ...perms, ...others], public: isPublic, handler: view.text, framework: "django", anchored }, target?.node ? { node: target.node, file: target.file } : null, target?.file ?? file, target?.node ? lineOf(target.node) : line)
		}
		const rootFile = rootConf ? moduleFiles.get(rootConf) : null
		if (rootFile) expand(rootFile, "", [], true)
		// urls modules no root reaches: mapped on their own, their prefix unknown
		for (const fi of djangoFiles) if (/urls\.py$/.test(fi.file) && !reachable.has(fi.file)) expand(fi.file, "", [], false)
	}

	// ---------- connexion: routes from the OpenAPI spec, handlers by operationId ----------
	function mapConnexion() {
		if (!routes.frameworks.connexion) return
		for (const specFile of findSpecs(root)) {
			// connexion checks a declared scheme only when the spec names the function that does it
			const enforced = /x-\w*InfoFunc|x-\w*info-func/i.test(readFileSync(specFile, "utf8"))
			for (const op of readOperations(specFile)) {
				const dotted = op.operationId
				const modName = dotted.split(".").slice(0, -1).join(".")
				const fnName = dotted.split(".").at(-1)
				const file = moduleFiles.get(modName)
				const def = file ? info.get(file)?.defs.get(fnName) : null
				const decs = def?.decorated ? decoratorsOf(def.decorated).map(d => withHint(nameOf(d), file)) : []
				const security = op.security && enforced ? ["openapi securitySchemes (auth)"] : []
				add({ method: op.method, path: op.path, middleware: [...security, ...decs], handler: dotted, framework: "connexion", anchored: true, origin: specFile }, def ? { node: def.node, file } : null, file ?? specFile, def ? lineOf(def.node) : op.line)
			}
		}
	}
}

// if settings.ENVIRONMENT == "local": app.include_router(private.router)
function settingGuard(call) {
	for (let n = call.parent; n; n = n.parent) {
		if (n.type === "if_statement") {
			const c = field(n, "condition")?.text ?? ""
			if (/debug|env|development|local|settings\.|config\.|enable/i.test(c)) return c.slice(0, 60)
		}
		if (n.type === "function_definition") return null
	}
	return null
}

const SPEC = /^(openapi|swagger|api)[\w.-]*\.(json|ya?ml)$/i
function findSpecs(dir, out = []) {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (/^(node_modules|\.git|venv|\.venv|tests?)$/.test(entry.name)) continue
		const full = path.join(dir, entry.name)
		if (entry.isDirectory()) findSpecs(full, out)
		else if (SPEC.test(entry.name)) out.push(full)
	}
	return out
}

// path, method and operationId from an OpenAPI file, JSON or YAML (read by indentation, no parser)
function readOperations(file) {
	const text = readFileSync(file, "utf8")
	const ops = []
	if (file.endsWith(".json")) {
		try {
			const spec = JSON.parse(text)
			const globalSecurity = Boolean(spec.security?.length)
			for (const [p, methods] of Object.entries(spec.paths ?? {}))
				for (const [m, op] of Object.entries(methods))
					if (op?.operationId && ["get", "post", "put", "patch", "delete"].includes(m)) ops.push({ path: p, method: m.toUpperCase(), operationId: op.operationId, security: op.security ? op.security.length > 0 : globalSecurity, line: 1 })
		} catch {}
		return ops
	}
	const lines = text.split("\n")
	let inPaths = false
	let pathIndent = -1
	let current = null
	let method = null
	let methodIndent = -1
	let globalSecurity = false
	lines.forEach((line, i) => {
		if (/^security:\s*$/.test(line) && /^\s+-/.test(lines[i + 1] ?? "")) globalSecurity = true
		if (/^paths:\s*$/.test(line)) {
			inPaths = true
			return
		}
		if (inPaths && /^\S/.test(line)) inPaths = false
		if (!inPaths) return
		const indent = line.match(/^ */)[0].length
		const pathMatch = line.match(/^(\s+)['"]?(\/[^'":]*)['"]?:\s*$/)
		if (pathMatch && (pathIndent === -1 || indent === pathIndent)) {
			pathIndent = indent
			current = pathMatch[2]
			method = null
			return
		}
		const m = line.match(/^(\s+)(get|post|put|patch|delete):\s*$/)
		if (m && current && indent > pathIndent) {
			method = { name: m[2].toUpperCase(), security: null }
			methodIndent = indent
			return
		}
		if (method && indent > methodIndent) {
			const op = line.match(/^\s+operationId:\s*['"]?([\w.]+)['"]?/)
			if (op) ops.push({ path: current, method: method.name, operationId: op[1], line: i + 1, opRef: method })
			if (/^\s+security:\s*\[\s*\]/.test(line)) method.security = false
			else if (/^\s+security:\s*$/.test(line)) method.security = true
		}
	})
	for (const op of ops) op.security = op.opRef.security ?? globalSecurity
	return ops
}
