// Maps the routes of a Go API: Gin, Echo, Fiber, chi, gorilla/mux, httprouter and net/http.
// Routers are followed through groups, sub-routers, mounts and the functions they are passed to,
// so each route gets its full path and every middleware in front of it.
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import { classify, ignoredRules } from "../mapper.js"
import { initGo, listGoFiles, parseGo, walk, field, lineOf, stringValue, calleeName, calleeObject, args, paramsOf, resultsOf, baseType, qualType } from "./ast.js"

const FRAMEWORKS = [
	["gin", /github\.com\/gin-gonic\/gin$/],
	["echo", /github\.com\/labstack\/echo(\/v\d+)?$/],
	["fiber", /github\.com\/gofiber\/fiber(\/v\d+)?$/],
	["chi", /github\.com\/go-chi\/chi(\/v\d+)?$/],
	["mux", /github\.com\/gorilla\/mux$/],
	["httprouter", /github\.com\/julienschmidt\/httprouter$/],
	["flamego", /github\.com\/flamego\/flamego$/],
	["macaron", /(gopkg\.in\/macaron\.v1|github\.com\/go-macaron\/macaron)$/],
	["net/http", /^net\/http$/]
]
const CONSTRUCTOR = /^(gin\.(Default|New)|echo\.New\w*|fiber\.New|chi\.New\w*|mux\.NewRouter|http\.NewServeMux|httprouter\.New|web\.New\w*|flamego\.(New|Classic)|macaron\.(New|Classic))$/
// parameter types that carry a router into a function
const ROUTER_TYPE = /^\*?(gin\.(Engine|RouterGroup|IRouter|IRoutes)|echo\.(Echo|Group)|fiber\.(App|Router|Group)|chi\.(Router|Mux)|mux\.Router|http\.ServeMux|httprouter\.Router|flamego\.(Flame|Router)|macaron\.(Macaron|Router)|router\.(Router|RouterGroup)(\[.*\])?)$/
const RETURNS_ROUTER = /gin\.Engine|RouterGroup|echo\.Echo|echo\.Group|fiber\.App|fiber\.Router|chi\.Mux|chi\.Router|mux\.Router|http\.ServeMux|httprouter\.Router|flamego\.Flame|macaron\.Macaron|http\.Handler\b/
const VERB = { GET: "GET", POST: "POST", PUT: "PUT", PATCH: "PATCH", DELETE: "DELETE", HEAD: "HEAD", OPTIONS: "OPTIONS" }
const ANY = /^(Any|All)$/
// methods that take the HTTP method as their first argument
const WITH_METHOD = /^(Handle|Method|Methods|MethodFunc|Add|Handler|HandlerFunc)$/
const PATH_ONLY = /^(HandleFunc|Handle)$/
// a handler's first parameters say it is one: (c *gin.Context), (w http.ResponseWriter, r *http.Request)
export const HANDLER_PARAM = /Context|Ctx|ResponseWriter|http\.Request|httprouter\.Params/
// conversions and adapters that only wrap a handler
const ADAPTER = /^(http\.HandlerFunc|http\.Handler|gin\.WrapH|gin\.WrapF|echo\.WrapHandler|adaptor\.HTTPHandlerFunc|adaptor\.HTTPHandler)$/

// middleware that runs on a route but enforces nothing about who is calling
const NOT_ENFORCED = /optional|maybe|soft|limit|throttle|logger|logging|recover|cors|gzip|compress|request_?id|timeout|metrics|prometheus|static|nocache|real_?ip|tracing|otel|sentry|LoadAndSave|Sessions$|csrf|secure$|bodylimit|decompress|i18n|locale/i
const OPTIONAL = /optional|maybe|soft|skips GET/i
const AUTH_NAME = /auth|jwt|token|login|logged|signed|sign_?in|protect|guard|bearer|api_?key|oauth|oidc|keycloak|require_?user|current_?user|basic_?auth|key_?auth|session/i
// reqRepoWriter, mustBeOrgMember, ensureTeamAccess: a check on the caller's rights to something
const ROLE_NAME = /admin|role|permission|rbac|acl|casbin|privilege|scope|owner|staff|superuser|can[A-Z]|is_?(admin|staff|owner)|require_?(admin|role|permission|owner|staff)|^(req|require|must|ensure|check)_?\w*(writer|reader|member|membership|access|collaborator|maintainer|manager|team|ownership)|^(req|require|must|ensure|check)_?(read|write|pull|push|edit|view|manage)\b|^Must(Pull|Push|Read|Write|Edit|View|Manage)|local_?only|internal_?only|APILocal|localhost_?only|auth_?internal|internal_?(auth|token)|service_?token/i
// what a middleware's own code shows when its name says nothing
const AUTH_BODY = /Authorization|Bearer|BasicAuth\(|DecodeBasic\(|ConstantTimeCompare\(|ParseWithClaims|jwt\.Parse|StatusUnauthorized|ErrUnauthorized|\b401\b|Cookie\(/
const ROLE_BODY = /StatusForbidden|ErrForbidden|\b403\b|IsAdmin|\.Role\b|Permission/

export function classifyGo(names) {
	// app.MetricsFilter whose body checks basic auth still guards the route
	const enforced = names.filter(n => !NOT_ENFORCED.test(n) || (/ \(checks(Auth|Role)\)$/.test(n) && !OPTIONAL.test(n)))
	// session.MustOrgMember: the package says little, the function name decides
	const lasts = enforced.map(n => n.replace(/\(.*$/, "").split(".").at(-1))
	const { auth, role } = classify(enforced)
	const roleGo = role || [...enforced, ...lasts].some(n => ROLE_NAME.test(n))
	return { auth: auth || roleGo || [...enforced, ...lasts].some(n => AUTH_NAME.test(n)), role: roleGo }
}

const exprName = node => {
	if (!node) return "?"
	if (node.type === "call_expression") return exprName(field(node, "function"))
	if (node.type === "func_literal") return "inline"
	const text = node.text.replace(/\s+/g, "")
	return text.length > 48 ? `${text.slice(0, 45)}…` : text
}

// module paths from go.mod, so an import can be found on disk
function modulesOf(files, root) {
	const dirs = new Set(files.map(f => path.dirname(f)))
	const mods = []
	for (const dir of [root, ...dirs]) {
		const mod = path.join(dir, "go.mod")
		if (!existsSync(mod)) continue
		const name = readFileSync(mod, "utf8").match(/^module\s+(\S+)/m)?.[1]
		if (name && !mods.some(m => m.dir === dir)) mods.push({ name, dir })
	}
	return mods.sort((a, b) => b.name.length - a.name.length)
}

export async function mapGoRoutes(root) {
	await initGo()
	const files = listGoFiles(root)
	const routes = []
	Object.defineProperty(routes, "frameworks", { value: {} })
	if (files.length === 0) return routes
	const modules = modulesOf(files, root)
	const importDir = imp => {
		const mod = modules.find(m => imp === m.name || imp.startsWith(m.name + "/"))
		return mod ? path.join(mod.dir, imp.slice(mod.name.length)) : null
	}
	const moduleOf = file => modules.find(m => file.startsWith(m.dir + path.sep))?.dir ?? root

	// one index for the whole tree: functions, methods, structs and string constants per package directory
	const pkgs = new Map()
	const methods = new Map()
	const types = new Map()
	// constants resolve on demand, so APIURLSuffix = APIURLSuffixV4 works whatever the file order
	const constNodes = new Map()
	const resolving = new Set()
	const consts = {
		get(name) {
			const node = constNodes.get(name)
			if (!node || resolving.has(name)) return undefined
			resolving.add(name)
			const value = stringValue(node, consts)
			resolving.delete(name)
			return value ?? undefined
		}
	}
	const fileInfo = new Map()
	for (const file of files) {
		const parsed = parseGo(file)
		if (!parsed) continue
		const dir = path.dirname(file)
		if (!pkgs.has(dir)) pkgs.set(dir, { dir, funcs: new Map(), literals: [] })
		const pkg = pkgs.get(dir)
		const imports = new Map()
		const rootNode = parsed.tree.rootNode
		walk(rootNode, n => {
			if (n.type === "import_spec") {
				const imp = field(n, "path").text.slice(1, -1)
				const alias = field(n, "name")?.text ?? imp.split("/").filter(s => !/^v\d+$/.test(s)).at(-1).replace(/^go-/, "").replace(/[.-]go$/, "")
				imports.set(alias, imp)
				return false
			}
			if (n.type === "function_declaration") {
				pkg.funcs.set(field(n, "name").text, { node: n, file, dir })
				return false
			}
			if (n.type === "method_declaration") {
				const recv = baseType(paramsOf({ childForFieldName: k => (k === "parameters" ? field(n, "receiver") : null) })[0]?.type ?? "")
				const name = field(n, "name").text
				if (!methods.has(name)) methods.set(name, [])
				methods.get(name).push({ node: n, file, dir, recv })
				return false
			}
			if (n.type === "type_spec" && field(n, "type")?.type === "struct_type") {
				const name = field(n, "name").text
				if (!types.has(name)) types.set(name, [])
				types.get(name).push({ dir, file, fields: structFields(field(n, "type")) })
				return false
			}
			// var webCmd = &cobra.Command{Run: func(...) { e := routes.NewEcho() ... }}
			if (n.type === "func_literal") {
				pkg.literals.push({ node: n, file, dir })
				return false
			}
			if (n.type === "const_spec" || (n.type === "var_spec" && n.parent?.parent?.type === "source_file")) {
				const names = n.namedChildren.filter(c => c.type === "identifier")
				const values = field(n, "value")?.namedChildren ?? []
				names.forEach((id, i) => {
					if (values[i] && !constNodes.has(id.text)) constNodes.set(id.text, values[i])
				})
			}
		})
		const frameworks = [...imports.values()].map(imp => FRAMEWORKS.find(([, re]) => re.test(imp))?.[0]).filter(Boolean)
		for (const f of new Set(frameworks)) routes.frameworks[f] = (routes.frameworks[f] ?? 0) + 1
		fileInfo.set(file, { imports, dir, frameworks, tree: parsed.tree })
	}

	const ctx = { root, pkgs, methods, types, consts, fileInfo, importDir }
	const fieldRouters = new Map()
	const pkgRouters = new Map()
	const sites = new Map()
	const analysed = new Set()
	// functions some other function hands a router to, or mounts: their own standalone guesses are dropped
	const reached = new Set()
	let entryKey = null

	// a function, reached with some routers bound to its parameters
	function analyse(fnNode, file, env, depth) {
		const body = field(fnNode, "body")
		if (!body || depth > 6) return
		const info = fileInfo.get(file)
		const local = { routers: new Map(env.routers), types: new Map(env.types), funcs: new Map() }
		for (const p of paramsOf(fnNode)) if (p.name) local.types.set(p.name, baseType(p.type))
		const receiver = field(fnNode, "receiver")
		if (receiver) for (const p of paramsOf({ childForFieldName: k => (k === "parameters" ? receiver : null) })) if (p.name) local.types.set(p.name, baseType(p.type))

		walk(body, n => {
			if (n.type === "short_var_declaration" || n.type === "assignment_statement" || n.type === "var_spec") {
				const left = n.type === "var_spec" ? n.namedChildren.filter(c => c.type === "identifier") : field(n, "left").namedChildren
				const right = (n.type === "var_spec" ? field(n, "value") : field(n, "right"))?.namedChildren ?? []
				if (n.type === "var_spec" && field(n, "type")) left.forEach(l => local.types.set(l.text, baseType(field(n, "type").text)))
				right.forEach((r, i) => {
					if (!left[i]) return
					// a router seeded for a mount point keeps its place when the function builds it
					const seeded = r.type === "call_expression" && CONSTRUCTOR.test(field(r, "function").text) && env.routers.has(left[i].text)
					const router = seeded ? null : routerOf(r, local, info, file, depth)
					if (router) {
						local.routers.set(left[i].text, router)
						// api.BaseRoutes.Users = ...: other functions reach it by the field name
						if (left[i].type === "selector_expression") fieldRouters.set(fieldKey(left[i].text), router)
						else if (n.type === "assignment_statement") pkgRouters.set(left[i].text, router)
					}
					const type = typeOf(r, local, info)
					if (type) local.types.set(left[i].text, type)
					if (r.type === "func_literal") local.funcs.set(left[i].text, r)
				})
				// a := r.Group(...) is evaluated above; its arguments hold no routes
				return right.some(r => r.type === "func_literal") ? false : undefined
			}
			if (n.type === "call_expression") return statement(n, local, info, file, depth)
		})
	}

	// what a call does to the routing: Use, a route, a nested Route/Group, a mount, or a router handed on
	function statement(call, local, info, file, depth) {
		const name = calleeName(call)
		const object = calleeObject(call)
		const router = object ? routerOf(object, local, info, file, depth) : null
		const a = args(call)
		// Use, Echo's Pre, Gitea's AfterRouting: middleware for every route on the router
		if (router && /^(Use|Pre|AfterRouting|BeforeRouting|UseMiddleware|Bind|BindFunc)$/.test(name)) {
			router.mw.push(...a.map(m => middlewareName(m, local, info)))
			return false
		}
		// r.Route("/x", func(r chi.Router) {...}), r.Group(func(r chi.Router) {...}),
		// and Gitea's m.Group("/x", func() {...}, reqToken()), where the closure keeps using m
		const fn = a.find(x => x.type === "func_literal")
		if (router && (name === "Route" || name === "Group") && fn) {
			const prefix = a[0] !== fn ? stringValue(a[0], ctx.consts) ?? `<${exprName(a[0])}>` : ""
			const child = makeRouter(router, prefix)
			child.mw.push(...a.filter(x => x !== fn && x !== a[0]).map(m => middlewareName(m, local, info)))
			const param = paramsOf(fn)[0]?.name
			const inner = { routers: new Map(local.routers), types: local.types }
			inner.routers.set(param ?? object.text, child)
			analyse(fn, file, inner, depth + 1)
			return false
		}
		if (router && name === "Mount" && a.length >= 2) {
			const prefix = stringValue(a[0], ctx.consts) ?? `<${exprName(a[0])}>`
			const sub = routerOf(a[1], local, info, file, depth, { parent: router, segment: prefix })
			if (sub && !sub.parent && sub !== router) Object.assign(sub, { parent: router, segment: prefix })
			return false
		}
		if (registerRoute(call, router, name, a, local, info, file, depth)) return false
		// return auth(cors(mux)): every route on mux goes through auth
		if (call.parent?.type !== "expression_statement" && !router) {
			const wrapped = wrappedRouter(call, local, info, file, depth)
			if (wrapped && !resolveCall(call, local, info).some(t => paramsOf(t.node).some(p => ROUTER_TYPE.test(p.type)))) {
				wrapped.mw.push(middlewareName(field(call, "function"), local, info))
				return
			}
		}
		// a router passed to another function: routes.Register(api), h.Routes(v1.Group("/users"))
		const bound = a.map(arg => routerOf(arg, local, info, file, depth)).map((r, i) => (r ? [i, r] : null)).filter(Boolean)
		if (bound.length) {
			for (const target of resolveCall(call, local, info)) {
				const params = paramsOf(target.node)
				const env = { routers: new Map(), types: new Map() }
				for (const [i, r] of bound) if (params[i]?.name) env.routers.set(params[i].name, r)
				const key = `${target.file}:${lineOf(target.node)}:${bound.map(([, r]) => r.id).join(",")}`
				if (analysed.has(key)) continue
				analysed.add(key)
				reached.add(`${target.file}:${lineOf(target.node)}`)
				analyse(target.node, target.file, env, depth + 1)
			}
		}
	}

	// the router inside a chain of wrappers: auth(cors(mux)) → mux
	function wrappedRouter(call, local, info, file, depth) {
		for (const arg of args(call)) {
			if (arg.type === "identifier" || arg.type === "selector_expression") {
				const r = local.routers.get(arg.text)
				if (r) return r
			}
			if (arg.type === "call_expression" && !CONSTRUCTOR.test(field(arg, "function").text)) {
				const inner = wrappedRouter(arg, local, info, file, depth)
				if (inner) return inner
			}
		}
		return null
	}

	// the setting every call of a function sits behind, if there is one
	const callerGuards = new Map()
	function guardOfCallers(name) {
		if (!name) return null
		if (callerGuards.has(name)) return callerGuards.get(name)
		callerGuards.set(name, null)
		const guards = []
		for (const { tree } of fileInfo.values()) {
			if (!tree.rootNode.text.includes(name + "(")) continue
			walk(tree.rootNode, n => {
				if (n.type === "call_expression" && calleeName(n) === name) guards.push(settingGuard(n))
			})
		}
		const result = guards.length && guards.every(Boolean) ? guards[0] : null
		callerGuards.set(name, result)
		return result
	}

	let nextId = 0
	// where the router being made was built: separate apps in one module keep separate inventories
	let currentSite = null
	const returnedCache = new Map()
	// Gin and Fiber copy the middleware at the moment a group or route is made; Echo, chi and mux
	// apply the router's middleware to every route, whenever it was added
	function makeRouter(parent, segment, anchored = true, frozen = parent?.frozen ?? false) {
		return { id: nextId++, parent, segment, mw: [], anchored, frozen, inherited: parent && frozen ? fullMw(parent) : null, origin: currentSite }
	}
	const fullMw = r => (r.inherited ? [...r.inherited, ...r.mw] : [...(r.parent ? fullMw(r.parent) : []), ...r.mw])

	// the router an expression stands for, if any
	function routerOf(expr, local, info, file, depth, mount) {
		if (!expr) return null
		if (expr.type === "identifier" || expr.type === "selector_expression") {
			const known = local.routers.get(expr.text)
			if (known) return known
			// a package-level router: APIv1 = router.Group(...) in one function, api.GetCamera(APIv1) in another
			if (expr.type === "identifier" && !local.types.has(expr.text) && pkgRouters.has(expr.text)) return pkgRouters.get(expr.text)
			if (expr.type === "selector_expression" && fieldRouters.has(fieldKey(expr.text))) return fieldRouters.get(fieldKey(expr.text))
			return null
		}
		if (expr.type === "unary_expression") return routerOf(expr.namedChildren[0], local, info, file, depth, mount)
		if (expr.type !== "call_expression") return null
		const fnText = field(expr, "function").text
		currentSite = `${file}:${lineOf(expr)}`
		if (CONSTRUCTOR.test(fnText)) return makeRouter(mount?.parent ?? null, mount?.segment ?? "", true, /^(gin|fiber)\./.test(fnText))
		const name = calleeName(expr)
		const object = calleeObject(expr)
		const parent = object ? routerOf(object, local, info, file, depth) : null
		const a = args(expr)
		if (parent) {
			if (name === "Group" && a[0] && a[0].type !== "func_literal") {
				const child = makeRouter(parent, stringValue(a[0], ctx.consts) ?? `<${exprName(a[0])}>`)
				child.mw.push(...a.slice(1).map(m => middlewareName(m, local, info)))
				return child
			}
			// rg.Group("/settings").Bind(RequireSuperuserAuth()): the chain returns the group itself
			if (/^(Bind|BindFunc)$/.test(name)) {
				parent.mw.push(...a.map(m => middlewareName(m, local, info)))
				return parent
			}
			if (name === "With") {
				const child = makeRouter(parent, "")
				child.mw.push(...a.map(m => middlewareName(m, local, info)))
				return child
			}
			if (name === "PathPrefix") return makeRouter(parent, stringValue(a[0], ctx.consts) ?? `<${exprName(a[0])}>`)
			// m.Combo("/x", mw).Get(h).Post(h): the methods that follow take no path
			if (name === "Combo") {
				const combo = makeRouter(parent, stringValue(a[0], ctx.consts) ?? `<${exprName(a[0])}>`)
				combo.combo = true
				combo.mw.push(...a.slice(1).map(m => middlewareName(m, local, info)))
				return combo
			}
			if (parent.combo && VERB[name.toUpperCase()]) return parent
			if (/^(Subrouter|StrictSlash|UseEncodedPath|SkipClean|Host|Schemes|Name|Headers)$/.test(name)) return parent
			return null
		}
		// a function that builds and returns a router: r := router.New(), r.Mount("/api", apiRouter())
		for (const target of resolveCall(expr, local, info)) {
			if (!mount && !RETURNS_ROUTER.test(field(target.node, "result")?.text ?? "")) continue
			const key = `${target.file}:${lineOf(target.node)}:${mount?.parent?.id ?? "-"}:${mount?.segment ?? ""}`
			if (!returnedCache.has(key)) returnedCache.set(key, returnedRouter(target, mount ?? { parent: null, segment: "" }, depth))
			if (returnedCache.get(key)) return returnedCache.get(key)
		}
		return null
	}

	function returnedRouter(target, mount, depth) {
		const body = field(target.node, "body")
		if (!body || depth > 6) return null
		let result = null
		const local = { routers: new Map(), types: new Map(), funcs: new Map() }
		const info = fileInfo.get(target.file)
		// routers built here hang under the mount point
		walk(body, n => {
			if (n.type === "short_var_declaration" || n.type === "assignment_statement") {
				const left = field(n, "left").namedChildren
				field(n, "right").namedChildren.forEach((r, i) => {
					if (left[i] && r.type === "call_expression" && CONSTRUCTOR.test(field(r, "function").text))
						local.routers.set(left[i].text, makeRouter(mount.parent, mount.segment, true, /^(gin|fiber)\./.test(field(r, "function").text)))
				})
			}
		})
		const env = { routers: local.routers, types: new Map() }
		analyse(target.node, target.file, env, depth + 1)
		walk(body, n => {
			if (n.type === "return_statement" && !result) {
				const value = n.namedChildren[0]?.namedChildren?.[0] ?? n.namedChildren[0]
				if (value) result = local.routers.get(value.text) ?? null
			}
			if (n.type === "func_literal") return false
		})
		reached.add(`${target.file}:${lineOf(target.node)}`)
		return result ?? [...local.routers.values()][0] ?? null
	}

	// r.GET("/x", mw, h) and friends; returns true when the call registered a route
	function registerRoute(call, router, name, a, local, info, file, depth) {
		let method = null
		let pathArg = null
		let handlers = []
		const upper = name.toUpperCase()
		if (router?.combo && VERB[upper]) {
			method = VERB[upper]
			pathArg = { type: "interpreted_string_literal", text: '""' }
			handlers = a
		} else if (VERB[name] || (VERB[upper] && name === name[0] + name.slice(1).toLowerCase())) {
			method = VERB[upper]
			pathArg = a[0]
			handlers = a.slice(1)
		} else if (ANY.test(name)) {
			method = "ALL"
			pathArg = a[0]
			handlers = a.slice(1)
		} else if (WITH_METHOD.test(name) && a.length >= 3 && methodOf(a[0])) {
			method = methodOf(a[0])
			pathArg = a[1]
			handlers = a.slice(2)
		} else if (PATH_ONLY.test(name) && a.length === 2) {
			// mux.Handle("/v1/", api.NewHandler(store)): a sub-router, not a route
			let inner = a[1]
			let strip = false
			if (inner.type === "call_expression" && field(inner, "function").text === "http.StripPrefix") {
				inner = args(inner)[1]
				strip = true
			}
			if (router && inner?.type === "call_expression") {
				const builds = resolveCall(inner, local, info).some(t => RETURNS_ROUTER.test(field(t.node, "result")?.text ?? "") && /\b(http\.NewServeMux|chi\.New\w*|mux\.NewRouter|gin\.(New|Default)|echo\.New\w*)\(/.test(t.node.text))
				if (builds) {
					const segment = strip ? stringValue(a[0], ctx.consts) ?? "" : ""
					const sub = routerOf(inner, local, info, file, depth, { parent: router, segment })
					if (sub && !sub.parent && sub !== router) Object.assign(sub, { parent: router, segment })
					return true
				}
			}
			pathArg = a[0]
			handlers = [a[1]]
			method = methodsChain(call) ?? "ALL"
		} else return false
		if (!pathArg || handlers.length === 0) return false
		let raw = stringValue(pathArg, ctx.consts)
		// an unknown receiver must look like a router call: a literal path and a handler
		if (!router) {
			const isHttp = object => /^http$/.test(object?.text ?? "")
			if (raw === null || !/^(\/|[A-Z]+ \/)/.test(raw)) return false
			if (!isHttp(calleeObject(call)) && !info.frameworks.length) return false
			router = fieldRouterFor(calleeObject(call), info)
		}
		if (raw === null) raw = `<${exprName(pathArg)}>`
		// net/http 1.22 patterns: "GET /items/{id}"
		const pattern = raw.match(/^([A-Z]+)\s+(\/.*)$/)
		if (pattern) {
			method = pattern[1]
			raw = pattern[2]
		}
		// Echo takes the handler first and middleware after; the others take the handler last
		const echoStyle = info.frameworks.includes("echo") && !info.frameworks.includes("gin") && !info.frameworks.includes("fiber")
		const handlerExpr = echoStyle ? handlers[0] : handlers.at(-1)
		const routeMw = [...(echoStyle ? handlers.slice(1) : handlers.slice(0, -1)), ...bindChain(call)].map(m => middlewareName(m, local, info))
		const { fn, wrappers, name: handlerName } = unwrapHandler(handlerExpr, local, info)
		const key = `${file}:${lineOf(call)}:${method}`
		if (!sites.has(key)) sites.set(key, [])
		sites.get(key).push({ entry: entryKey, conditional: settingGuard(call, guardOfCallers), router, raw, method, mwAt: router.frozen ? fullMw(router) : null, mw: [...routeMw, ...wrappers], fn, handlerName, file, line: lineOf(call), framework: info.frameworks[0] ?? "net/http" })
		return true
	}

	// PocketBase: sub.GET("", h).Bind(RequireSuperuserAuth())
	function bindChain(call) {
		const out = []
		let node = call
		while (node.parent?.type === "selector_expression" && node.parent.parent?.type === "call_expression") {
			const outer = node.parent.parent
			if (/^(Bind|BindFunc)$/.test(calleeName(outer))) out.push(...args(outer))
			node = outer
		}
		return out
	}

	// gorilla/mux: r.HandleFunc("/x", h).Methods("GET", "POST")
	function methodsChain(call) {
		let node = call
		while (node.parent?.type === "selector_expression" && node.parent.parent?.type === "call_expression") {
			const outer = node.parent.parent
			if (calleeName(outer) === "Methods") {
				const methods = args(outer).map(methodOf).filter(Boolean)
				// .Methods("GET", "OPTIONS"): the OPTIONS is the CORS preflight, not a second endpoint
				return (methods.length > 1 ? methods.filter(m => m !== "OPTIONS") : methods).join("|") || null
			}
			node = outer
		}
		return null
	}

	// s.router.GET(...) where s.router was set up in another function: one router per field name
	function fieldRouterFor(object, info) {
		// http.HandleFunc registers on the default mux; "\0http" keeps it apart from a variable named http
		const key = !object || object.text === "http" ? "\0http" : object.type === "selector_expression" ? fieldKey(object.text) : `\0${object.text}`
		if (!fieldRouters.has(key)) fieldRouters.set(key, makeRouter(null, "", object?.text === "http"))
		return fieldRouters.get(key)
	}

	// the name a middleware goes by, plus what its body shows when the name is silent
	function middlewareName(expr, local, info) {
		let name = exprName(expr)
		if (expr?.type === "func_literal") return bodyHint(expr.text) ?? "inline"
		// AuthMiddleware(false): the flag usually means "do not require a login"
		if (expr?.type === "call_expression" && args(expr).length === 1 && args(expr)[0].type === "false") name += "(optional)"
		// JWTWithConfig({Skipper: ... GET ...}): reads are let through
		if (expr?.type === "call_expression" && /Skipper/.test(expr.text) && /MethodGet|"GET"/.test(expr.text)) name += "(skips GET)"
		const { auth } = classifyGo([name])
		if (auth || OPTIONAL.test(name)) return name
		const target = expr ? resolveCall(expr.type === "call_expression" ? expr : { fake: expr }, local, info)[0] : null
		const hint = target ? bodyHint(target.node.text) : null
		return hint ? `${name} (${hint})` : name
	}
	const bodyHint = text => (ROLE_BODY.test(text) && AUTH_BODY.test(text) ? "checksRole" : AUTH_BODY.test(text) ? "checksAuth" : null)

	// h.GetOrder, handlers.GetOrder(db), mw(h), http.HandlerFunc(h): the function that handles the request
	function unwrapHandler(expr, local, info, wrappers = []) {
		if (!expr) return { fn: null, wrappers, name: "?" }
		if (expr.type === "func_literal") return { fn: { node: expr, file: info.file }, wrappers, name: "inline" }
		if (expr.type === "call_expression") {
			const fnText = field(expr, "function").text
			const a = args(expr)
			if (ADAPTER.test(fnText) && a[0]) return unwrapHandler(a[0], local, info, wrappers)
			// alice.New(a, b).ThenFunc(h)
			if (/^Then(Func)?$/.test(calleeName(expr)) && a[0]) {
				const chain = calleeObject(expr)
				const mws = chain?.type === "call_expression" ? args(chain).map(m => middlewareName(m, local, info)) : []
				return unwrapHandler(a[0], local, info, [...wrappers, ...mws])
			}
			const handlerArg = [...a].reverse().find(x => ["identifier", "selector_expression", "func_literal", "call_expression"].includes(x.type) && looksLikeHandler(x, local, info))
			if (handlerArg) {
				// pm(a.GetLogs, auth.PermSettingsGet): the other arguments name the permission
				const others = a.filter(x => x !== handlerArg).map(x => x.text).join(",")
				const name = middlewareName(field(expr, "function"), local, info) + (INLINE_ROLE.test(others) || /Perm|perm/.test(others) ? "(permission)" : "")
				return unwrapHandler(handlerArg, local, info, [...wrappers, name])
			}
			// a factory: h.GetOrder() returns the handler
			const target = resolveCall(expr, local, info)[0]
			if (target) return { fn: returnedFunc(target), wrappers, name: exprName(expr) }
			return { fn: null, wrappers, name: exprName(expr) }
		}
		const fakeCall = { fake: expr }
		const local_fn = expr.type === "identifier" ? local.funcs.get(expr.text) : null
		if (local_fn) return { fn: { node: local_fn, file: info.file }, wrappers, name: expr.text }
		const target = resolveCall(fakeCall, local, info, true)[0]
		return { fn: target ?? null, wrappers, name: expr.text }
	}

	function looksLikeHandler(expr, local, info) {
		if (expr.type === "func_literal") return paramsOf(expr).some(p => HANDLER_PARAM.test(p.type))
		if (expr.type === "call_expression") return ADAPTER.test(field(expr, "function").text) || args(expr).some(x => looksLikeHandler(x, local, info))
		const target = resolveCall({ fake: expr }, local, info, true)[0]
		return Boolean(target)
	}

	function returnedFunc(target) {
		let found = null
		walk(field(target.node, "body"), n => {
			if (found) return false
			if (n.type === "return_statement" && n.namedChildren[0]) {
				const value = n.namedChildren[0].type === "expression_list" ? n.namedChildren[0].namedChildren[0] : n.namedChildren[0]
				if (value?.type === "func_literal") found = { node: value, file: target.file }
			}
		})
		return found ?? target
	}

	// the functions a call can land in: pkg.Func, Func in this package, x.Method by x's type or by name
	function resolveCall(call, local, info, handlersOnly = false) {
		const fnExpr = call.fake ?? field(call, "function")
		if (!fnExpr) return []
		return resolveName(fnExpr, local, info, handlersOnly, call.fake ? null : args(call).length)
	}
	function resolveName(fnExpr, local, info, handlersOnly, arity, typedOnly = false) {
		const isHandler = t => paramsOf(t.node).some(p => HANDLER_PARAM.test(p.type))
		const filter = list => (handlersOnly ? list.filter(isHandler) : list)
		if (fnExpr.type === "identifier") {
			const own = pkgs.get(info.dir)?.funcs.get(fnExpr.text)
			return own ? filter([own]) : []
		}
		if (fnExpr.type !== "selector_expression") return []
		const operand = field(fnExpr, "operand")
		const name = field(fnExpr, "field").text
		const imp = operand.type === "identifier" ? info.imports.get(operand.text) : null
		if (imp) {
			const dir = importDir(imp)
			const target = dir ? pkgs.get(dir)?.funcs.get(name) : null
			return target ? filter([target]) : []
		}
		const candidates = filter(methods.get(name) ?? [])
		if (candidates.length <= 1 && !typedOnly) return candidates
		// db.Passkeys().DeleteByID(...): the receiver's type is what Passkeys() returns
		const type = (operand.type === "call_expression" ? typeOf(operand, local, info) : null) ?? local.types.get(operand.text) ?? local.types.get(operand.text.split(".").at(-1))
		// api.playlists.Delete: the type of the struct field
		const fieldType = !type && operand.type === "selector_expression" ? fieldTypeOf(operand, local, info) : null
		const want = type ?? fieldType
		const typed = want ? candidates.filter(c => c.recv === baseType(want)) : []
		if (typed.length) return typed
		// an interface Playlists is usually implemented by a struct playlists in its package
		const impl = want ? candidates.filter(c => c.recv.toLowerCase() === baseType(want).toLowerCase()) : []
		if (impl.length) return impl
		if (typedOnly) return []
		const sameDir = candidates.filter(c => c.dir === info.dir)
		if (sameDir.length === 1) return sameDir
		const sized = arity === null ? candidates : candidates.filter(c => paramsOf(c.node).length === arity)
		return sized.slice(0, 4)
	}

	function fieldTypeOf(selector, local, info) {
		const owner = field(selector, "operand")
		const ownerType = owner?.type === "identifier" ? local.types.get(owner.text) : null
		if (!ownerType) return null
		const name = field(selector, "field").text
		const struct = (types.get(baseType(ownerType)) ?? []).find(t => t.dir === info.dir) ?? (types.get(baseType(ownerType)) ?? [])[0]
		return struct?.fields.find(f => f.name === name)?.type ?? null
	}

	function typeOf(expr, local, info) {
		if (!expr) return null
		if (expr.type === "composite_literal") return qualType(field(expr, "type")?.text ?? "")
		if (expr.type === "unary_expression") return typeOf(expr.namedChildren[0], local, info)
		if (expr.type === "identifier") return local.types.get(expr.text) ?? null
		if (expr.type === "call_expression") {
			if (calleeName(expr) === "new" && args(expr)[0]) return qualType(args(expr)[0].text)
			const target = resolveCall(expr, local, info)[0]
			return target ? resultsOf(target.node)[0] ?? null : null
		}
		return null
	}

	ctx.resolveName = (fnExpr, local, file) => resolveName(fnExpr, local, { ...fileInfo.get(file), file }, false, null)
	ctx.resolveCall = (call, local, file) => resolveCall(call, local, { ...fileInfo.get(file), file })
	// only a method whose receiver type is known: api.playlists.Delete, not db.Delete
	ctx.resolveTyped = (call, local, file) => {
		const fnExpr = field(call, "function")
		return fnExpr?.type === "selector_expression" ? resolveName(fnExpr, local, { ...fileInfo.get(file), file }, false, args(call).length, true) : []
	}
	ctx.typeOf = (expr, local, file) => typeOf(expr, local, { ...fileInfo.get(file), file })
	// the struct a type name means from this file: models.User through the import, User in this package
	ctx.structOf = (typeText, file) => {
		if (!typeText) return null
		const [alias, name] = typeText.includes(".") ? typeText.split(".") : [null, typeText]
		const list = types.get(name)
		if (!list?.length) return null
		if (alias) {
			const imp = fileInfo.get(file)?.imports.get(alias)
			const dir = imp ? importDir(imp) : null
			return list.find(t => t.dir === dir) ?? null
		}
		return list.find(t => t.dir === path.dirname(file)) ?? (list.length === 1 ? list[0] : null)
	}

	// every function is a starting point; routes reached with a known prefix replace the guesses
	for (const [file, info] of fileInfo) info.file = file
	const entries = []
	for (const pkg of pkgs.values()) entries.push(...pkg.funcs.values(), ...pkg.literals)
	for (const list of methods.values()) entries.push(...list)
	// main and the functions that build routers first, so routers passed around are known when reached
	entries.sort((a, b) => Number(field(b.node, "name")?.text === "main") - Number(field(a.node, "name")?.text === "main"))
	// main.go often imports no framework itself: router.New(), h.Register(v1)
	const ROUTING_TEXT = /\.(Group|Route|Mount|Handle|HandleFunc|Use|Register\w*|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(|[Rr]outer|[Mm]ux\b/
	const relevant = entries.filter(e => fileInfo.get(e.file).frameworks.length || ROUTING_TEXT.test(e.node.text))
	// twice: the first pass learns routers kept in struct fields, the second uses them wherever they are read
	for (const pass of [1, 2]) {
		sites.clear()
		returnedCache.clear()
		analysed.clear()
		for (const entry of relevant) {
			entryKey = `${entry.file}:${lineOf(entry.node)}`
			const env = { routers: new Map(), types: new Map() }
			for (const p of paramsOf(entry.node)) if (p.name && ROUTER_TYPE.test(p.type)) env.routers.set(p.name, makeRouter(null, "", false))
			analyse(entry.node, entry.file, env, 0)
		}
	}

	const prefixOf = router => {
		const parts = []
		let anchored = true
		let origin = null
		for (let r = router; r; r = r.parent) {
			parts.unshift(r.segment)
			if (!r.parent) {
				anchored = r.anchored
				origin = r.origin
			}
		}
		return { prefix: parts.join("/"), anchored, origin }
	}
	for (const variants of sites.values()) {
		const fromRoots = variants.filter(v => !reached.has(v.entry))
		const resolved = (fromRoots.length ? fromRoots : variants).map(v => ({ v, ...prefixOf(v.router), mw: v.mwAt ?? fullMw(v.router) }))
		const anchoredOnes = resolved.filter(r => r.anchored)
		const keep = anchoredOnes.length ? anchoredOnes : resolved.slice(0, 1)
		const seen = new Set()
		for (const { v, prefix, anchored, mw, origin } of keep) {
			const full = normalisePath(`${prefix}/${v.raw}`)
			for (const method of v.method.split("|")) {
				if (seen.has(`${method} ${full}`)) continue
				seen.add(`${method} ${full}`)
				const middleware = [...mw, ...v.mw, ...handlerChecks(v.fn)]
				const { auth, role } = classifyGo(method === "GET" ? middleware.filter(m => !m.endsWith("(skips GET)")) : middleware)
				const route = {
					method,
					path: full,
					middleware,
					auth,
					role,
					handler: v.handlerName,
					file: path.relative(root, v.file),
					line: v.line,
					framework: v.framework,
					anchored,
					lang: "go"
				}
				Object.defineProperties(route, {
					go: { value: { fn: v.fn, ctx } },
					root: { value: root },
					rootFile: { value: anchored && origin ? origin : moduleOf(v.file) },
					conditional: { value: v.conditional },
					ignored: { value: ignoredRules(v.file, v.line) },
					guards: { value: [] }
				})
				routes.push(route)
			}
		}
	}
	Object.defineProperty(routes, "goContext", { value: ctx })
	return routes
}

// a check the handler makes first thing: s := Auth(c, acl.ResourcePhotos, acl.ActionView)
const INLINE_AUTH = /^(Auth\w*|Authenticate\w*|Authori[sz]e\w*|Require\w*|Must\w*(Auth|User|Login|Session)\w*|Check\w*(Auth|Session|Token|Login|Permission|Access)\w*|Verify\w*(Token|Session|Auth)\w*|SessionRequired|LoginRequired)$/
const ROLE_CALL = /^(require|assert|ensure|check|verify|enforce|must)_?(admin|role|permission|staff|owner|system_?admin|super_?user)|^is_?(admin|staff|owner|system_?admin|super_?user)\w*$|^has_?(role|permission)|permission_?to|^can[A-Z]/i
const INLINE_ROLE = /admin|role|acl\.|permission|Permission|Action\w+|Resource\w+|Scope/
function handlerChecks(fn) {
	if (!fn?.node) return []
	const params = paramsOf(fn.node).filter(p => p.name && HANDLER_PARAM.test(p.type)).map(p => p.name)
	const found = []
	walk(field(fn.node, "body"), n => {
		if (n.type === "func_literal") return false
		if (n.type !== "call_expression" || !INLINE_AUTH.test(calleeName(n))) return
		const a = args(n)
		if (!a.some(x => params.includes(x.text))) return
		const rest = a.filter(x => !params.includes(x.text)).map(x => x.text).join(",")
		found.push(`${calleeName(n)}(in handler${INLINE_ROLE.test(rest) || ROLE_NAME.test(calleeName(n)) ? ", role" : ""})`)
	})
	// c.App.SessionHasPermissionTo(session, model.PermissionManageSystem), if !user.IsAdmin { 403 }
	walk(field(fn.node, "body"), n => {
		if (n.type === "func_literal") return false
		if (n.type === "call_expression" && ROLE_CALL.test(calleeName(n))) found.push(`${calleeName(n)}(in handler, role)`)
		if (n.type === "if_statement" && /\b(IsAdmin|IsSystemAdmin|IsSuperuser|IsSuperUser|Admin|IsStaff)\b/.test(field(n, "condition")?.text ?? "") && /Forbidden|403|Unauthorized|401/.test(field(n, "consequence")?.text ?? ""))
			found.push("admin check(in handler, role)")
	})
	return [...new Set(found)]
}

// api.BaseRoutes.Users and a.BaseRoutes.Users are the same field; line.User is not BaseRoutes.User
const fieldKey = text => text.replace(/\s+/g, "").split(".").slice(1).join(".")

// if setting.EnablePprof { r.Get("/debug/pprof", ...) }: the route exists only when a setting is on
const SETTING = /debug|pprof|profil|enable|dev\b|development|metrics|\.Is\w*Enabled|Opts\.|config\.|setting\.|Setting|Config/i
function settingGuard(call, callers) {
	for (let n = call.parent; n; n = n.parent) {
		if (n.type === "if_statement") {
			const condition = field(n, "condition")?.text ?? ""
			if (SETTING.test(condition)) return condition.slice(0, 60)
		}
		// if setting.EnablePprof { go servePprof() }: the whole function is behind the setting
		if (/^(function_declaration|method_declaration)$/.test(n.type)) return callers?.(field(n, "name")?.text) ?? null
	}
	return null
}

// "GET", http.MethodGet → "GET"
function methodOf(node) {
	const text = node?.type === "selector_expression" ? node.text.match(/^http\.Method(\w+)$/)?.[1]?.toUpperCase() : stringValue(node)
	if (!text) return null
	// "GET,OPTIONS": Gitea's m.Methods lists several
	const methods = text.split(/\s*,\s*/).filter(m => /^[A-Z]+$/.test(m))
	const real = methods.length > 1 ? methods.filter(m => m !== "OPTIONS") : methods
	return real.length ? real.join("|") : null
}

// "/api//users/{id:[0-9]+}/" → "/api/users/{id}"
function normalisePath(p) {
	const clean = p
		.replace(/\{(\w+):[^}]*\}/g, "{$1}")
		.replace(/\{(\w+)\.\.\.\}/g, "*")
		.replace(/\/+/g, "/")
		.replace(/(.)\/$/, "$1")
	return clean.startsWith("/") ? clean : `/${clean}`
}

// a struct's fields with their JSON names; embedded structs are listed by type and opened later
function structFields(struct) {
	const out = []
	for (const decl of field(struct, "body")?.namedChildren ?? struct.namedChildren.find(c => c.type === "field_declaration_list")?.namedChildren ?? []) {
		if (decl.type !== "field_declaration") continue
		const type = field(decl, "type")?.text ?? ""
		const tag = field(decl, "tag")?.text ?? ""
		const json = tag.match(/json:"([^"]*)"/)?.[1]
		const names = decl.namedChildren.filter(c => c.type === "field_identifier").map(c => c.text)
		if (names.length === 0) out.push({ embedded: type.replace(/^[*\s]+/, "") })
		for (const name of names) out.push({ name, type, json: json?.split(",")[0] || name, hidden: json?.split(",")[0] === "-", binding: tag })
	}
	return out
}
