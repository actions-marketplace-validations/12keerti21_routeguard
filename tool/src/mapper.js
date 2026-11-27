import { readdirSync, readFileSync, existsSync, statSync } from "node:fs"
import path from "node:path"
import { parse } from "@babel/parser"

const FRAMEWORK = [
	["express", /^express$/],
	["fastify", /^(fastify|@fastify\/)/],
	["koa", /^(koa|@koa\/|koa-router)/],
	["nestjs", /^@nestjs\//],
	["hapi", /^@hapi\/hapi$/]
]

// objects that register routes: router, app, api, apiRouter, server (not cache.get or map.get)
const ROUTER_OWNER = /router|^app$|app\b|^api|route|server/i
const METHODS = new Set(["get", "post", "put", "patch", "delete", "all", "options", "head"])
// static and frontend code holds no Express routes; juice-shop keeps challenge snippets in data/static
const SKIP_DIRS = new Set([
	"node_modules", "dist", "build", "coverage", "client", "frontend", "public", "static",
	"test", "tests", "__tests__", "e2e", "cypress", "playwright", "mocks", "__mocks__", "stubs", "examples", "example", "storybook"
])
// bundles and vendored releases (.yarn/releases/yarn-4.cjs) are not the app's code
const MAX_SOURCE_BYTES = 512 * 1024
const SOURCE = /\.(c|m)?(j|t)s$/

// role checks first: "adminAuth" is a role check, not just an auth check
// isAuthorized() only checks login; authorize(ADMIN) with an argument names a role
// isAccounting(), isStaff(): an "is" check that is not about being signed in
// requireGroupMemberManagement, ensureProjectAccess, checkOwner: a named check on a right, not on login
// scimAuth: a provisioning token only the identity provider holds
const ROLE =
	/admin|role|scim|permission|owner|rbac|acl|can[A-Z]|scope|^is_?(?!auth|logged|signed|valid|verified)[a-z]+$|^(require|ensure|check|assert|verify)_?\w*(manag|access|member|owner|permission|role|staff|privilege|collaborat)/i
// auth('manageUsers'), permit('editor'): a guard called with the right it demands
const PERMISSION_CALL = /(^|\.)(auth|authori[sz]e|permit|allow|can|requires?|guard)\((?!\))/i
// matched against a function's own name: isAuthenticated, checkAuth, auth.jwt, verifyToken, apiAuth
// but not jwtChallenges or updateAuthenticatedUsers
const AUTH =
	/^((is|ensure|require|check|verify|validate)_?)?((api_?)?auth\w*|jwt|token|api_?key|log(ged)?_?in|protect(ed)?|guard)$|auth$|auth(enticate|entication)?_?(middleware|guard)$|^(is|ensure|require|check|verify|validate)_?(session|user|signed_?in)\w*$/i
// auth.required, passport.check: the last segment says little, so the whole name decides
const GENERIC = /^(required|check|ensure|verify|middleware|guard|protect|handler|validate)$/i
// present in the chain but enforces nothing
// authLimiter is rate limiting, not authentication
const NOT_ENFORCED = /optional|initialize|session\(|limit|throttle/i

export function listSourceFiles(root) {
	const files = []
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue
		const full = path.join(root, entry.name)
		if (entry.isDirectory()) files.push(...listSourceFiles(full))
		else if (SOURCE.test(entry.name) && !/\.(d|test|spec|min)\.(j|t)s$/.test(entry.name) && statSync(full).size <= MAX_SOURCE_BYTES) files.push(full)
	}
	return files
}

export function parseFile(file) {
	try {
		return parse(readFileSync(file, "utf8"), {
			sourceType: "unambiguous",
			errorRecovery: true,
			plugins: ["jsx", "typescript", "decorators-legacy"]
		})
	} catch {
		return null
	}
}

export function walk(node, visit) {
	if (!node || typeof node.type !== "string") return
	visit(node)
	for (const key of Object.keys(node)) {
		if (key === "loc" || key === "start" || key === "end") continue
		const child = node[key]
		if (Array.isArray(child)) child.forEach(c => walk(c, visit))
		else if (child && typeof child.type === "string") walk(child, visit)
	}
}

// a.b and a?.b, a() and a?.()
export const isMemberNode = node => node?.type === "MemberExpression" || node?.type === "OptionalMemberExpression"
export const isCallNode = node => node?.type === "CallExpression" || node?.type === "OptionalCallExpression"
const isMember = (node, objectName) => isMemberNode(node) && node.object.type === "Identifier" && node.object.name === objectName
const isFunctionNode = node => ["ArrowFunctionExpression", "FunctionExpression", "FunctionDeclaration", "ObjectMethod", "ClassMethod"].includes(node?.type)

// package.json "imports": { "#*": "./src/*" } lets code import "#modules/x.js"
let subpathImports = { root: "", map: {} }

// monorepo packages by name: "@verdaccio/middleware" → packages/middleware
let workspacePackages = new Map()

function findPackages(dir, depth = 0, out = new Map()) {
	if (depth > 4) return out
	let entries
	try {
		entries = readdirSync(dir, { withFileTypes: true })
	} catch {
		return out
	}
	for (const entry of entries) {
		if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) findPackages(path.join(dir, entry.name), depth + 1, out)
		if (entry.name === "package.json" && depth > 0) {
			try {
				const pkg = JSON.parse(readFileSync(path.join(dir, entry.name), "utf8"))
				if (pkg.name) out.set(pkg.name, dir)
			} catch {}
		}
	}
	return out
}

function resolvePackage(spec) {
	const name = [...workspacePackages.keys()].filter(n => spec === n || spec.startsWith(`${n}/`)).sort((a, b) => b.length - a.length)[0]
	if (!name) return null
	const dir = workspacePackages.get(name)
	const sub = spec.slice(name.length + 1)
	if (sub) return path.join(dir, sub)
	for (const entry of ["src/index.ts", "src/index.js", "index.ts", "index.js", "lib/index.js"])
		if (existsSync(path.join(dir, entry))) return path.join(dir, entry)
	return null
}

function loadSubpathImports(root) {
	workspacePackages = findPackages(root)
	try {
		const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"))
		subpathImports = { root, map: pkg.imports ?? {} }
	} catch {
		subpathImports = { root, map: {} }
	}
}

function resolveSubpath(spec) {
	for (const [key, value] of Object.entries(subpathImports.map)) {
		const target = typeof value === "string" ? value : (value?.node ?? value?.import ?? value?.default)
		if (typeof target !== "string") continue
		const star = key.indexOf("*")
		if (star === -1 && key === spec) return path.resolve(subpathImports.root, target)
		if (star !== -1 && spec.startsWith(key.slice(0, star)) && spec.endsWith(key.slice(star + 1)))
			return path.resolve(subpathImports.root, target.replace("*", spec.slice(star, spec.length - (key.length - star - 1))))
	}
	return null
}

function resolveModule(fromFile, spec) {
	if (!spec) return null
	const base = spec.startsWith("#")
		? resolveSubpath(spec)
		: spec.startsWith(".")
			? path.resolve(path.dirname(fromFile), spec)
			: resolvePackage(spec)
	if (!base) return null
	// TypeScript sources import "./x.js" for a file that is x.ts on disk
	const tsBase = base.replace(/\.(m|c)?js$/, (_, kind) => `.${kind ?? ""}ts`)
	for (const candidate of [base, tsBase, ...["", ".js", ".ts", ".mjs", ".cjs", ".tsx", "/index.js", "/index.ts"].map(ext => base + ext)]) {
		if (existsSync(candidate) && statSync(candidate).isFile()) return candidate
	}
	return null
}

function stringValue(node) {
	if (!node) return null
	if (node.type === "StringLiteral") return node.value
	if (node.type === "TemplateLiteral" && node.expressions.length === 0) return node.quasis[0].value.cooked
	return null
}

function nameOf(node) {
	if (isMemberNode(node)) return `${nameOf(node.object)}.${node.property.name ?? "?"}`
	if (isCallNode(node)) {
		const args = node.arguments.map(a => stringValue(a) ?? nameOf(a) ?? "…")
		return `${nameOf(node.callee)}(${args.join(", ")})`
	}
	if (node?.type === "Identifier") return node.name
	if (isFunctionNode(node)) return "<inline>"
	return null
}

// catchAsync(async (req, res) => {}) and asyncHandler(getUser) wrap the real handler
function unwrapHandler(node) {
	if (isCallNode(node)) {
		// asyncHandler(retrieveBasket()): the inner call is a factory, keep it for the resolver
		const inner = node.arguments.find(a => isFunctionNode(a) || a.type === "Identifier" || isMemberNode(a) || isCallNode(a))
		return inner ? unwrapHandler(inner) : node
	}
	return node
}

// plumbing, not access control
const NOISE = /^(cors|vhost|morgan|compression|helmet|cookieParser|bodyParser|express\.(json|urlencoded|static|text|raw))\b/

// [auth, admin] and auth, admin both mean two middlewares
function flattenMiddleware(args) {
	return args
		.flatMap(a => (a.type === "ArrayExpression" ? a.elements : [a]))
		.map(nameOf)
		.filter(name => name && !NOISE.test(name))
}

// router.route("/x").get(…).post(…): the path sits on .route(), down the chain
function routeChainPath(object) {
	let node = object
	while (isCallNode(node) && isMemberNode(node.callee)) {
		const prop = node.callee.property.name
		if (prop === "route") return stringValue(node.arguments[0])
		if (!METHODS.has(prop)) return null
		node = node.callee.object
	}
	return null
}

// Router().use(a).use(b) and router.route("/x").get(…): the object at the root of the chain
function chainRootNode(object) {
	let node = object
	while (isCallNode(node) && isMemberNode(node.callee) && /^(use|route|get|post|put|patch|delete|all)$/.test(node.callee.property.name))
		node = node.callee.object
	return node
}

function scanFile(file) {
	const ast = parseFile(file)
	const result = {
		file,
		requires: new Map(),
		named: new Map(),
		mounts: [],
		localMounts: new Map(),
		routes: [],
		uses: [],
		pathUses: [],
		// const PREFIX = "/api", const ENDPOINTS = { list: "/stage" }, enum ENDPOINTS { list = "/stage" }
		constants: new Map(),
		reexportAll: [],
		reexportNamed: new Map(),
		// module.exports = router / export default router: which router a plain import gets
		defaultExport: null,
		createsApp: false,
		functions: new Map(),
		frameworks: new Set()
	}
	if (!ast) return result

	// const api = Router().use(a).use(b): calls on that chain belong to "api", not to "Router()"
	const chainOwners = new Map()
	walk(ast, node => {
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && isCallNode(node.init))
			chainOwners.set(chainRootNode(node.init), node.id.name)
	})
	// const routes = [{ path: "/auth", route: authRoute }, …]: for routes.forEach(r => router.use(r.path, r.route))
	const arrays = new Map()
	walk(ast, node => {
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init?.type === "ArrayExpression")
			arrays.set(node.id.name, node.init.elements)
	})
	// return client.get(url, config), await api.post(url, data), http.get(url).then(…): an HTTP client call, not a route
	const consumed = new Set()
	walk(ast, node => {
		if ((node.type === "ReturnStatement" || node.type === "AwaitExpression") && isCallNode(node.argument)) consumed.add(node.argument)
		if (isMemberNode(node) && ["then", "catch", "finally"].includes(node.property?.name) && isCallNode(node.object)) consumed.add(node.object)
	})
	const chainRoot = object => {
		const root = chainRootNode(object)
		return chainOwners.get(root) ?? nameOf(root)
	}

	walk(ast, node => {
		// named handlers: function getBook() {}, const getBook = () => {}, const getBook = catchAsync(() => {})
		if (node.type === "FunctionDeclaration" && node.id) result.functions.set(node.id.name, node)
		// this.loadThread(req) inside a controller class
		if (node.type === "ClassMethod" && node.key?.type === "Identifier" && !result.functions.has(node.key.name)) result.functions.set(node.key.name, node)
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init) {
			const fn = unwrapHandler(node.init)
			if (isFunctionNode(fn)) result.functions.set(node.id.name, fn)
		}
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init) {
			let init = node.init
			while (["TSAsExpression", "TSSatisfiesExpression"].includes(init.type) || (isCallNode(init) && nameOf(init.callee) === "Object.freeze")) init = init.expression ?? init.arguments[0]
			if (["StringLiteral", "TemplateLiteral", "ObjectExpression", "BinaryExpression"].includes(init?.type)) result.constants.set(node.id.name, init)
		}
		if (node.type === "TSEnumDeclaration")
			result.constants.set(node.id.name, { type: "Enum", members: new Map(node.members.map(m => [m.id.name ?? m.id.value, m.initializer])) })
		if (node.type === "ExportAllDeclaration") {
			const target = resolveModule(file, node.source.value)
			if (target) result.reexportAll.push(target)
		}
		if (node.type === "ExportNamedDeclaration" && node.source) {
			const target = resolveModule(file, node.source.value)
			if (target) for (const sp of node.specifiers) if (sp.local) result.reexportNamed.set(sp.exported.name ?? sp.exported.value, { file: target, name: sp.local.name })
		}

		if (node.type === "AssignmentExpression" && nameOf(node.left) === "module.exports" && node.right.type === "Identifier")
			result.defaultExport = node.right.name
		if (node.type === "ExportDefaultDeclaration")
			result.defaultExport = node.declaration.type === "Identifier" ? node.declaration.name : isCallNode(node.declaration) ? chainRoot(node.declaration) : null
		if (isCallNode(node) && (node.callee.name === "express" || (isMemberNode(node.callee) && node.callee.property.name === "listen")))
			result.createsApp = true

		// const Controller = { getMessages(req, res) {…}, list: async (req, res) => {…} }; export default Controller
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init?.type === "ObjectExpression") {
			for (const prop of node.init.properties) {
				const key = prop.key?.name ?? prop.key?.value
				if (!key) continue
				if (prop.type === "ObjectMethod") result.functions.set(key, prop)
				else if (prop.type === "ObjectProperty") {
					const fn = unwrapHandler(prop.value)
					if (isFunctionNode(fn) && !result.functions.has(key)) result.functions.set(key, fn)
				}
			}
		}

		// exports.getBook = () => {} and module.exports.getBook = () => {}
		if (node.type === "AssignmentExpression" && isMemberNode(node.left) && /^(module\.)?exports\./.test(nameOf(node.left))) {
			const fn = unwrapHandler(node.right)
			if (isFunctionNode(fn)) result.functions.set(node.left.property.name, fn)
		}

		// which web framework each file builds on, for the warning when it is not Express
		const spec = node.type === "ImportDeclaration" ? node.source.value : isCallNode(node) && node.callee.name === "require" ? stringValue(node.arguments[0]) : null
		const framework = spec && FRAMEWORK.find(([, pattern]) => pattern.test(spec))?.[0]
		if (framework) result.frameworks.add(framework)

		// const users = require("./users") and const { getUser } = require("./users")
		if (node.type === "VariableDeclarator" && isCallNode(node.init) && node.init.callee.name === "require") {
			const target = resolveModule(file, stringValue(node.init.arguments[0]))
			if (target && node.id.type === "Identifier") result.requires.set(node.id.name, target)
			if (target && node.id.type === "ObjectPattern")
				for (const p of node.id.properties)
					if (p.value?.type === "Identifier") result.named.set(p.value.name, { file: target, name: p.key.name })
		}
		// import users from "./users" and import { getUser } from "./users"
		if (node.type === "ImportDeclaration") {
			const target = resolveModule(file, node.source.value)
			if (!target) return
			for (const s of node.specifiers) {
				if (s.type === "ImportDefaultSpecifier" || s.type === "ImportNamespaceSpecifier") result.requires.set(s.local.name, target)
				if (s.type === "ImportSpecifier") result.named.set(s.local.name, { file: target, name: s.imported.name ?? s.imported.value })
			}
		}

		if ((node.type === "ClassDeclaration" || node.type === "ClassExpression") && node.decorators?.length) {
			const routes = decoratedRoutes(node)
			result.routes.push(...routes)
			if (routes.length) result.frameworks.add("decorators")
		}
		// providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }], app.useGlobalGuards(...): every route is guarded
		if (node.type === "Identifier" && node.name === "APP_GUARD") result.globalGuard = true
		if (isCallNode(node) && isMemberNode(node.callee) && node.callee.property.name === "useGlobalGuards") result.globalGuard = true
		if (isCallNode(node) && isMemberNode(node.callee) && node.callee.property.name === "setGlobalPrefix") result.globalPrefix = stringValue(node.arguments[0])

		if (!isCallNode(node) || !isMemberNode(node.callee)) return
		const method = node.callee.property.name

		if (method === "forEach" && node.callee.object.type === "Identifier" && arrays.has(node.callee.object.name)) {
			const callback = node.arguments[0]
			const item = callback?.params?.[0]?.name
			if (!item) return
			walk(callback.body, inner => {
				if (!isCallNode(inner) || !isMemberNode(inner.callee) || inner.callee.property.name !== "use") return
				const [pathArg, routerArg] = inner.arguments
				if (!isMember(pathArg, item) || !isMember(routerArg, item)) return
				for (const element of arrays.get(node.callee.object.name)) {
					if (element?.type !== "ObjectExpression") continue
					const field = key => element.properties.find(p => p.key?.name === key)?.value
					const prefix = stringValue(field(pathArg.property.name))
					const target = field(routerArg.property.name)
					if (prefix !== null && target?.type === "Identifier")
						result.mounts.push({ owner: chainRoot(inner.callee.object), prefix, target: target.name, middleware: [], allMiddleware: [], line: inner.loc.start.line })
				}
			})
			return
		}
		const owner = chainRoot(node.callee.object)
		const line = node.loc.start.line
		const [first, ...rest] = node.arguments
		const routePath = stringValue(first)

		// router.get(ENDPOINTS.list, …), app.use(`${PREFIX}/users`, users): resolved once every file is read
		const pathExpression =
			routePath === null && ["Identifier", "MemberExpression", "TemplateLiteral", "BinaryExpression"].includes(first?.type) && ROUTER_OWNER.test(owner ?? "")
				? first
				: null

		if (method === "use") {
			if (routePath !== null || (pathExpression && rest.length > 0 && !isFunctionNode(rest.at(-1)) && !isCallNode(rest.at(-1)) && rest.at(-1)?.type === "Identifier" && first.type !== "Identifier")) {
				// app.use("/api/users", auth, users): the last identifier is the mounted router
				const last = rest.at(-1)
				const target = last?.type === "Identifier" ? last.name : null
				result.mounts.push({
					owner,
					prefix: routePath,
					prefixNode: routePath === null ? first : null,
					target,
					middleware: flattenMiddleware(rest.slice(0, -1)),
					// app.use("/rest/basket", isAuthorized()): no router, so every argument is middleware
					allMiddleware: flattenMiddleware(rest),
					line
				})
			} else {
				// app.use(auth) is middleware, app.use(usersRouter) mounts at "", sorted out once every file is read
				const idents = node.arguments.filter(a => a.type === "Identifier").map(a => a.name)
				result.uses.push({ owner, middleware: flattenMiddleware(node.arguments), idents, line })
			}
			return
		}

		if (!METHODS.has(method)) return
		if (consumed.has(node) && !isFunctionNode(unwrapHandler(node.arguments.at(-1))) && !/router|^app$|server/i.test(nameOf(chainRootNode(node.callee.object)) ?? "")) return
		if (routePath !== null && rest.length > 0) {
			if (!handlerLike(rest.at(-1))) return
			result.routes.push(routeEntry(owner, method, routePath, rest, line))
			return
		}
		if (pathExpression && rest.length > 0 && rest.some(a => isFunctionNode(a) || a.type === "Identifier" || isMemberNode(a) || isCallNode(a))) {
			result.routes.push({ ...routeEntry(owner, method, null, rest, line), pathNode: first })
			return
		}
		const chainPath = routeChainPath(node.callee.object)
		if (chainPath !== null && node.arguments.length > 0) result.routes.push(routeEntry(owner, method, chainPath, node.arguments, line))
	})
	return result
}

// @Controller("users") class UsersController { @Get(":id") findOne(@Param("id") id) {} }
// NestJS, routing-controllers, and n8n's @RestController (signed in unless skipAuth, mounted at /rest)
const CONTROLLER = { Controller: "", JsonController: "", RestController: "/rest", RootLevelController: "", PublicApiController: "/api/v1" }
const SIGNED_IN_BY_DEFAULT = { RestController: "authenticated", RootLevelController: "authenticated", PublicApiController: "apiKeyAuth" }
const ROUTE_DECORATOR = { Get: "get", Post: "post", Put: "put", Patch: "patch", Delete: "delete", All: "all", Options: "options", Head: "head" }
// docs, serialisation and plumbing say nothing about who may call the route
const DECORATOR_NOISE = /^(Api(?!KeyScope)[A-Z]\w*|HttpCode|Header|Redirect|Render|Version|Deprecated|Licensed|Use(Interceptors|Pipes|Filters)|SerializeOptions|Sse|OnPubSubEvent|Injectable|Service)$/
// @Public(), @SkipAuth(): the route opts out of a global guard
const PUBLIC_DECORATOR = /^(Public|IsPublic|SkipAuth|NoAuth|AllowAnonymous|Anonymous|Unauthenticated)$/i

const decoratorCallee = d => (isCallNode(d.expression) ? d.expression.callee : d.expression)
const decoratorName = d => {
	const callee = decoratorCallee(d)
	return (isMemberNode(callee) ? callee.property.name : callee.name) ?? ""
}

// what a decorator puts in front of the handler: @UseGuards(JwtGuard, RolesGuard) is two guards
function decoratorMiddleware(decorators) {
	const out = []
	for (const d of decorators ?? []) {
		const name = decoratorName(d)
		if (name in CONTROLLER || name in ROUTE_DECORATOR || DECORATOR_NOISE.test(name)) continue
		if (name === "UseGuards" && isCallNode(d.expression)) {
			out.push(...flattenMiddleware(d.expression.arguments.map(a => (a.type === "NewExpression" ? a.callee : a))))
			continue
		}
		const label = nameOf(d.expression)
		if (label) out.push(label)
	}
	return out
}

function decoratedRoutes(cls) {
	const controller = cls.decorators?.find(d => decoratorName(d) in CONTROLLER)
	if (!controller) return []
	const kind = decoratorName(controller)
	const arg = isCallNode(controller.expression) ? controller.expression.arguments[0] : null
	const base = stringValue(arg) ?? stringValue(arg?.properties?.find(p => p.key?.name === "path")?.value) ?? ""
	const classMiddleware = decoratorMiddleware(cls.decorators)
	const classPublic = cls.decorators.some(d => PUBLIC_DECORATOR.test(decoratorName(d)))
	const routes = []
	for (const member of cls.body.body) {
		if (member.type !== "ClassMethod" || !member.decorators) continue
		for (const d of member.decorators) {
			const method = ROUTE_DECORATOR[decoratorName(d)]
			if (!method) continue
			const [pathArg, options] = isCallNode(d.expression) ? d.expression.arguments : []
			const paths = pathArg?.type === "ArrayExpression" ? pathArg.elements.map(stringValue) : [stringValue(pathArg) ?? ""]
			const middleware = [...classMiddleware, ...decoratorMiddleware(member.decorators)]
			const open = classPublic || member.decorators.some(x => PUBLIC_DECORATOR.test(decoratorName(x)))
			for (const routePath of paths.filter(p => p !== null))
				routes.push({
					guards: [],
					owner: `@${cls.id?.name ?? "controller"}`,
					method: method.toUpperCase(),
					path: joinPath(joinPath(CONTROLLER[kind], base), routePath),
					middleware: [...middleware],
					handler: `${cls.id?.name ?? "?"}.${member.key.name ?? "?"}`,
					handlerNode: member,
					line: d.loc.start.line,
					decorated: { open, kind, options }
				})
		}
	}
	return routes
}

// what can end a route: a function, a name for one, or a call that builds one; never data
const handlerLike = node => isFunctionNode(node) || node?.type === "Identifier" || isMemberNode(node) || isCallNode(node)

function routeEntry(owner, method, routePath, args, line) {
	return {
		// inline middleware: (req, res, next) => { if (!req.user.admin) … } guards the route too
		guards: args
			.slice(0, -1)
			.flatMap(a => (a.type === "ArrayExpression" ? a.elements : [a]))
			.map(unwrapHandler)
			.filter(isFunctionNode),
		owner,
		method: method.toUpperCase(),
		path: routePath,
		middleware: flattenMiddleware(args.slice(0, -1)),
		handler: nameOf(args.at(-1)) ?? "?",
		handlerNode: args.at(-1),
		line
	}
}

function joinPath(prefix, routePath) {
	const joined = `${prefix}/${routePath}`.replace(/\/+/g, "/")
	return joined.length > 1 ? joined.replace(/\/$/, "") : joined
}

// auth.featureAccess and helpers.verify are not auth checks: judge the function's own name,
// falling back to the whole name only when that is generic (auth.required)
// asyncHandler(auth.jwt): the check is the wrapped argument, not the wrapper
function matches(pattern, middleware) {
	const open = middleware.indexOf("(")
	const base = open === -1 ? middleware : middleware.slice(0, open)
	const segments = base.split(".")
	const last = segments.at(-1)
	if (pattern.test(last) || (GENERIC.test(last) && segments.length > 1 && pattern.test(segments.at(-2)))) return true
	// only async wrappers: validate(authValidation.login) is a validator, not a login check
	if (!/async|wrap|catch|handler/i.test(last)) return false
	const inner = open === -1 ? "" : middleware.slice(open + 1, middleware.lastIndexOf(")"))
	return inner.split(",").some(arg => /^[\w.]+$/.test(arg.trim()) && matches(pattern, arg.trim()))
}

export function classify(middleware) {
	const enforced = middleware.filter(m => !NOT_ENFORCED.test(m))
	// createAuthMiddleware(config, "credentials:read"): a login that demands a scope
	const role = enforced.some(m => matches(ROLE, m) || PERMISSION_CALL.test(m) || (matches(AUTH, m) && /[(,]\s*[\w-]+:[\w-]+\s*[,)]/.test(m)))
	const auth = role || enforced.some(m => matches(AUTH, m))
	return { auth, role }
}

// "// routeguard-ignore BOLA" (or every rule, with no names) in the three lines above a route
const IGNORE = /routeguard-ignore(?:\s+([A-Z_, ]+))?/
const fileLines = new Map()

export function ignoredRules(file, line) {
	if (!fileLines.has(file)) fileLines.set(file, readFileSync(file, "utf8").split("\n"))
	const above = fileLines.get(file).slice(Math.max(0, line - 4), line).join("\n")
	const match = above.match(IGNORE)
	if (!match) return null
	return match[1] ? new Set(match[1].split(/[\s,]+/).filter(Boolean)) : "all"
}

export function mapRoutes(root) {
	loadSubpathImports(root)
	const scans = listSourceFiles(root).map(scanFile)
	const byFile = new Map(scans.map(s => [s.file, s]))
	const isRouterFile = file => byFile.get(file)?.routes.length > 0 || byFile.get(file)?.mounts.length > 0

	// a constant exported from `file` under `name`, following export * and export { x } from
	function exportedConstant(file, name, depth = 0) {
		const scan = byFile.get(file)
		if (!scan || depth > 4) return null
		if (scan.constants.has(name)) return { file, node: scan.constants.get(name) }
		const named = scan.reexportNamed.get(name)
		if (named) return exportedConstant(named.file, named.name, depth + 1)
		for (const next of scan.reexportAll) {
			const found = exportedConstant(next, name, depth + 1)
			if (found) return found
		}
		return null
	}

	function lookup(file, name) {
		const scan = byFile.get(file)
		if (!scan) return null
		if (scan.constants.has(name)) return { file, node: scan.constants.get(name) }
		const named = scan.named.get(name)
		if (named) return exportedConstant(named.file, named.name)
		const module = scan.requires.get(name)
		if (module) return { file: module, module: true }
		return null
	}

	// ENDPOINTS, Constants.API: an object (or enum, or module) whose properties can be read
	function evaluateObject(file, node, depth = 0) {
		if (depth > 6 || !node) return null
		if (node.type === "Identifier") {
			const found = lookup(file, node.name)
			if (!found) return null
			if (found.module) return { file: found.file, module: true }
			return evaluateObject(found.file, found.node, depth + 1)
		}
		if (node.type === "Enum") return { file, get: key => node.members.get(key) }
		if (node.type === "ObjectExpression")
			return { file, get: key => node.properties.find(p => (p.key?.name ?? p.key?.value) === key)?.value }
		if (isMemberNode(node)) {
			const owner = evaluateObject(file, node.object, depth + 1)
			const key = node.computed ? stringValue(node.property) : node.property.name
			if (!owner || key == null) return null
			if (owner.module) {
				const found = exportedConstant(owner.file, key)
				return found ? evaluateObject(found.file, found.node, depth + 1) : null
			}
			return evaluateObject(owner.file, owner.get(key), depth + 1)
		}
		return null
	}

	function evaluateString(file, node, depth = 0) {
		if (!node || depth > 6) return null
		const literal = stringValue(node)
		if (literal !== null) return literal
		if (node.type === "TemplateLiteral") {
			const parts = node.expressions.map(e => evaluateString(file, e, depth + 1))
			if (parts.some(p => p === null)) return null
			return node.quasis.map((q, i) => q.value.cooked + (parts[i] ?? "")).join("")
		}
		if (node.type === "BinaryExpression" && node.operator === "+") {
			const left = evaluateString(file, node.left, depth + 1)
			const right = evaluateString(file, node.right, depth + 1)
			return left === null || right === null ? null : left + right
		}
		if (node.type === "Identifier") {
			const found = lookup(file, node.name)
			return found && !found.module ? evaluateString(found.file, found.node, depth + 1) : null
		}
		if (isMemberNode(node)) {
			const owner = evaluateObject(file, node.object)
			const key = node.computed ? stringValue(node.property) : node.property.name
			if (!owner || key == null) return null
			if (owner.module) {
				const found = exportedConstant(owner.file, key)
				return found ? evaluateString(found.file, found.node, depth + 1) : null
			}
			return evaluateString(owner.file, owner.get(key), depth + 1)
		}
		return null
	}

	// paths written as constants; one that cannot be worked out stays visible as <NAME>
	for (const scan of scans) {
		for (const route of scan.routes)
			if (route.path === null) route.path = evaluateString(scan.file, route.pathNode) ?? `<${nameOf(route.pathNode) ?? "path"}>`
		for (const mount of scan.mounts)
			if (mount.prefix === null) mount.prefix = evaluateString(scan.file, mount.prefixNode) ?? `<${nameOf(mount.prefixNode) ?? "prefix"}>`
	}

	// which router object an identifier imports: users → "routes/users.js#router", { learnerRouter } → "…#learnerRouter".
	// "*" when the file's default export is not a plain name, so the mount applies to every router in it
	function mountKey(scan, ident) {
		// only files that define routes: { authLimiter } from middlewares/rateLimiter.js is middleware
		const file = scan.requires.get(ident)
		if (file && isRouterFile(file)) return { file, key: `${file}#${byFile.get(file).defaultExport ?? "*"}` }
		const named = scan.named.get(ident)
		if (named && isRouterFile(named.file)) return { file: named.file, key: `${named.file}#${named.name}` }
		return null
	}

	// who mounts each file, with what prefix and mount-level middleware
	const mountedBy = new Map()
	const addMount = (target, mount) => {
		if (!mountedBy.has(target)) mountedBy.set(target, [])
		mountedBy.get(target).push(mount)
	}
	for (const scan of scans) {
		for (const mount of scan.mounts) {
			const target = mount.target && mountKey(scan, mount.target)
			if (target) addMount(target.key, { parent: scan.file, ...mount })
			// app.use("/api", api) where api is a router built in this file
			else if (mount.target && !scan.requires.has(mount.target) && !scan.named.has(mount.target) && !scan.functions.has(mount.target))
				scan.localMounts.set(mount.target, mount)
			else scan.pathUses.push({ owner: mount.owner, prefix: mount.prefix, middleware: mount.allMiddleware, line: mount.line })
		}
		for (const use of scan.uses) {
			const routers = use.idents.filter(id => isRouterFile(mountKey(scan, id)?.file))
			for (const id of routers)
				addMount(mountKey(scan, id).key, { parent: scan.file, owner: use.owner, prefix: "", middleware: [], line: use.line })
			// a mounted router is not middleware: authController must not count as an auth check
			use.middleware = use.middleware.filter(m => !routers.includes(m))
		}
	}

	// the prefix a router built in this file sits under: api → "/api" when app.use("/api", api)
	function localContext(scan, owner, seen = new Set()) {
		const mount = scan.localMounts.get(owner)
		if (!mount || seen.has(owner)) return { prefix: "", middleware: [], owner }
		seen.add(owner)
		const outer = localContext(scan, mount.owner, seen)
		return {
			prefix: joinPath(outer.prefix, mount.prefix),
			middleware: [...outer.middleware, ...inheritedUses(scan, mount.owner, mount.line), ...mount.middleware],
			owner: outer.owner
		}
	}

	// a router can be mounted at several prefixes, through nested routers. anchored: the chain
	// reaches a file that creates the app, so the full path is known
	function contexts(file, owner, seen = new Set()) {
		const key = `${file}#${owner}`
		const parents = [...(mountedBy.get(key) ?? []), ...(mountedBy.get(`${file}#*`) ?? [])]
		// a root is known when it creates the app or assembles other routers (startup/routes.js);
		// a router built in a factory and mounted by call has no known prefix
		const root = byFile.get(file)
		if (parents.length === 0 || seen.has(key)) return [{ prefix: "", middleware: [], anchored: Boolean(root?.createsApp || root?.mounts.length), rootFile: file }]
		seen.add(key)
		return parents.flatMap(m => {
			const local = localContext(byFile.get(m.parent), m.owner)
			return contexts(m.parent, local.owner, new Set(seen)).map(ctx => {
				return {
					anchored: ctx.anchored,
					rootFile: ctx.rootFile,
					prefix: joinPath(joinPath(ctx.prefix, local.prefix), m.prefix),
					middleware: [
						...ctx.middleware,
						...local.middleware,
						...inheritedUses(byFile.get(m.parent), m.owner, m.line),
						...m.middleware
					]
				}
			})
		})
	}

	// router.use(auth) applies to routes registered after it on the same object
	function inheritedUses(scan, owner, line) {
		return scan.uses.filter(u => u.owner === owner && u.line < line).flatMap(u => u.middleware)
	}

	const covers = (prefix, fullPath) => {
		const pattern = new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\:\w+|:\w+/g, "[^/]+")}(/|$)`, "i")
		return pattern.test(fullPath)
	}

	// app.use("/rest/basket", isAuthorized()) guards /rest/basket and everything under it
	function pathScopedUses(scan, route) {
		return scan.pathUses
			.filter(u => u.owner === route.owner && u.line <= route.line && covers(u.prefix, route.path))
			.flatMap(u => u.middleware)
	}

	// app.use("/v1/auth", authLimiter) in app.js covers routes defined in routes/auth.route.js
	const outerPathUses = scans.flatMap(scan =>
		scan.pathUses.flatMap(u => contexts(scan.file, localContext(scan, u.owner).owner).map(ctx => ({ file: scan.file, prefix: joinPath(ctx.prefix, u.prefix), middleware: u.middleware })))
	)
	const crossFileUses = (file, fullPath) =>
		outerPathUses.filter(u => u.file !== file && covers(u.prefix, fullPath)).flatMap(u => u.middleware)

	// the handler's function node and file, following controllers into the files they come from
	function resolveHandler(scan, node) {
		const target = unwrapHandler(node)
		// retrieveBasket(): a factory whose returned function is the handler
		if (isCallNode(target) && target.arguments.length === 0) {
			const factory = resolveHandler(scan, target.callee)
			let returned = null
			walk(factory?.fn?.body, n => {
				if (!returned && n.type === "ReturnStatement" && isFunctionNode(n.argument)) returned = n.argument
			})
			return returned ? { fn: returned, file: factory.file } : null
		}
		if (isFunctionNode(target)) return { fn: target, file: scan.file }
		if (target?.type === "Identifier") {
			if (scan.functions.has(target.name)) return { fn: scan.functions.get(target.name), file: scan.file }
			const imported = scan.named.get(target.name)
			const fn = byFile.get(imported?.file)?.functions.get(imported.name)
			return fn ? { fn, file: imported.file } : null
		}
		if (isMemberNode(target) && target.object.type === "ThisExpression")
			return scan.functions.has(target.property.name) ? { fn: scan.functions.get(target.property.name), file: scan.file } : null
		if (isMemberNode(target) && target.object.type === "Identifier") {
			const file = scan.requires.get(target.object.name) ?? scan.named.get(target.object.name)?.file
			// HistoryController.remove, with the controller defined in this file
			if (!file) return scan.functions.has(target.property.name) ? { fn: scan.functions.get(target.property.name), file: scan.file } : null
			const fn = byFile.get(file)?.functions.get(target.property.name)
			return fn ? { fn, file } : null
		}
		return null
	}

	// the file an identifier in `file` was imported from: User → models/user.js
	function importedFile(file, name) {
		const scan = byFile.get(file)
		return scan?.requires.get(name) ?? scan?.named.get(name)?.file ?? null
	}

	// the function a call in `file` names: getCourseShares(...), courseService.getCourse(...)
	function resolveCallee(file, callee) {
		const scan = byFile.get(file)
		if (!scan || !callee) return null
		const found = resolveHandler(scan, callee)
		return found?.fn?.body ? found : null
	}

	// NestJS: a guard registered for the whole app, and app.setGlobalPrefix("api")
	const globalGuard = scans.some(s => s.globalGuard)
	const globalPrefix = scans.find(s => s.globalPrefix)?.globalPrefix ?? ""

	// n8n: @Post("/login", { skipAuth: true, ipRateLimit: true, middlewares: [...] }), the options maybe imported
	function decorate(scan, route) {
		const { kind, options } = route.decorated
		route.decorated.done = true
		const object = options?.type === "ObjectExpression" ? { get: key => options.properties.find(p => p.key?.name === key)?.value } : options ? evaluateObject(scan.file, options) : null
		const option = key => (object?.module ? null : object?.get(key))
		const open = route.decorated.open || ["skipAuth", "allowUnauthenticated"].some(k => option(k)?.value === true)
		if (["rateLimit", "ipRateLimit", "keyedRateLimit"].some(k => option(k))) route.middleware.push("rateLimit")
		if (option("apiKeyAuth")?.value === true) route.middleware.push("apiKeyAuth")
		if (option("middlewares")) route.middleware.push(...flattenMiddleware([option("middlewares")]))
		if (SIGNED_IN_BY_DEFAULT[kind]) {
			if (!open) route.middleware.unshift(SIGNED_IN_BY_DEFAULT[kind])
			return
		}
		route.path = joinPath(globalPrefix, route.path)
		if (globalGuard && !open) route.middleware.unshift("globalAuthGuard")
	}

	const routes = []
	for (const scan of scans) {
		for (const route of scan.routes) {
			const handler = resolveHandler(scan, route.handlerNode)
			const local = route.decorated ? { prefix: "", middleware: [], owner: route.owner } : localContext(scan, route.owner)
			if (route.decorated && !route.decorated.done) decorate(scan, route)
			const routeContexts = route.decorated ? [{ prefix: "", middleware: [], anchored: true, rootFile: scan.file }] : contexts(scan.file, local.owner)
			for (const ctx of routeContexts) {
				const middleware = [
					...ctx.middleware,
					...local.middleware,
					...inheritedUses(scan, route.owner, route.line),
					...pathScopedUses(scan, route),
					...route.middleware
				]
				const fullPath = joinPath(joinPath(ctx.prefix, local.prefix), route.path)
				middleware.unshift(...crossFileUses(scan.file, fullPath))
				const entry = {
					method: route.method,
					path: fullPath,
					middleware,
					handler: route.handler,
					...classify(middleware),
					file: path.relative(root, scan.file),
					line: route.line
				}
				// kept off JSON output: rules read the handler's AST
				Object.defineProperty(entry, "fn", { value: handler?.fn?.body ? handler.fn : null })
				Object.defineProperty(entry, "fnFile", { value: path.relative(root, handler?.file ?? scan.file) })
				Object.defineProperty(entry, "fnPath", { value: handler?.file ?? scan.file })
				Object.defineProperty(entry, "guards", { value: route.guards ?? [] })
				// lets rules follow a call from the handler into the function it names
				Object.defineProperty(entry, "resolve", { value: resolveCallee })
				Object.defineProperty(entry, "importedFile", { value: importedFile })
				Object.defineProperty(entry, "root", { value: root })
				Object.defineProperty(entry, "anchored", { value: ctx.anchored })
				Object.defineProperty(entry, "rootFile", { value: ctx.rootFile })
				Object.defineProperty(entry, "ignored", { value: ignoredRules(scan.file, route.line) })
				routes.push(entry)
			}
		}
	}
	routes.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
	// how many files build on each framework: an app built on another one is read only in part
	const frameworks = {}
	for (const scan of scans) for (const f of scan.frameworks) frameworks[f] = (frameworks[f] ?? 0) + 1
	Object.defineProperty(routes, "frameworks", { value: frameworks })
	return routes
}
