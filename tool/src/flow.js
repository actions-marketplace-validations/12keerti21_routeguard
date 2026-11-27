import { walk, isCallNode, isMemberNode } from "./mapper.js"
import { DB_CALL, DB_WRITE, decoratedParams, handlerParams, isMember } from "./rules/handler.js"

// a call that takes the caller and decides: canEdit(user, course), assertCourseReach(user, id), findOwnedCourse(id, user)
const CHECK_FN = /can[A-Z_]|check|assert|ensure|reach|access|permi(t|ssion)|authori[sz]|verify|owned|own[A-Z]|allowed|guard|scope/i
// an unresolved call that looks like it loads a record: userService.getUserById(id)
const SERVICE_LOOKUP = /^(get|find|fetch|load|read|update|edit|patch|delete|remove|destroy|archive)[A-Z_]/
const IDENTITY_KEYS = new Set(["user", "auth", "session", "userId", "currentUser", "principal", "identity", "actor", "accountability", "claims"])
// queueScope(req, projectId): a filter built from the request is the caller's
const IDENTITY_FN = /user|auth|jwt|token|session|identity|principal|caller|scope/i
const APPENDS_USER = /(append|set|attach|inject|add)_?user/i
const BODY_USER_FIELD = /^(user_?id|owner_?id|owner)$/i
const MAX_DEPTH = 4
// a record created for the caller: comment.create({ author: user.id })
const CREATE = /^(create|insert|insertOne|insertMany|save|build|bulkCreate)$/
const SERVICE_WRITE = /^(update|edit|patch|delete|remove|destroy|archive)[A-Z_]/

// identifiers a node reads, skipping property names: in course.user, "user" is not a variable
function identifiers(node, out = []) {
	if (!node || typeof node.type !== "string") return out
	if (node.type === "Identifier") {
		out.push(node.name)
		return out
	}
	if (isMemberNode(node)) {
		identifiers(node.object, out)
		if (node.computed) identifiers(node.property, out)
		return out
	}
	if (node.type === "ObjectProperty") {
		if (node.computed) identifiers(node.key, out)
		identifiers(node.value, out)
		return out
	}
	for (const key of Object.keys(node)) {
		if (key === "loc" || key === "start" || key === "end") continue
		const child = node[key]
		if (Array.isArray(child)) child.forEach(c => identifiers(c, out))
		else if (child && typeof child.type === "string") identifiers(child, out)
	}
	return out
}

function boundNames(id) {
	if (!id) return []
	if (id.type === "Identifier") return [id.name]
	if (id.type === "AssignmentPattern") return boundNames(id.left)
	if (id.type === "RestElement") return boundNames(id.argument)
	if (id.type === "ObjectPattern") return id.properties.flatMap(p => boundNames(p.value ?? p.argument))
	if (id.type === "ArrayPattern") return id.elements.flatMap(boundNames)
	return []
}

const isFunction = node => ["ArrowFunctionExpression", "FunctionExpression"].includes(node?.type)

// solveIf(() => user.bid != id): a callback is code, not a value; its body is read where it is written
const valueArgs = call => call.arguments.filter(a => !isFunction(a))

const calleeName = call => (isMemberNode(call.callee) ? call.callee.property.name : call.callee.name) ?? ""

// how a request object marks URL values and the caller, under whatever name it has here
function requestPredicates(req, bodyIsCaller) {
	if (!req) return { isId: () => false, isCaller: () => false }
	return {
		isId: n => isMember(n, req, "params") || (isMemberNode(n) && isMember(n.object, req, "params")),
		isCaller: n =>
			(isMember(n, req) && IDENTITY_KEYS.has(n.property.name)) ||
			(bodyIsCaller && isMemberNode(n) && isMember(n.object, req, "body") && BODY_USER_FIELD.test(n.property.name ?? "")) ||
			(isCallNode(n) &&
				n.arguments.some(a => a.type === "Identifier" && a.name === req) &&
				IDENTITY_FN.test(isMemberNode(n.callee) ? `${n.callee.object.name ?? n.callee.object.property?.name ?? ""}.${n.callee.property.name}` : (n.callee.name ?? "")))
	}
}

function reads(node, names, predicate) {
	if (!node) return false
	if (identifiers(node).some(name => names.has(name))) return true
	let found = false
	walk(node, n => {
		if (!found && predicate(n)) found = true
	})
	return found
}

// pass the caller's arguments onto the callee's parameters
function bindArguments(fn, args, ctx, readsId, readsCaller) {
	const ids = new Set()
	const callers = new Set()
	let req = null
	fn.params.forEach((param, i) => {
		const arg = args[i]
		if (!arg || isFunction(arg)) return
		const target = param.type === "AssignmentPattern" ? param.left : param
		// service(req): the whole request travels, under the parameter's name
		if (arg.type === "Identifier" && arg.name === ctx.req && target.type === "Identifier") req = target.name
		if (target.type === "ObjectPattern" && arg.type === "ObjectExpression") {
			for (const prop of target.properties) {
				const value = arg.properties.find(a => a.key?.name === prop.key?.name)?.value
				if (!value) continue
				if (readsCaller(value)) boundNames(prop.value).forEach(n => callers.add(n))
				else if (readsId(value)) boundNames(prop.value).forEach(n => ids.add(n))
			}
			return
		}
		if (readsCaller(arg)) boundNames(target).forEach(n => callers.add(n))
		if (readsId(arg)) boundNames(target).forEach(n => ids.add(n))
	})
	return { ids, callers, req }
}

// Does the caller limit the record that the URL id reaches, here or in what this function calls?
// scoped: true, the caller is in the query, a guard or a check call
// scoped: false, a query uses the id and nothing on the way looks at the caller (at: where)
// scoped: null, nothing conclusive (trusted: the caller was handed to code we cannot read)
export function traceScope(ctx) {
	const { fn, file, resolve, depth = 0, seen = new Set(), chain = [] } = ctx
	const ids = new Set(ctx.ids ?? [])
	const callers = new Set(ctx.callers ?? [])
	const { isId, isCaller } = requestPredicates(ctx.req, ctx.bodyIsCaller)
	const readsId = node => reads(node, ids, isId)
	const readsCaller = node => reads(node, callers, isCaller)

	// const course = await findOwnedCourse(id, user) stands for the caller from here on
	for (let pass = 0; pass < 2; pass++) {
		walk(fn.body, n => {
			if (n.type !== "VariableDeclarator" || !n.init) return
			// a value built from both (findOwnedCourse(id, user)) belongs to both sets
			const caller = readsCaller(n.init)
			const id = readsId(n.init)
			if (caller) boundNames(n.id).forEach(name => callers.add(name))
			if (id) boundNames(n.id).forEach(name => ids.add(name))
		})
	}

	let scoped = false
	let why = null
	let trusted = false
	let ownedCreate = false
	const scope = (n, reason) => {
		if (!scoped) why = { file, line: n.loc.start.line, reason, chain }
		scoped = true
	}
	const unscoped = []

	walk(fn.body, n => {
		// if (course.ownerOrgId !== user.orgId): the caller compared with what the id reached.
		// if (!user) alone checks login, not ownership.
		// history[noteId] where history is the caller's own: the id only picks among the caller's records
		if (isMemberNode(n) && n.computed && readsCaller(n.object) && readsId(n.property)) scope(n, "id looked up in the caller's own data")
		if ((n.type === "IfStatement" || n.type === "ConditionalExpression") && readsCaller(n.test) && readsId(n.test))
			scope(n, "guard comparing the caller with the record")
		if (!isCallNode(n)) return

		const name = calleeName(n)
		const takesId = valueArgs(n).some(readsId)
		const takesCaller = valueArgs(n).some(readsCaller)
		if (takesCaller && CHECK_FN.test(name)) scope(n, `${name}(… caller …)`)
		if (takesCaller && CREATE.test(name)) ownedCreate = true
		// getHistory(req.user.id, (err, history) => …): history is the caller's
		if (takesCaller) n.arguments.filter(isFunction).forEach(cb => cb.params.flatMap(boundNames).forEach(p => callers.add(p)))
		if (!takesId || scoped) return

		const line = n.loc.start.line
		if (DB_CALL.test(name)) {
			if (takesCaller) scope(n, `${name} scoped to the caller`)
			else unscoped.push({ file, line, method: name, chain, write: DB_WRITE.test(name) })
			return
		}

		const target = depth < MAX_DEPTH ? resolve?.(file, n.callee) : null
		const key = target && `${target.file}:${target.fn.start}`
		if (!target || seen.has(key)) {
			if (takesCaller) trusted = true
			else if (SERVICE_LOOKUP.test(name)) unscoped.push({ file, line, method: name, chain, write: SERVICE_WRITE.test(name) })
			return
		}

		const bound = bindArguments(target.fn, n.arguments, ctx, readsId, readsCaller)
		const result = traceScope({
			fn: target.fn,
			file: target.file,
			resolve,
			ids: bound.ids,
			callers: bound.callers,
			req: bound.req,
			bodyIsCaller: ctx.bodyIsCaller,
			depth: depth + 1,
			seen: new Set([...seen, key]),
			chain: [...chain, name]
		})
		if (result.scoped === true) {
			if (!scoped) why = result.why
			scoped = true
		}
		else if (result.scoped === false) unscoped.push(...result.unscoped)
		else if (takesCaller || result.trusted) trusted = true
		if (result.ownedCreate) ownedCreate = true
	})

	if (scoped) return { scoped: true, why }
	const writes = unscoped.filter(u => u.write)
	// reading a public parent to attach the caller's own record is fine; changing it is not
	if (ownedCreate && writes.length === 0) return { scoped: true, why: { file, line: fn.loc.start.line, reason: "new record owned by the caller", chain }, ownedCreate }
	if (unscoped.length) return { scoped: false, at: writes[0] ?? unscoped[0], unscoped, ownedCreate }
	return { scoped: null, trusted, ownedCreate }
}

// start at a route's handler, where req.params are the ids and req.user is the caller
export function traceRoute(route) {
	const { req } = handlerParams(route.fn)
	const { ids, callers } = decoratedParams(route.fn)
	return traceScope({
		fn: route.fn,
		ids,
		callers,
		file: route.fnPath,
		resolve: route.resolve,
		req,
		bodyIsCaller: route.middleware.some(m => APPENDS_USER.test(m))
	})
}
