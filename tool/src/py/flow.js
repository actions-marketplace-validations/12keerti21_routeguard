// Follows a URL id through a Python view and the functions it calls, up to four calls deep, and looks
// for the caller limiting it: in the query, in a comparison, or in a check call.
import path from "node:path"
import { walk, field, lineOf, pyString, callName, callObject, posArgs, pyParams } from "./ast.js"

const DEPTH = 4
// ORM, raw SQL and Mongo calls, judged with what they are called on: User.query.get, Book.objects.filter
export const DB_METHOD = /^(get|get_or_404|first_or_404|one|one_or_none|first|filter|filter_by|where|delete|update|execute|exec|scalar|scalars|scalar_one|scalar_one_or_none|find_one|find|update_one|update_many|delete_one|delete_many|find_one_and_update|find_one_and_delete|replace_one|raw|get_by_id|get_or_none|get_object)$/
const DB_RECEIVER = /(^|\.)(query|objects|session|db|cursor|conn|connection|collection|coll|queryset|repo\w*|crud|dao|store)\b|^[A-Z]\w*\.(query|objects)|select\(/
export const DB_FN = /^(get_object_or_404|get_list_or_404)$/
const RECORD_SERVICE = /^(get|find|fetch|load|read|update|edit|patch|delete|remove|destroy|archive|lookup|retrieve)_\w+/
// the caller: request.user, current_user, g.user, get_jwt_identity(), a dependency that returns the user
const IDENTITY_ATTR = /^(request\.user|self\.request\.user|current_user|g\.user|g\.current_user|info\.context\.user|flask_login\.current_user|self\.user|self\.current_user|self\.current_org|current_org|g\.org|request\.org|self\.request\.org|request\.tenant)$/
const IDENTITY_FN = /current_?user|get_?jwt_?identity|get_?jwt|get_?current|token_?validator|decode_?(auth_?)?token|verify_?(auth_?)?token|get_?user_?from|auth_?user|logged_?in_?user|request_?user|get_?identity|authenticated_?user/i
const IDENTITY_KEY = /user|uid|sub|account|identity|owner|member/i
const CHECK_FN = /can_|check_object_permissions|has_object_permission|has_perm|authori[sz]|ensure_|verify_|assert_|require_|permit|allowed|owns|belongs|is_owner|is_member|has_access|check_access|check_permission/i
const OWNER_WORD = /user|owner|author|created_by|creator|account|tenant|org/i
const CALLER_ACTION = /^(create|save|insert|add|follow|unfollow|favou?rite|unfavou?rite|like|unlike|subscribe|unsubscribe|join|leave|vote|star|unstar|bookmark|react|pin|unpin|watch|unwatch|mark|remove|delete|un)/i
const READ_SINK = /\[…\]$|^(get|get_or_404|first_or_404|one|one_or_none|first|filter|filter_by|where|scalar|scalars|scalar_one|scalar_one_or_none|find_one|find|raw|get_by_id|get_or_none|get_object_or_404|get_list_or_404|get_object)$|^(get|find|fetch|load|read|lookup|retrieve)_/
const LOG_CALL = /^(debug|info|warning|warn|error|exception|critical|log|print|format|str|repr|int|len|abort|jsonify|Response|HTTPException|ValidationError|NotFound|Http404|PermissionDenied|_|gettext)$/

const chainTop = call => {
	let n = call
	while (n.parent?.type === "attribute" && n.parent.parent?.type === "call") n = n.parent.parent
	return n
}
const rootName = node => {
	let n = node
	while (n && (n.type === "attribute" || n.type === "call" || n.type === "subscript")) n = n.namedChildren[0]
	return n?.type === "identifier" ? n.text : null
}

// self.repo → self.repos → AllRepositories(session, group_id=self.group_id): scoped to the caller's tenant
const TENANT = /group_id|household_id|tenant|org_id|organi[sz]ation|user_id|owner|request\.user|self\.user/
function tenantScoped(receiver, owner, ctxRef) {
	if (!owner || !/^self\./.test(receiver)) return false
	const seen = new Set()
	const check = name => {
		if (seen.has(name) || seen.size > 4) return false
		seen.add(name)
		const m = ctxRef.classMethod(owner, name)
		if (!m) return false
		if (TENANT.test(m.node.text)) return true
		return [...m.node.text.matchAll(/self\.(\w+)/g)].some(x => x[1] !== name && check(x[1]))
	}
	return check(receiver.split(".")[1])
}

// self.queryset = self.queryset.restrict(request.user, action) in initial() or dispatch() of a base view
export function querysetScoped(owner, ctx) {
	if (!owner) return false
	for (const c of ctx.lineage(owner))
		for (const [name, m] of c.methods ?? []) {
			const t = m.node.text
			if (/^(initial|dispatch|get_queryset|filter_queryset|setup)$/.test(name) && /restrict\(|request\.user|self\.request\.user|for_user\(|current_user/.test(t)) return true
		}
	return false
}

export function tracePy(route, requestIds = []) {
	const { fn, ctx, cls } = route.py
	if (!fn?.node) return { scoped: null }
	const params = route.path.match(/\{(\w+)\}|:(\w+)/g)?.map(p => p.replace(/[{}:]/g, "")) ?? []
	const memo = new Map()

	// the class a method belongs to, for self.helper() and self.get_queryset()
	const classOf = node => {
		for (let n = node.parent; n; n = n.parent) if (n.type === "class_definition") return ctx.classes.get(field(n, "name").text)?.find(c => c.node.id === n.id) ?? null
		return cls ?? null
	}

	function resolve(call, file, owner) {
		const fnExpr = field(call, "function")
		if (!fnExpr) return []
		if (fnExpr.type === "attribute" && field(fnExpr, "object").text === "self" && owner) {
			const m = ctx.classMethod(owner, field(fnExpr, "attribute").text)
			return m ? [{ node: m.node, file: m.file, owner }] : []
		}
		const found = ctx.lookup(fnExpr.text, file)
		if (found?.kind === "def" && found.node?.type === "function_definition") return [{ node: found.node, file: found.file }]
		if (found?.kind === "method" && found.node) return [{ node: found.node, file: found.file, owner: found.cls }]
		// a method on an object of unknown type: every project method by that name, a few at most
		if (fnExpr.type === "attribute") {
			const name = field(fnExpr, "attribute").text
			const all = []
			for (const list of ctx.classes.values()) for (const c of list) if (c.methods?.has(name)) all.push({ node: c.methods.get(name).node, file: c.file, owner: c })
			return all.length <= 3 ? all : []
		}
		return []
	}

	function analyse(fnNode, file, taint, depth, chain, owner) {
		const key = `${file}:${lineOf(fnNode)}:${[...taint.id].join()}|${[...taint.caller].join()}`
		if (memo.has(key)) return memo.get(key)
		const result = { sinks: [], guarded: false, unknown: false, callerAction: false, creates: false }
		memo.set(key, result)
		const body = field(fnNode, "body")
		if (!body) return result
		const state = { id: new Set(taint.id), record: new Set(taint.record), caller: new Set(taint.caller) }

		const isIdentity = n => {
			if ((n.type === "attribute" || n.type === "identifier") && IDENTITY_ATTR.test(n.text)) return true
			if (n.type === "call" && IDENTITY_FN.test(callName(n))) return true
			// session["user_id"], g.get("user")
			if (n.type === "subscript" && /^session$|^g$/.test(n.namedChildren[0]?.text ?? "") && IDENTITY_KEY.test(pyString(n.namedChildren[1]) ?? "")) return true
			return false
		}
		const readsParam = n => {
			// content["id"], request.json.get("order_id"): ids the client sends in the request
			if (requestIds.length) {
				const key = n.type === "subscript" ? pyString(n.namedChildren[1]) : n.type === "call" && callName(n) === "get" ? pyString(posArgs(n)[0]) : null
				if (key && requestIds.includes(key)) return true
			}
			// self.kwargs["pk"], kwargs.get("pk"), request.view_args["id"], request.match_info["id"]
			if (n.type === "subscript" && /kwargs|view_args|match_info|path_params/.test(n.namedChildren[0]?.text ?? "")) return params.includes(pyString(n.namedChildren[1]) ?? "")
			if (n.type === "call" && callName(n) === "get" && /kwargs|view_args|match_info|path_params/.test(callObject(n)?.text ?? "")) return params.includes(pyString(posArgs(n)[0]) ?? "")
			return false
		}
		const has = (node, kind) => {
			let found = false
			walk(node, n => {
				if (found || n.type === "lambda") return false
				if (n.type === "identifier" && state[kind].has(n.text)) found = true
				if (kind === "id" && readsParam(n)) found = true
				if (kind === "caller" && isIdentity(n)) {
					found = true
					return false
				}
				// x.user, x.user_id read off a record are the record's, not the caller's
				if (kind === "caller" && n.type === "attribute" && state.caller.has(rootName(n) ?? "")) found = true
			})
			return found
		}

		walk(body, n => {
			if (n.type === "function_definition" || n.type === "class_definition") return false
			if (n.type === "assignment" || n.type === "augmented_assignment") {
				const left = field(n, "left")
				const right = field(n, "right")
				if (!left || !right) return
				const names = (left.type === "pattern_list" || left.type === "tuple_pattern" ? left.namedChildren : [left]).filter(l => l.type === "identifier").map(l => l.text)
				// get_by_id_and_org(alert_id, self.current_org) is a record, found with the caller's help
				if (has(right, "caller") && !has(right, "id")) names.forEach(x => state.caller.add(x))
				else if (has(right, "id")) {
					const isCall = right.type === "call" && !/^(int|str|uuid|UUID|ObjectId|float|strip|lower|upper|unquote|escape)$/.test(callName(right))
					names.forEach(x => state[isCall ? "record" : "id"].add(x))
				} else if (has(right, "record")) names.forEach(x => state.record.add(x))
				return
			}
			if (n.type === "comparison_operator" && /==|!=|\bis\b|\bin\b/.test(n.text)) {
				if ((has(n, "id") || has(n, "record")) && (has(n, "caller") || OWNER_WORD.test(n.text) && has(n, "caller"))) result.guarded = true
				return
			}
			if (n.type !== "call") return
			const name = callName(n)
			const top = chainTop(n)
			if (top !== n && n.parent?.type === "attribute") {
				// judged once, at the top of its chain
				return
			}
			const hasId = has(top, "id")
			const hasRecord = has(top, "record")
			const hasCaller = has(top, "caller")
			const topName = callName(top)
			if (CHECK_FN.test(topName) && (hasId || hasRecord) && hasCaller) result.guarded = true
			// require_admin_or_owner(alert.user_id): the check reads the caller itself
			if (CHECK_FN.test(topName) && (hasId || hasRecord) && /owner|access|perm|admin|member/i.test(topName)) result.guarded = true
			if (/check_object_permissions|has_object_permission/.test(topName)) result.guarded = true
			// if not ProjectMember.objects.filter(member=request.user, project_id=pk).exists(): a membership check
			if (topName === "exists" && hasId && hasCaller) result.guarded = true
			if (CALLER_ACTION.test(topName) && hasCaller && !isIdentity(top)) result.callerAction = true
			if (/^(create|insert|insert_one|add|bulk_create|save)$|^(create|insert|add)_/.test(topName)) result.creates = true
			// UpdateActionType.do(request.user, integration): the record and the caller go on together, so follow them
			// bookmark_read(request, asset.bookmark_id): the whole request carries the caller in
			const passesRequest = (field(top, "arguments")?.namedChildren ?? []).some(a => a.type === "identifier" && /^(request|req)$/.test(a.text))
			const handsOn = !hasId && hasRecord && (hasCaller || passesRequest)
			if (!hasId && !handsOn) return
			if (LOG_CALL.test(topName)) return
			const receiver = field(top, "function")?.text ?? ""
			const isDb = (DB_METHOD.test(topName) && DB_RECEIVER.test(receiver)) || DB_FN.test(topName)
			// self.repos.comments.get_one(id): a repository the class builds for the caller's group or user
			if (tenantScoped(receiver, owner, ctx)) return
			if (/self\.queryset|self\.get_queryset\(\)/.test(top.text) && querysetScoped(owner, ctx)) return
			// the owner in the same query: filter(id=pk, user=request.user), where(Item.owner_id == user.id)
			const ownerInQuery = hasCaller || (OWNER_WORD.test(top.text) && has(top, "caller"))
			// filter(id=pk, owner=user) reads the id; filter_by(username=resp["sub"]) only names a field like it
			let idValue = false
			if (hasId)
				walk(top, a => {
					if (a.type === "argument_list" && a.namedChildren.some(arg => has(arg.type === "keyword_argument" ? field(arg, "value") : arg, "id"))) idValue = true
				})
			// Bookmark.objects.get(pk=asset.bookmark_id, owner=request.user): the loaded record's parent, re-read as the caller's
			if (isDb && hasRecord && !hasId && ownerInQuery && /^(get|get_object_or_404|first_or_404|one|get_or_404)$/.test(topName)) result.guarded = true
			if (isDb) {
				result.sinks.push({ method: topName, line: lineOf(top), file, chain, scoped: ownerInQuery, withId: idValue })
				return
			}
			const targets = depth < DEPTH ? resolve(top, file, owner) : []
			if (targets.length) {
				for (const target of targets) {
					const ps = pyParams(target.node).filter(p => p.name !== "self" && p.name !== "cls")
					const next = { id: new Set(), record: new Set(), caller: new Set() }
					const args = posArgs(top)
					args.forEach((arg, i) => {
						const p = ps[i]
						if (!p?.name) return
						if (has(arg, "caller")) next.caller.add(p.name)
						else if (has(arg, "id")) next.id.add(p.name)
						else if (has(arg, "record")) next.record.add(p.name)
					})
					for (const kw of field(top, "arguments")?.namedChildren.filter(c => c.type === "keyword_argument") ?? []) {
						const nameKw = field(kw, "name").text
						const v = field(kw, "value")
						if (has(v, "caller")) next.caller.add(nameKw)
						else if (has(v, "id")) next.id.add(nameKw)
						else if (has(v, "record")) next.record.add(nameKw)
					}
					const inner = analyse(target.node, target.file, next, depth + 1, [...chain, topName], target.owner ?? owner)
					result.sinks.push(...inner.sinks)
					for (const k of ["guarded", "unknown", "callerAction", "creates"]) if (inner[k]) result[k] = true
				}
				return
			}
			// a service we cannot open that gets the caller with the record or id is trusted to check them, as a caller action is
			if (hasCaller && !isIdentity(top) && !/render|jsonify|response|serializ|dump|format|template|print|log/i.test(topName)) result.callerAction = true
			if (handsOn) return
			if (RECORD_SERVICE.test(topName) || DB_METHOD.test(topName)) {
				if (DB_METHOD.test(topName) && !DB_RECEIVER.test(receiver) && !RECORD_SERVICE.test(topName)) return
				result.sinks.push({ method: topName, line: lineOf(top), file, chain, scoped: ownerInQuery, withId: idValue })
			}
		})
		return result
	}

	// view parameters named like the path parameters carry the id; a dependency returning the user is the caller
	const ps = pyParams(fn.node)
	const ids = ps.filter(p => params.includes(p.name)).map(p => p.name)
	// def put(self, request, order_id=None, user=None): a decorator such as @jwt_auth_required hands the caller in
	const callers = ps.filter(p => !params.includes(p.name) && (/^(user|current_user|request_user|auth_user|authed_user|me|account|principal)$/.test(p.name) || (/user|account|principal|identity/i.test(p.name) && /Depends|Security|User|Account/.test(p.type + (p.default?.text ?? ""))))).map(p => p.name)
	const owner = classOf(fn.node)
	const result = analyse(fn.node, fn.file, { id: new Set(ids), record: new Set(), caller: new Set(callers) }, 0, [], owner)
	if (result.guarded) return { scoped: true }
	let open = result.sinks.filter(s => !s.scoped)
	// a write scoped to the caller, after reading a parent by another id (the published board, the project)
	const ownedWrite = !["GET", "HEAD"].includes(route.method) && result.sinks.some(s => s.scoped && s.withId)
	if ((result.callerAction || ownedWrite || (route.method === "POST" && result.creates)) && open.every(s => READ_SINK.test(s.method))) open = []
	if (open.length === 0) return { scoped: result.sinks.length ? true : null }
	if (result.unknown) return { scoped: null, unknown: true }
	const at = open[0]
	return { scoped: false, at: { ...at, file: path.relative(route.root, at.file) } }
}
