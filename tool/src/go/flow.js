// Follows a URL id through a Go handler and the functions it calls, up to four calls deep,
// and looks for the caller limiting it: in the query, in a comparison, or in a check call.
import path from "node:path"
import { walk, field, lineOf, calleeName, calleeObject, args, paramsOf, stringValue } from "./ast.js"

const DEPTH = 4
// reads of a path parameter: c.Param("id"), chi.URLParam(r, "id"), r.PathValue("id"), ps.ByName("id")
export const PARAM_READ = /^(Param|Params|ParamsInt|ParamInt\w*|ParamUint\w*|ParamString|PathParam\w*|PathValue|URLParam\w*|ByName|ParamsID|GetParam)$/
// GORM, database/sql, sqlx, the Mongo driver and ent calls that load or change a record
export const DB_CALL =
	/^(First|Find|Take|Last|FindOne|FindByID|FindById|FindOneAndUpdate|FindOneAndDelete|FindOneAndReplace|UpdateOne|UpdateByID|DeleteOne|ReplaceOne|Delete|Updates|Update|UpdateColumn|UpdateColumns|Query|QueryRow|QueryContext|QueryRowContext|QueryRowx|Queryx|QueryxContext|QueryRowxContext|Exec|ExecContext|Get|GetContext|Select|SelectContext|NamedExec|NamedExecContext|UpdateOneID|DeleteOneID|Only|OnlyX|Scan|Raw)$/
// service and repository calls named for a record: GetOrder(id), DeleteArticle(slug), FindByID(id)
export const RECORD_SERVICE = /^(Get|Find|Fetch|Load|Read|Update|Edit|Patch|Delete|Remove|Destroy|Archive|Lookup|Retrieve)[A-Z_]/
export const DB_WRITE = /^(Create|Save|Insert|InsertOne|InsertMany|Updates|Update|UpdateOne|UpdateMany|Upsert|Exec|ExecContext|NamedExec|NamedExecContext|CreateInBatches|Delete|DeleteOne|DeleteMany)$/
// the key under which middleware stores the caller: c.Get("userID"), ctx.Value(userKey), c.Locals("user")
const IDENTITY_KEY = /user|uid|account|member|claims|principal|identity|actor|session|owner|subject|^sub$|caller|auth|viewer|doer|^me$/i
const CONTEXT_GETTER = /^(Get|MustGet|GetString|GetInt\w*|GetUint\w*|GetInt64|Locals|Value|UserValue)$/
// helpers that return the caller: middleware.UserFromContext(ctx), GetUserID(c), request.UserID(r), jwt.ExtractClaims(c)
const IDENTITY_FN =
	/^(get|must|current|load|from|extract|parse|require|auth|session|request)?_?(current|authed|authenticated|logged_?in|signed_?in)?_?(user|account|member|claims|principal|identity|session|caller|actor|viewer|doer)_?(id|from\w*|ctx|context|info|or\w*)?$|user_?from|claims_?from|^(user|claims|session|account)(id)?$|(user|account|member|caller)_?(id)?_?from_?(token|ctx|context|request|claims|session|jwt|header)|^(get_?)?(id|uid)_?from_?(token|ctx|context|claims|jwt|session)$/i
// fields of the request context that hold the caller: ctx.Doer, c.Session, ctx.User
const IDENTITY_FIELD = /^(Doer|User|CurrentUser|Session|Claims|Principal|Viewer|AuthUser|SignedUser|Actor|ContextUser|AuthedUser|LoggedUser|UserID|UserId)$/
// handler parameters that carry the request, and so the caller
export const CARRIER_TYPE = /Context|Ctx|http\.Request|context\.Context/
const CHECK_FN = /can|authori[sz]|check|ensure|verify|assert|require|permit|allow|access|own|belong|member|guard|has[A-Z]/i
// an action the caller takes on a record they may read: follow a user, favourite an article
const CALLER_ACTION = /^(create|save|insert|add|follow|unfollow|favou?rite|unfavou?rite|like|unlike|subscribe|unsubscribe|join|leave|vote|star|unstar|bookmark|react|pin|unpin|watch|unwatch|mark|remove|delete|unset|unlink|un[A-Z])/i
const READ_SINK = /\[…\]$|^(First|Find|Take|Last|FindOne|FindByID|FindById|Get|GetContext|Select|SelectContext|Query\w*|Only|OnlyX|Scan|Raw|Count)$|^(Get|Find|Fetch|Load|Read|Lookup|Retrieve)[A-Z_]/
const LOG_CALL = /^(Error|Errorf|Warn\w*|Info\w*|Debug\w*|Trace\w*|Log\w*|Print\w*|Fatal\w*|Panic\w*|Sprint\w*|Wrap\w*|New\w*Error|Err\w*|With\w*|Set\w*Error|NotFound\w*|ServerError|HTTPError|JSONError)$/
const OWNER_SQL = /user_?id|owner|author|created_?by|tenant|org_?id|account_?id/i

const rootName = node => {
	let n = node
	while (n && (n.type === "selector_expression" || n.type === "call_expression" || n.type === "index_expression")) n = n.namedChildren[0]
	return n?.type === "identifier" ? n.text : null
}

// the outermost call of a method chain: db.Where(...).First(&o) seen from First or from Where
function chainTop(call) {
	let node = call
	while (node.parent?.type === "selector_expression" && node.parent.parent?.type === "call_expression") node = node.parent.parent
	return node
}

export function traceGo(route) {
	const { fn, ctx } = route.go
	if (!fn?.node) return { scoped: null }
	const params = route.path.match(/[:{]\w+/g)?.map(p => p.slice(1)) ?? []
	const memo = new Map()

	function analyse(fnNode, file, taint, depth, chain) {
		const key = `${file}:${lineOf(fnNode)}:${[...taint.id].join()}|${[...taint.caller].join()}|${[...taint.carriers].join()}`
		if (memo.has(key)) return memo.get(key)
		const result = { sinks: [], guarded: false, unknown: false, callerAction: false }
		memo.set(key, result)
		const body = field(fnNode, "body")
		if (!body) return result
		const state = { id: new Set(taint.id), record: new Set(taint.record), caller: new Set(taint.caller), carriers: new Set(taint.carriers), vars: new Set() }
		const local = { types: new Map(), funcs: new Map() }
		for (const p of paramsOf(fnNode)) if (p.name) local.types.set(p.name, p.type.replace(/^[*&]/, "").split(".").at(-1))
		const receiver = field(fnNode, "receiver")
		if (receiver) for (const p of paramsOf({ childForFieldName: k => (k === "parameters" ? receiver : null) })) if (p.name) local.types.set(p.name, p.type.replace(/^[*&]/, "").split(".").at(-1))

		const has = (node, kind) => {
			let found = false
			walk(node, n => {
				if (found) return false
				if (n.type === "func_literal") return false
				if (n.type === "identifier" && state[kind].has(n.text)) found = true
				if (kind === "id" && readsParam(n)) found = true
				if (kind === "caller" && isIdentity(n)) found = true
			})
			return found
		}
		const readsParam = n => {
			if (n.type === "call_expression" && PARAM_READ.test(calleeName(n))) {
				const name = args(n).map(a => stringValue(a, ctx.consts)).find(v => v !== null)?.replace(/^:/, "")
				return name !== undefined && (params.length === 0 || params.includes(name))
			}
			// mux.Vars(r)["id"], vars["id"]
			if (n.type === "index_expression") {
				const operand = n.namedChildren[0]
				const isVars = (operand.type === "call_expression" && calleeName(operand) === "Vars") || (operand.type === "identifier" && state.vars.has(operand.text))
				const key = stringValue(n.namedChildren[1], ctx.consts)
				return isVars && key !== null && (params.length === 0 || params.includes(key))
			}
			return false
		}
		const isIdentity = n => {
			if (n.type === "call_expression") {
				const name = calleeName(n)
				if (CONTEXT_GETTER.test(name)) {
					const key = args(n)[0]
					const keyText = key ? stringValue(key, ctx.consts) ?? key.text : ""
					return IDENTITY_KEY.test(keyText)
				}
				return IDENTITY_FN.test(name)
			}
			if (n.type === "selector_expression" && IDENTITY_FIELD.test(field(n, "field").text)) {
				const root = rootName(n)
				return root !== null && (state.carriers.has(root) || state.caller.has(root))
			}
			return false
		}

		walk(body, n => {
			if (n.type === "func_literal" && n !== fnNode) return
			if (n.type === "short_var_declaration" || n.type === "assignment_statement" || n.type === "var_spec") {
				const left = n.type === "var_spec" ? n.namedChildren.filter(c => c.type === "identifier") : field(n, "left").namedChildren
				const right = (n.type === "var_spec" ? field(n, "value") : field(n, "right"))?.namedChildren ?? []
				const names = left.filter(l => l.type === "identifier" && l.text !== "_" && l.text !== "err").map(l => l.text)
				const whole = right.length === 1 && left.length > 1
				right.forEach((r, i) => {
					const targets = whole ? names : left[i]?.type === "identifier" && !["_", "err"].includes(left[i].text) ? [left[i].text] : []
					if (r.type === "call_expression" && calleeName(r) === "Vars") targets.forEach(t => state.vars.add(t))
					if (has(r, "caller")) targets.forEach(t => state.caller.add(t))
					else if (has(r, "id")) {
						// a call that takes the id returns the record: o, err := svc.GetOrder(id)
						const kind = r.type === "call_expression" && !readsParam(r) && !PARAM_READ.test(calleeName(r)) && !/^(Atoi|Parse\w*|ParseInt|ParseUint|FromString|MustParse|ObjectIDFromHex|Trim\w*|ToLower|ToUpper|String|Unescape|PathUnescape|QueryUnescape|Sprint\w*)$/.test(calleeName(r)) ? "record" : "id"
						targets.forEach(t => state[kind].add(t))
					} else if (has(r, "record")) targets.forEach(t => state.record.add(t))
					else if (r.type === "call_expression" && readsParamInside(r, local, file)) targets.forEach(t => state.id.add(t))
				})
				return
			}
			if (n.type === "binary_expression" && /^(==|!=)$/.test(field(n, "operator")?.text ?? "")) {
				if ((has(n, "id") || has(n, "record")) && has(n, "caller")) result.guarded = true
				return
			}
			// s.orders[id]: an in-memory store read by the id
			if (n.type === "index_expression" && n.namedChildren[0]?.type === "selector_expression" && has(n.namedChildren[1], "id")) {
				result.sinks.push({ method: `${n.namedChildren[0].text}[…]`, line: lineOf(n), file, chain, scoped: has(n, "caller") })
				return
			}
			if (n.type !== "call_expression") return
			const name = calleeName(n)
			const top = chainTop(n)
			const objectRoot = rootName(calleeObject(n))
			if (CONTEXT_GETTER.test(name) && objectRoot && state.carriers.has(objectRoot)) return
			const hasId = has(top, "id")
			const hasRecord = has(top, "record")
			const hasCaller = has(top, "caller")
			if (CHECK_FN.test(name) && (hasId || hasRecord) && hasCaller) result.guarded = true
			if (CALLER_ACTION.test(name) && hasCaller && !isIdentity(n)) result.callerAction = true
			if (/^(Create|Insert|InsertOne|Save|SaveOne|CreateInBatches)$|^(Create|Insert|Add)[A-Z]/.test(name)) result.creates = true
			if (!hasId) return
			const sqlScoped = args(top).some(a => OWNER_SQL.test(stringValue(a) ?? "")) && hasCaller
			if (DB_CALL.test(name) && n === top && !(depth < DEPTH && ctx.resolveTyped(n, local, file).length)) {
				result.sinks.push({ method: name, line: lineOf(n), file, chain, scoped: hasCaller || sqlScoped })
				// db.First(&order, id): order now holds the record
				for (const a of args(n)) if (a.type === "unary_expression") state.record.add(a.namedChildren[0].text)
				return
			}
			if (n !== top && DB_CALL.test(calleeName(top))) return
			// logging and error wrapping only mention the id
			if (LOG_CALL.test(name) || /^(log|logger|logging|slog|zap|logrus|errors|fmt)$/i.test(objectRoot ?? "")) return
			// a function of our own: follow the id into it
			const targets = depth < DEPTH ? ctx.resolveCall(n, local, file) : []
			if (targets.length) {
				const a = args(n)
				for (const target of targets) {
					const ps = paramsOf(target.node)
					const next = { id: new Set(), record: new Set(), caller: new Set(), carriers: new Set() }
					a.forEach((arg, i) => {
						const p = ps[i]
						if (!p?.name) return
						if (has(arg, "caller")) next.caller.add(p.name)
						else if (has(arg, "id")) next.id.add(p.name)
						else if (has(arg, "record")) next.record.add(p.name)
						if (CARRIER_TYPE.test(p.type) && arg.type === "identifier" && (state.carriers.has(arg.text) || /^(ctx|c|r|req|context)$/.test(arg.text))) next.carriers.add(p.name)
					})
					// the receiver may hold the caller too: h.withUser(user).GetOrder(id)
					const inner = analyse(target.node, target.file, next, depth + 1, [...chain, name])
					result.sinks.push(...inner.sinks)
					if (inner.guarded) result.guarded = true
					if (inner.unknown) result.unknown = true
					if (inner.callerAction) result.callerAction = true
					if (inner.creates) result.creates = true
				}
				return
			}
			if (RECORD_SERVICE.test(name) || DB_CALL.test(name)) {
				// an interface method we cannot open: it may read the caller from the context it is given
				const passesCarrier = args(n).some(a => a.type === "identifier" && state.carriers.has(a.text))
				if (passesCarrier && !hasCaller) result.unknown = true
				else result.sinks.push({ method: name, line: lineOf(n), file, chain, scoped: hasCaller || sqlScoped })
			}
		})
		return result
	}

	// id, err := parseID(c): a helper that reads the path parameter
	function readsParamInside(call, local, file) {
		for (const target of ctx.resolveCall(call, local, file)) {
			let found = false
			walk(field(target.node, "body"), n => {
				if (n.type === "call_expression" && PARAM_READ.test(calleeName(n))) found = true
			})
			if (found) return true
		}
		return false
	}

	const carriers = paramsOf(fn.node).filter(p => p.name && CARRIER_TYPE.test(p.type)).map(p => p.name)
	// func(w, r, user *model.User): the caller handed in by a wrapper
	const callerParams = paramsOf(fn.node).filter(p => p.name && /User|Session|Claims|Principal|Identity|Account/.test(p.type) && !CARRIER_TYPE.test(p.type)).map(p => p.name)
	const result = analyse(fn.node, fn.file, { id: new Set(), record: new Set(), caller: new Set(callerParams), carriers: new Set(carriers) }, 0, [])
	if (result.guarded) return { scoped: true }
	let open = result.sinks.filter(s => !s.scoped)
	// reading the record is fine when what the handler then does belongs to the caller
	// a POST that creates something under a record it only reads: a comment on an article
	if ((result.callerAction || (route.method === "POST" && result.creates)) && open.every(s => READ_SINK.test(s.method))) open = []
	if (open.length === 0) return { scoped: result.sinks.length ? true : null, unknown: result.unknown }
	if (result.unknown) return { scoped: null, unknown: true }
	const at = open[0]
	return { scoped: false, at: { ...at, file: path.relative(route.root, at.file) } }
}
