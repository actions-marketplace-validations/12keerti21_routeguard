// App-wide checks for Python code: CORS, debug mode, secrets and JWT, error leaks, security headers
// and third-party APIs
import path from "node:path"
import { walk, field, lineOf, pyString, callName, callObject, posArgs, kwarg, items } from "./ast.js"

const KEY_IN_URL = /[?&](app_?id|api_?key|key|token|access_token|secret|client_secret)=([A-Za-z0-9_\-]{16,})/i
const LOCAL = /^http:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\]|[\w-]+:\d+\/?|[\w-]+\/|[\w-]+$|example\.)/i
const VALIDATE = /validat|verify|check|sanitiz|schema|parse_obj|model_validate|clean/i
const SECRET_SETTING = /^(SECRET_KEY|JWT_SECRET_KEY|JWT_SECRET|SECRET|TOKEN_SECRET|SIGNING_KEY|APP_SECRET)$/
const SECURE_HEADERS = /flask_talisman|Talisman\(|secure\.|SecurityMiddleware|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy|secure_headers|SecureHeaders/

const finding = (rule, owasp, severity, where, message, fix) => ({ rule, owasp, severity, route: "(app-wide)", where, message, fix })
const isTrue = node => node?.type === "true"

export function pyAppRules(routes) {
	const ctx = routes.pyContext
	if (!ctx || routes.length === 0) return []
	const { root } = ctx
	const out = []
	let secureHeaders = false
	let firstApp = null
	const at = (file, node) => `${path.relative(root, file)}:${lineOf(node)}`
	const djangoAllOrigins = []
	const hardSecrets = []
	const secretReplaced = new Set()
	let djangoCredentials = false
	const ofApp = new Set(routes.map(r => path.join(root, r.file)))
	// settings for tests, local development and project templates are not what runs in production
	const devFile = file => /(^|[\/_.-])(dev|development|local|test|tests|testing|ci|e2e|example|sample|template|project_template)([\/_.-]|$)/i.test(path.relative(root, file))
	const devClass = node => {
		for (let n = node.parent; n; n = n.parent) if (n.type === "class_definition") return /Test|Dev|Local|Debug|Example/.test(field(n, "name").text)
		return false
	}
	const push = out.push.bind(out)
	out.push = (...fs) => push(...fs.map(f => (f.rule === "JWT" || f.rule === "ERROR_LEAK") && f.severity !== "LOW" && f.devSettings ? { ...f, severity: "LOW", message: `${f.message} (Development or test settings.)` } : f).map(({ devSettings, ...f }) => f))

	for (const [file, fi] of ctx.info) {
		const rootNode = fi.tree.rootNode
		const text = rootNode.text
		if (SECURE_HEADERS.test(text)) secureHeaders = true
		if (!firstApp && /\b(Flask|FastAPI)\(/.test(text) && fi.fw.size) firstApp = file
		let rawErrors = 0
		let firstRaw = null
		walk(rootNode, n => {
			// settings: SECRET_KEY = "…", DEBUG = True, CORS_ALLOW_ALL_ORIGINS = True
			if (n.type === "assignment") {
				const left = field(n, "left")
				const right = field(n, "right")
				const name = left?.type === "identifier" ? left.text : left?.type === "subscript" ? pyString(left.namedChildren[1]) : left?.type === "attribute" ? field(left, "attribute").text : null
				if (!name || !right) return
				const dev = devFile(file) || devClass(n)
				if ((SECRET_SETTING.test(name) || name === "secret_key") && right.type === "string" && (pyString(right) ?? "").length >= 4 && !/^(change|replace|your|xxx|<)/i.test(pyString(right) ?? ""))
					hardSecrets.push({ name, dir: path.dirname(file), finding: { ...finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), `${name} is written in the code, so anyone with the source can sign sessions and tokens.`, "Read the key from the environment or a secret store, with no default."), devSettings: dev } })
				// prod.py: SECRET_KEY = read_secret() replaces the one in base.py
				if (SECRET_SETTING.test(name) && right.type !== "string" && !dev) secretReplaced.add(`${path.dirname(file)}#${name}`)
				// os.environ.get("SECRET_KEY", "dev-secret")
				// getattr(obj, "SECRET_KEY", default): the default is the third argument there, the second elsewhere
				const fallback = right.type === "call" ? (callName(right) === "getattr" ? posArgs(right)[2] : posArgs(right)[1]) ?? kwarg(right, "default") : null
				if (SECRET_SETTING.test(name) && right.type === "call" && /environ|getenv|config|env\(|getattr/.test(right.text) && fallback?.type === "string" && (pyString(fallback) ?? "").length >= 4)
					out.push(dev ? { ...finding("JWT", "API2:2023 Broken Authentication", "MEDIUM", at(file, n), `${name} falls back to a key written in the code when the environment does not set one.`, "Fail at start-up when the key is missing instead of using a default."), devSettings: true } : finding("JWT", "API2:2023 Broken Authentication", "MEDIUM", at(file, n), `${name} falls back to a key written in the code when the environment does not set one.`, "Fail at start-up when the key is missing instead of using a default."))
				if (name === "DEBUG" && isTrue(right) && /settings|config/i.test(file))
					out.push(dev ? { ...finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), "DEBUG = True in the settings: errors show stack traces, settings and SQL to anyone.", "Read DEBUG from the environment and keep it off in production."), devSettings: true } : finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), "DEBUG = True in the settings: errors show stack traces, settings and SQL to anyone.", "Read DEBUG from the environment and keep it off in production."))
				if (/^(CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)$/.test(name) && isTrue(right)) djangoAllOrigins.push({ file, n })
				if (name === "CORS_ALLOW_CREDENTIALS" && isTrue(right)) djangoCredentials = true
				// response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")
				// origin not in settings.ALLOWED_ORIGINS: return response — an allow-list in front of the echo
				const allowListed = /\borigin\b[^\n]*\b(not\s+)?in\b|in_allowlist|allowed/i.test(enclosingFunction(n)?.text ?? "")
				if (name === "Access-Control-Allow-Origin" && /Origin|origin/.test(right.text) && right.type !== "string" && !allowListed) {
					const credentials = /Access-Control-Allow-Credentials['"]\]\s*=\s*['"]true/i.test(enclosingFunction(n)?.text ?? "")
					out.push(finding("CORS", "API8:2023 Security Misconfiguration", credentials ? "HIGH" : "LOW", at(file, n), `Access-Control-Allow-Origin is copied from the request${credentials ? ", with Allow-Credentials true, so any website can act as the signed-in user" : ""}.`, "Compare the Origin against an allow-list before echoing it."))
				}
				return
			}
			if (n.type !== "call") return
			const name = callName(n)
			// flask_cors.CORS(app, supports_credentials=True), @cross_origin(...)
			if (name === "CORS" || name === "cross_origin") {
				const origins = kwarg(n, "origins") ?? kwarg(n, "resources")
				const anyOrigin = !origins || /["']\*["']|r?["']\.\*["']/.test(origins.text)
				const credentials = isTrue(kwarg(n, "supports_credentials"))
				if (anyOrigin)
					out.push(finding("CORS", "API8:2023 Security Misconfiguration", credentials ? "HIGH" : "LOW", at(file, n), credentials ? "CORS accepts any origin and allows credentials, so any website can make signed-in requests and read the answers." : `${name}() answers every origin. Fine for a public, token-only API; not with cookies or for internal APIs.`, "List the origins that may call the API."))
			}
			// app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
			if (name === "add_middleware" && /CORSMiddleware/.test(posArgs(n)[0]?.text ?? "")) {
				const anyOrigin = /["']\*["']/.test(kwarg(n, "allow_origins")?.text ?? "") || /\.\*/.test(kwarg(n, "allow_origin_regex")?.text ?? "")
				const credentials = isTrue(kwarg(n, "allow_credentials"))
				if (anyOrigin)
					out.push(finding("CORS", "API8:2023 Security Misconfiguration", credentials ? "HIGH" : "LOW", at(file, n), credentials ? "CORSMiddleware accepts any origin with credentials, so any website can make signed-in requests and read the answers." : "CORSMiddleware answers every origin. Fine for a public, token-only API.", "List the origins that may call the API."))
			}
			// app.run(debug=True): the Werkzeug debugger runs code for whoever reaches it
			if (name === "run" && isTrue(kwarg(n, "debug")) && /app|application/i.test(callObject(n)?.text ?? ""))
				out.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "HIGH", at(file, n), "app.run(debug=True): the interactive debugger lets anyone who triggers an error run code on the server.", "Never run with debug=True outside a developer's machine; read it from the environment."))
			if (/^(FastAPI|Starlette)$/.test(name) && isTrue(kwarg(n, "debug")))
				out.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), `${name}(debug=True) sends tracebacks to the client.`, "Turn debug off outside development."))
			// JWT
			if (name === "decode" && /jwt/.test(callObject(n)?.text ?? "")) {
				const options = kwarg(n, "options")?.text ?? ""
				// is_jwt_formatted(): a result nobody reads decides nothing
				if (n.parent?.type === "expression_statement") return
				if (/verify_signature['"]\s*:\s*False/.test(options) || kwarg(n, "verify")?.type === "false")
					out.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), "jwt.decode() does not check the signature, so anyone can forge a token.", "Verify the signature: pass the key and algorithms=[...]."))
				else if (/["']none["']/i.test(kwarg(n, "algorithms")?.text ?? ""))
					out.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), "jwt.decode() accepts alg none, so an unsigned token passes.", "List only the algorithms you sign with."))
				else if (!kwarg(n, "algorithms") && posArgs(n).length < 3)
					out.push(finding("JWT", "API2:2023 Broken Authentication", "LOW", at(file, n), "jwt.decode() without algorithms: older PyJWT versions let the token choose its algorithm.", 'Pass algorithms=["HS256"] (or your algorithm).'))
				if (/verify_exp['"]\s*:\s*False/.test(options))
					out.push(finding("JWT", "API2:2023 Broken Authentication", "MEDIUM", at(file, n), "Token expiry is not checked, so a stolen token works forever.", 'Remove "verify_exp": False.'))
			}
			if (name === "encode" && /jwt/.test(callObject(n)?.text ?? "") && posArgs(n)[1]?.type === "string")
				out.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), "Tokens are signed with a key written in the code, so anyone with the source can mint them.", "Load the key from configuration or a secret store."))
			// errors and tracebacks sent to the client
			if (/^(jsonify|JsonResponse|Response|HTTPException|make_response|JSONResponse)$/.test(name) || (name === "abort" && posArgs(n).length > 1)) {
				if (/traceback\.format_exc\(\)|format_exception/.test(n.text))
					out.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), "A traceback goes back to the client, showing file paths and code structure.", "Log the traceback and send a generic message."))
				else if (/\b(str|repr)\(\s*(e|err|error|ex|exc|exception)\s*\)|\{(e|err|error|ex|exc)\}/.test(n.text)) {
					rawErrors++
					firstRaw ??= n
				}
			}
		})
		if (rawErrors >= 3 && ofApp.has(file))
			out.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "LOW", at(file, firstRaw), `${rawErrors} responses in this file send str(exception) to the client, which can carry query details, driver messages and paths.`, "Log the exception and send a generic message with a status code."))
		out.push(...consumption(file, rootNode, at))
	}
	for (const { name, dir, finding: f } of hardSecrets)
		out.push(secretReplaced.has(`${dir}#${name}`) ? { ...f, severity: "LOW", message: `${f.message} Another settings file here sets it from elsewhere, so this one is likely a development default.`, devSettings: false } : f)
	for (const { file, n } of djangoAllOrigins)
		out.push(finding("CORS", "API8:2023 Security Misconfiguration", djangoCredentials ? "HIGH" : "LOW", at(file, n), djangoCredentials ? "django-cors-headers allows every origin with credentials, so any website can make signed-in requests and read the answers." : "django-cors-headers allows every origin. Fine for a public, token-only API.", "List the allowed origins in CORS_ALLOWED_ORIGINS."))
	if (!secureHeaders && firstApp)
		out.push(finding("SECURITY_HEADERS", "API8:2023 Security Misconfiguration", "LOW", `${path.relative(root, firstApp)}:1`, "No security-headers middleware: no HSTS, nosniff or frame protection.", "Add one, e.g. flask-talisman, or set the headers in an after-request hook or middleware."))
	return out
}

function enclosingFunction(node) {
	for (let n = node.parent; n; n = n.parent) if (n.type === "function_definition") return n
	return null
}

// API10: third-party answers trusted as they are
function consumption(file, rootNode, at) {
	const out = []
	walk(rootNode, n => {
		if (n.type === "string") {
			const s = pyString(n) ?? n.text
			const key = s.match(KEY_IN_URL)
			if (key && /^https?:/.test(s)) out.push(finding("SECRET_IN_URL", "API10:2023 Unsafe Consumption of APIs", "HIGH", at(file, n), `The "${key[1]}" key for a third-party API is written into the URL in the code.`, "Move the key to configuration and send it in a header."))
			return false
		}
		if (n.type !== "function_definition") return
		const calls = []
		walk(n, c => {
			if (c.type === "call") calls.push(c)
		})
		const client = calls.find(c => /^(get|post|put|patch|request|urlopen)$/.test(callName(c)) && /^(requests|httpx|urllib\.request|session|client|http)$/i.test(callObject(c)?.text ?? (callName(c) === "urlopen" ? "urllib.request" : "")))
		if (!client) return
		const url = pyString(posArgs(client)[0])
		if (url && /^http:\/\//.test(url) && !LOCAL.test(url))
			out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "LOW", at(file, client), `A third-party API is called over plain http (${url.slice(0, 60)}), so its answers can be changed in transit.`, "Use https."))
		// data = resp.json(); Model(**data) / db.add(...) with nothing validating it
		const text = n.text
		const decoded = [...text.matchAll(/(\w+)\s*=\s*\w+\.json\(\)/g)].map(m => m[1])
		if (!decoded.length || VALIDATE.test(text)) return false
		for (const d of decoded) {
			const stored = calls.find(c => (/^[A-Z]\w+$/.test(callName(c)) && c.text.includes(`**${d}`)) || (/^(create|insert_one|insert_many|update_one|bulk_create|add)$/.test(callName(c)) && c.text.includes(d)))
			if (stored) {
				out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "MEDIUM", at(file, stored), `${callName(stored)}() stores data from another API without validating it, so a compromised or buggy provider writes into our database.`, "Validate the answer against what you expect (a schema with explicit fields) before storing it."))
				break
			}
			const exec = calls.find(c => /^(eval|exec|system|popen|run|call|check_output|Popen)$/.test(callName(c)) && c.text.includes(d))
			if (exec) {
				out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "HIGH", at(file, exec), "Code or a command is built from data another API returned, so whoever controls that API runs code here.", "Never run third-party data; map it to a fixed set of values."))
				break
			}
			const redirect = calls.find(c => /^(redirect|RedirectResponse|HttpResponseRedirect)$/.test(callName(c)) && c.text.includes(d))
			if (redirect) {
				out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "MEDIUM", at(file, redirect), "The client is redirected to a URL another API returned, which that API can point anywhere.", "Check the URL against an allow-list before redirecting."))
				break
			}
		}
		return false
	})
	return out
}
