// App-wide checks for Go code: CORS, JWT, error leaks, security headers and third-party APIs
import path from "node:path"
import { walk, field, lineOf, calleeName, calleeObject, args, stringValue } from "./ast.js"
import { DB_WRITE } from "./flow.js"

const CORS_CALL_ANY = /^(cors\.Default|cors\.AllowAll|middleware\.CORS)$/
const ORIGIN_KEYS = /^(AllowOrigins|AllowedOrigins)$/
const ORIGIN_FN = /^(AllowOriginFunc|AllowOriginRequestFunc|AllowOriginVaryRequestFunc|AllowOriginsFunc)$/
const SECRET_NAME = /secret|key|jwt|sign/i
const RESPOND = /^(JSON|String|Error|Write|WriteString|SendString|Send|AbortWithStatusJSON|AbortWithError|JSONP|IndentedJSON|NewHTTPError|Fprintf|Fprint|Fprintln)$/
const SECURE_HEADERS = /unrolled\/secure|gin-contrib\/secure|middleware\.Secure\w*\(|helmet|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy|X-Frame-Options/
const CLIENT = /^(Get|Post|Head|PostForm|Do|NewRequest|NewRequestWithContext)$/
const KEY_IN_URL = /[?&](app_?id|api_?key|key|token|access_token|secret|client_secret)=([A-Za-z0-9_\-]{16,})/i
const LOCAL = /^http:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\]|[\w-]+:\d+\/?$|[\w-]+\/|[\w-]+$|%s|example\.)/i
const VALIDATE = /validat|verify|check|sanitiz|schema|assert/i

const finding = (rule, owasp, severity, where, message, fix, route = "(app-wide)") => ({ rule, owasp, severity, route, where, message, fix })
const isTrue = node => node?.type === "true"
const returnsTrueOnly = fn => {
	const statements = field(fn, "body")?.namedChildren.flatMap(c => (c.type === "statement_list" ? c.namedChildren : [c])) ?? []
	return statements.length === 1 && statements[0].type === "return_statement" && /^return\s+true$/.test(statements[0].text.trim())
}

export function goAppRules(routes) {
	const ctx = routes.goContext
	if (!ctx) return []
	const { root } = ctx
	const findings = []
	let secureHeaders = false
	let firstRouterFile = null
	const at = (file, node) => `${path.relative(root, file)}:${lineOf(node)}`

	for (const [file, info] of ctx.fileInfo) {
		const rootNode = info.tree.rootNode
		const text = rootNode.text
		if (SECURE_HEADERS.test(text)) secureHeaders = true
		if (!firstRouterFile && info.frameworks.some(f => f !== "net/http")) firstRouterFile = file
		let rawErrors = 0
		let firstRawError = null

		walk(rootNode, n => {
			// cors.Config{AllowOrigins: []string{"*"}, AllowCredentials: true}
			if (n.type === "literal_value") {
				const keys = new Map()
				for (const el of n.namedChildren) {
					if (el.type !== "keyed_element") continue
					const [k, v] = el.namedChildren
					keys.set(k.text, v?.namedChildren?.[0] ?? v)
				}
				const anyOrigin = isTrue(keys.get("AllowAllOrigins")) || [...keys].some(([k, v]) => (ORIGIN_KEYS.test(k) && /"\*"/.test(v?.text ?? "")) || (ORIGIN_FN.test(k) && v?.type === "func_literal" && returnsTrueOnly(v)))
				if (anyOrigin) {
					const credentials = isTrue(keys.get("AllowCredentials"))
					findings.push(
						credentials
							? finding("CORS", "API8:2023 Security Misconfiguration", "HIGH", at(file, n), "CORS accepts any origin and allows credentials, so any website can make signed-in requests and read the answers.", "List the allowed origins, or drop AllowCredentials.")
							: finding("CORS", "API8:2023 Security Misconfiguration", "LOW", at(file, n), "CORS answers every origin. Fine for a public, token-only API; not with cookies or for internal APIs.", "List the origins that may call the API.")
					)
				}
				// echojwt.Config{SigningKey: []byte("secret")}
				for (const [k, v] of keys) {
					if (/^(SigningKey|SigningKeys|Secret|SecretKey|JWTSecret|SigningSecret|TokenSecret)$/.test(k) && hardcoded(v) && [...info.imports.values()].some(i => /jwt/i.test(i)))
						findings.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), `${k} is written in the code, so anyone with the source can mint tokens.`, "Load the key from configuration or a secret store."))
					if (k === "EnableStackTrace" && isTrue(v)) findings.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), "Stack traces are sent to the client, showing file paths and code structure.", "Turn EnableStackTrace off outside development."))
				}
			}
			if (n.type === "assignment_statement" && /\.Debug$/.test(field(n, "left").text) && isTrue(field(n, "right").namedChildren[0]))
				findings.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), "Debug mode is switched on in the code, so errors go back to the client with internals.", "Read debug mode from configuration and keep it off in production."))
			if (n.type !== "call_expression") return
			const name = calleeName(n)
			const full = field(n, "function").text
			const a = args(n)

			if (CORS_CALL_ANY.test(full) && a.length === 0)
				findings.push(finding("CORS", "API8:2023 Security Misconfiguration", "LOW", at(file, n), `${full}() answers every origin. Fine for a public, token-only API; not with cookies or for internal APIs.`, "List the origins that may call the API."))
			// w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			if (/^(Set|Add|Header)$/.test(name) && /Access-Control-Allow-Origin/.test(a[0]?.text ?? "")) {
				const value = a[1]?.text ?? ""
				// r.Header.Get("Origin") or a local origin read from it; conf.CORS.AllowOrigin is configuration
				const reflected = /Header\.Get\(\s*"Origin"|^origin$/i.test(value)
				if (reflected || value === '"*"') {
					// credentials sent only after an allow-list check do not count
					let credentials = false
					walk(enclosingFunction(n), c => {
						if (c.type === "call_expression" && /Access-Control-Allow-Credentials"\s*,\s*"true"/.test(c.text) && !allowListed(c)) credentials = true
					})
					findings.push(finding("CORS", "API8:2023 Security Misconfiguration", credentials && reflected ? "HIGH" : "LOW", at(file, n), `Access-Control-Allow-Origin is ${reflected ? "copied from the request" : "*"}${credentials ? (reflected ? ", with Allow-Credentials true, so any website can act as the signed-in user" : ", with Allow-Credentials true, which browsers refuse; drop one of the two") : ""}.`, "Compare the Origin against an allow-list before echoing it."))
				}
			}
			// JWT
			if (/UnsafeAllowNoneSignatureType|SigningMethodNone/.test(n.text) && /^(Parse|ParseWithClaims|SignedString|New|NewWithClaims)$/.test(name))
				findings.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), "The none algorithm is allowed, so an unsigned token passes.", "Never use SigningMethodNone or UnsafeAllowNoneSignatureType."))
			if (name === "ParseUnverified") {
				// reading the kid to pick a key, then verifying; an id_token straight from the provider's token endpoint; or a helper named for what it does
				const fn = enclosingFunction(n)
				const fnName = fn?.childForFieldName("name")?.text ?? ""
				const verifies = /\b(Parse|ParseWithClaims|Verify\w*|Validate\w*Signature)\(|\bkid\b|oauth2\.Token|Extra\("id_token"\)/.test(fn?.text ?? "") || /Unverified/i.test(fnName)
				findings.push(finding("JWT", "API2:2023 Broken Authentication", verifies ? "LOW" : "MEDIUM", at(file, n), `jwt.ParseUnverified() reads a token without checking its signature; any claim read from it can be forged.${verifies ? " Here it looks like a step before verification." : ""}`, "Use jwt.Parse with a key, and read unverified claims only to pick that key."))
			}
			if (name === "WithoutClaimsValidation")
				findings.push(finding("JWT", "API2:2023 Broken Authentication", "MEDIUM", at(file, n), "Token claims are not validated, so an expired token still works.", "Remove jwt.WithoutClaimsValidation()."))
			if (name === "SignedString" && hardcoded(a[0]))
				findings.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), "Tokens are signed with a key written in the code, so anyone with the source can mint them.", "Load the key from configuration or a secret store."))
			if (/^(Parse|ParseWithClaims)$/.test(name) && /jwt/.test(calleeObject(n)?.text ?? "")) {
				const keyFunc = a.find(x => x.type === "func_literal")
				if (keyFunc) {
					let literal = false
					walk(keyFunc, r => {
						if (r.type === "return_statement" && hardcoded(r.namedChildren[0]?.namedChildren?.[0] ?? r.namedChildren[0])) literal = true
					})
					if (literal) findings.push(finding("JWT", "API2:2023 Broken Authentication", "HIGH", at(file, n), "The key that verifies tokens is written in the code, so anyone with the source can mint tokens.", "Load the key from configuration or a secret store."))
					if (!/\.Method\b|SigningMethod|Alg\(\)/.test(keyFunc.text) && !a.some(x => /WithValidMethods/.test(x.text)))
						findings.push(finding("JWT", "API2:2023 Broken Authentication", "LOW", at(file, n), "The key function never checks token.Method, so the token chooses its own algorithm.", 'Check the method in the key function, or pass jwt.WithValidMethods([]string{"HS256"}).'))
				}
			}
			// errors
			if (name === "Stack" && calleeObject(n)?.text === "debug" && sentToClient(n))
				findings.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "MEDIUM", at(file, n), "A stack trace goes back to the client, showing file paths and code structure.", "Log the stack trace and send a generic message."))
			if (RESPOND.test(name) && a.some(x => /\berr\w*\.Error\(\)|\berr\b$/.test(x.text) || /"error"\s*:\s*err\w*(\.Error\(\))?\s*[,}]/.test(x.text))) {
				rawErrors++
				firstRawError ??= n
			}
		})
		if (rawErrors >= 3)
			findings.push(finding("ERROR_LEAK", "API8:2023 Security Misconfiguration", "LOW", at(file, firstRawError), `${rawErrors} responses in this file send err.Error() to the client, which can carry query details, driver messages and paths.`, "Log the error and send a generic message with a status code."))
		findings.push(...consumption(file, rootNode, at))
	}
	if (!secureHeaders && firstRouterFile)
		findings.push(finding("SECURITY_HEADERS", "API8:2023 Security Misconfiguration", "LOW", `${path.relative(root, firstRouterFile)}:1`, "No security-headers middleware: no HSTS, nosniff or frame protection.", "Add one, e.g. github.com/unrolled/secure, gin-contrib/secure or echo's middleware.Secure()."))
	return findings
}

// debug.Stack() inside c.String(500, ...), w.Write(...), c.JSON(500, gin.H{...})
function sentToClient(node) {
	let p = node.parent
	for (let i = 0; p && i < 6; i++, p = p.parent) {
		if (p.type === "call_expression" && RESPOND.test(calleeName(p))) {
			const object = calleeObject(p)?.text ?? ""
			// fmt.Fprint(w, ...) writes to the response; fmt.Sprintf and loggers do not
			if (object === "fmt") return /^Fprint/.test(calleeName(p)) && /^(w|rw|writer|res|resp|response)$/.test(args(p)[0]?.text ?? "")
			if (!/log|Log|errors|zap|logrus/.test(object)) return true
		}
		if (/statement|declaration/.test(p.type)) return false
	}
	return false
}

// []byte("secret"), "secret", or a constant holding one
function hardcoded(node) {
	if (!node) return false
	if (node.type === "interpreted_string_literal" || node.type === "raw_string_literal") return node.text.length > 2
	if (node.type === "call_expression" || node.type === "type_conversion_expression") {
		const inner = args(node)[0] ?? node.namedChildren.at(-1)
		return /^\[\]byte/.test(node.text) && (inner?.type === "interpreted_string_literal" || inner?.type === "raw_string_literal")
	}
	return false
}

function allowListed(node) {
	for (let n = node.parent; n && !/^(function_declaration|method_declaration|func_literal)$/.test(n.type); n = n.parent)
		if (n.type === "if_statement" && /allow|trust|valid|whitelist|permitted|origin/i.test(field(n, "condition")?.text ?? "")) return true
	return false
}

function enclosingFunction(node) {
	let n = node
	while (n && !/^(function_declaration|method_declaration|func_literal)$/.test(n.type)) n = n.parent
	return n
}

// API10: third-party answers trusted as they are
function consumption(file, rootNode, at) {
	const out = []
	walk(rootNode, n => {
		if (n.type === "interpreted_string_literal" || n.type === "raw_string_literal") {
			const key = n.text.match(KEY_IN_URL)
			if (key && /^"https?:/.test(n.text))
				out.push(finding("SECRET_IN_URL", "API10:2023 Unsafe Consumption of APIs", "HIGH", at(file, n), `The "${key[1]}" key for a third-party API is written into the URL in the code.`, "Move the key to configuration and send it in a header."))
			return
		}
		if (n.type !== "function_declaration" && n.type !== "method_declaration") return
		const calls = []
		walk(n, c => {
			if (c.type === "call_expression") calls.push(c)
		})
		const client = calls.find(c => CLIENT.test(calleeName(c)) && /^http$|client|Client/.test(calleeObject(c)?.text ?? ""))
		if (!client) return false
		const urlArg = args(client)[calleeName(client) === "NewRequest" ? 1 : calleeName(client) === "NewRequestWithContext" ? 2 : 0]
		const url = stringValue(urlArg) ?? (urlArg?.type === "call_expression" ? stringValue(args(urlArg)[0]) : null)
		if (url && /^http:\/\//.test(url) && !LOCAL.test(url))
			out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "LOW", at(file, client), `A third-party API is called over plain http (${url.slice(0, 60)}), so its answers can be changed in transit.`, "Use https."))
		// json.NewDecoder(resp.Body).Decode(&x) then db.Create(&x), with nothing validating x
		const decoded = new Set()
		for (const c of calls) {
			if (/^(Decode|Unmarshal)$/.test(calleeName(c)) && /resp|res\b|response|Body|body/.test(c.text)) {
				const target = args(c).at(-1)
				if (target?.type === "unary_expression") decoded.add(target.namedChildren[0].text)
			}
		}
		if (decoded.size === 0) return false
		const uses = name => c => args(c).some(a => a.text === name || a.text === `&${name}` || a.text.startsWith(`${name}.`))
		const validated = [...decoded].some(d => calls.some(c => VALIDATE.test(calleeName(c)) && uses(d)(c)))
		if (validated) return false
		for (const d of decoded) {
			const stored = calls.find(c => DB_WRITE.test(calleeName(c)) && uses(d)(c) && !/client|http/i.test(calleeObject(c)?.text ?? ""))
			if (stored) {
				out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "MEDIUM", at(file, stored), `${calleeName(stored)}() stores data from another API without validating it, so a compromised or buggy provider writes into our database.`, "Validate the answer against what you expect (fields, types, sizes) before storing it."))
				break
			}
			const redirect = calls.find(c => calleeName(c) === "Redirect" && uses(d)(c))
			if (redirect) {
				out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "MEDIUM", at(file, redirect), "The client is redirected to a URL another API returned, which that API can point anywhere.", "Check the URL against an allow-list before redirecting."))
				break
			}
			const exec = calls.find(c => /^(Command|CommandContext)$/.test(calleeName(c)) && uses(d)(c))
			if (exec) {
				out.push(finding("UNSAFE_CONSUMPTION", "API10:2023 Unsafe Consumption of APIs", "HIGH", at(file, exec), "A command is built from data another API returned, so whoever controls that API runs code here.", "Never build commands from third-party data; map it to a fixed set of values."))
				break
			}
		}
		return false
	})
	return out
}
