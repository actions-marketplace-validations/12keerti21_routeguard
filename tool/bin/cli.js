#!/usr/bin/env node
import { readFileSync } from "node:fs"
import path from "node:path"
import { mapRoutes } from "../src/mapper.js"
import { toSarif } from "../src/sarif.js"
import { bola } from "../src/rules/bola.js"
import { bfla } from "../src/rules/bfla.js"
import { massAssignment } from "../src/rules/massAssignment.js"
import { ssrf } from "../src/rules/ssrf.js"
import { rateLimit } from "../src/rules/rateLimit.js"
import { dataExposure } from "../src/rules/dataExposure.js"
import { misconfig } from "../src/rules/misconfig.js"
import { inventory } from "../src/rules/inventory.js"
import { businessFlow } from "../src/rules/businessFlow.js"
import { consumption } from "../src/rules/consumption.js"
import { verify } from "../src/verify.js"
import { mapGoRoutes } from "../src/go/mapper.js"
import { GO_RULES } from "../src/go/rules.js"
import { goAppRules } from "../src/go/app.js"
import { mapPyRoutes } from "../src/py/mapper.js"
import { PY_RULES } from "../src/py/rules.js"
import { pyAppRules } from "../src/py/app.js"

const RULES = [bola, bfla, massAssignment, dataExposure, ssrf, rateLimit, businessFlow]
// Go handlers get their own code checks; the path-only checks are shared
const RULES_GO = [...GO_RULES, bfla, rateLimit, businessFlow]
const RULES_PY = [...PY_RULES, bfla, rateLimit, businessFlow]
const PY_FIX = {
	RATE_LIMIT: "Add a limiter keyed on the caller and the account, e.g. Flask-Limiter, slowapi or DRF throttle classes, on this route.",
	BUSINESS_FLOW: "Limit per account and per device (Flask-Limiter, slowapi, DRF throttling), add a captcha or a queue for the flow, and alert on bursts.",
	BFLA: "Add a role check (an admin-only decorator, dependency or permission class), or remove the route from production.",
	NON_PROD_ROUTE: "Remove it from production builds, or register it only when DEBUG or a development setting is on."
}
// the shared checks suggest Express middleware; Go apps get Go advice
const GO_FIX = {
	RATE_LIMIT: "Add a limiter keyed on the caller and the account, e.g. golang.org/x/time/rate or a middleware such as ulule/limiter, on this route.",
	BUSINESS_FLOW: "Limit per account and per device, add a captcha or a queue for the flow, and alert on bursts.",
	BFLA: "Add a role-checking middleware to the route, or remove it from production builds.",
	NON_PROD_ROUTE: "Remove it from production builds, or register it only when a debug setting is on."
}

const SEVERITIES = ["LOW", "MEDIUM", "HIGH"]

// process.exit() drops what is still buffered for a pipe, which cut large --json output short
const finish = code => process.stdout.write("", () => process.exit(code))

// routeguard verify <dir> --base-url … --config …: replay the routes against a running app
const verifying = process.argv[2] === "verify"
const args = process.argv.slice(verifying ? 3 : 2)
const VALUE_FLAGS = new Set(["--fail-on", "--base-url", "--config", "--canary-host"])
const option = name => {
	const i = args.indexOf(name)
	return i === -1 ? null : args[i + 1]
}
const json = args.includes("--json")
const sarif = args.includes("--sarif")
// --fail-on HIGH: exit 2 only for findings at or above that severity (default LOW: any finding)
const failOn = (option("--fail-on") ?? "LOW").toUpperCase()
const target = args.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.has(args[i - 1]))

if (!target || !SEVERITIES.includes(failOn) || (verifying && (!option("--base-url") || !option("--config")))) {
	console.error("Usage: routeguard <express-project-dir> [--json | --sarif] [--fail-on LOW|MEDIUM|HIGH]")
	console.error("       routeguard verify <express-project-dir> --base-url <url> --config <file.json> [--allow-writes] [--probe-rate-limits] [--probe-ssrf [--canary-host <host>]] [--json]")
	process.exit(1)
}

// Go advice, and a lower severity for operator routes that exist only when a setting turns them on
function goAdvice(route, f) {
	const out = GO_FIX[f.rule] ? { ...f, fix: GO_FIX[f.rule] } : f
	if (route.conditional && ["BFLA", "NON_PROD_ROUTE"].includes(f.rule) && f.severity !== "LOW")
		return { ...out, severity: "LOW", message: `${out.message} It is registered only when ${route.conditional} holds.` }
	return out
}
function pyAdvice(route, f) {
	const out = PY_FIX[f.rule] ? { ...f, fix: PY_FIX[f.rule] } : f
	if (route.py.conditional && ["BFLA", "NON_PROD_ROUTE"].includes(f.rule) && f.severity !== "LOW")
		return { ...out, severity: "LOW", message: `${out.message} It is registered only when ${route.py.conditional} holds.` }
	return out
}
const jsRoutes = mapRoutes(path.resolve(target))
const goRoutes = await mapGoRoutes(path.resolve(target))
const pyRoutes = await mapPyRoutes(path.resolve(target))
const routes = [...jsRoutes, ...goRoutes, ...pyRoutes]
// NestJS services and modules import @nestjs too; its controllers are read as decorator routes
const other = Object.entries(jsRoutes.frameworks).filter(([f]) => f !== "express" && f !== "decorators" && !(f === "nestjs" && jsRoutes.frameworks.decorators)).sort((a, b) => b[1] - a[1])
const readable = (jsRoutes.frameworks.express ?? 0) + (jsRoutes.frameworks.decorators ?? 0)
if (goRoutes.length === 0 && pyRoutes.length === 0 && other.length && other[0][1] > readable)
	console.error(`warning: this looks like a ${other[0][0]} app (${other[0][1]} files, ${jsRoutes.frameworks.express ?? 0} using Express). routeguard reads Express, Go and Python routes only, so these results are unreliable.`)
const suppressed = (route, finding) => route.ignored === "all" || route.ignored?.has(finding.rule)
// a router mounted twice reports the same code twice
const seen = new Set()
const root = path.resolve(target)
const findings = [
	...jsRoutes.flatMap(r => RULES.map(rule => rule(r)).filter(f => f && !suppressed(r, f))),
	...goRoutes.flatMap(r => RULES_GO.map(rule => rule(r)).filter(f => f && !suppressed(r, f)).map(f => goAdvice(r, f))),
	...pyRoutes.flatMap(r => RULES_PY.map(rule => rule(r)).filter(f => f && !suppressed(r, f)).map(f => pyAdvice(r, f))),
	// checks that look at the app as a whole, not one route
	...inventory(routes, root).map(f => (!jsRoutes.length && (goRoutes.length ? GO_FIX : pyRoutes.length ? PY_FIX : {})[f.rule] ? { ...f, fix: (goRoutes.length ? GO_FIX : PY_FIX)[f.rule] } : f)),
	...(jsRoutes.length || (!goRoutes.length && !pyRoutes.length) ? [...misconfig(root), ...consumption(root)] : []),
	...(goRoutes.length ? goAppRules(goRoutes) : []),
	...(pyRoutes.length ? pyAppRules(pyRoutes) : [])
].filter(f => !seen.has(`${f.rule} ${f.route} ${f.where}`) && seen.add(`${f.rule} ${f.route} ${f.where}`))

function printReport() {
	const mark = ok => (ok ? "✅" : "❌")
	const rows = routes.map(r => [r.method, r.path, r.middleware.join(", ") || "-", mark(r.auth), mark(r.role), `${r.file}:${r.line}`])
	const header = ["METHOD", "PATH", "MIDDLEWARE", "AUTH", "ROLE", "WHERE"]
	const widths = header.map((h, i) => Math.max(h.length, ...rows.map(r => r[i].length)))
	const line = cells => cells.map((c, i) => c.padEnd(widths[i])).join("  ")

	console.log(line(header))
	console.log(widths.map(w => "-".repeat(w)).join("  "))
	rows.forEach(r => console.log(line(r)))

	const noAuth = routes.filter(r => !r.auth).length
	console.log(`\n${routes.length} routes · ${noAuth} without an auth check · ${routes.filter(r => !r.role).length} without a role check`)

	console.log(`\nFINDINGS (${findings.length})\n`)
	for (const f of findings) {
		console.log(`[${f.severity}] ${f.rule}  ${f.route}  (${f.where})`)
		console.log(`  ${f.owasp}`)
		console.log(`  ${f.message}`)
		console.log(`  Fix: ${f.fix}\n`)
	}
}

function printVerification(results) {
	if (results.discovered?.length) {
		console.log("Ids found from the app's own lists:")
		for (const d of results.discovered)
			console.log(`  :${d.param} = ${d.value}  (${d.from}${d.ownerOnly ? ", the owner's only" : ", also visible to the other user"})`)
		console.log("")
	}
	const order = { CONFIRMED: 0, INCONCLUSIVE: 1, PUBLIC: 2, PROTECTED: 3, SKIPPED: 4 }
	const sorted = [...results].filter(r => !r.probe).sort((a, b) => order[a.verdict] - order[b.verdict])
	for (const r of sorted) {
		const codes = r.status ? `owner ${r.status.owner ?? "-"} · other ${r.status.other} · anonymous ${r.status.anonymous}` : ""
		const agreement =
			r.verdict === "CONFIRMED" && r.staticRule ? "static finding confirmed"
			: r.verdict === "CONFIRMED" ? "missed by static analysis"
			: r.verdict === "PROTECTED" && r.staticRule ? `static ${r.staticRule} not reproduced`
			: ""
		console.log(`[${r.verdict}] ${r.route}${codes ? `  (${codes})` : ""}`)
		console.log(`  ${r.reason}${agreement ? ` · ${agreement}` : ""}`)
	}
	const probes = [...results].filter(r => r.probe).sort((a, b) => order[a.verdict] - order[b.verdict])
	if (probes.length) console.log("\nProbes:")
	for (const r of probes) console.log(`[${r.verdict}] ${r.probe}  ${r.route}\n  ${r.reason}`)
	const count = verdict => sorted.filter(r => r.verdict === verdict).length
	console.log(`\n${sorted.length} routes replayed, ${probes.length} probes · ${count("CONFIRMED")} confirmed · ${count("PUBLIC")} public · ${count("PROTECTED")} protected · ${count("INCONCLUSIVE")} inconclusive · ${count("SKIPPED")} skipped`)
}

const exitCode = findings.some(f => SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(failOn)) ? 2 : 0

if (verifying) {
	const config = JSON.parse(readFileSync(path.resolve(option("--config")), "utf8"))
	const results = await verify({ routes, findings, baseUrl: option("--base-url"), config,
		allowWrites: args.includes("--allow-writes"),
		probeOptions: {
			rateLimits: args.includes("--probe-rate-limits"),
			ssrf: args.includes("--probe-ssrf"),
			canaryHost: option("--canary-host") ?? config.canaryHost
		}
	})
	if (json) console.log(JSON.stringify(results, null, 2))
	else printVerification(results)
	finish(results.some(r => r.verdict === "CONFIRMED") ? 2 : 0)
} else if (json) {
	console.log(JSON.stringify({ routes, findings }, null, 2))
	finish(exitCode)
} else if (sarif) {
	const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))
	console.log(JSON.stringify(toSarif(findings, version), null, 2))
	finish(exitCode)
} else {
	printReport()
	finish(exitCode)
}
