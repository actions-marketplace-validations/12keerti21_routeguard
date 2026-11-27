const express = require("express")
const { corsMiddleware } = require("./cors")
const Item = require("./item")
const Pages = require("./pages")

const app = express()
const router = express.Router()
const inDevelopment = process.env.NODE_ENV === "development"

function createControlPlaneAuthMiddleware(config, scope) {
	return (req, res, next) => next()
}
function auth(req, res, next) {
	next()
}

if (inDevelopment) app.use(corsMiddleware)

app.post("/internal/credentials/resolve", createControlPlaneAuthMiddleware(config, "credentials:read"), resolve)
app.get("/system/ping", (req, res) => res.send("pong"))
app.get("/metrics", (req, res) => res.send(""))
app.head("/items/:id", async (req, res) => res.json(await Item.findById(req.params.id)))
router.delete("/uploads/:uuid", auth, async (req, res) => {
	await Item.findOneAndDelete({ uuid: req.params.uuid })
	res.sendStatus(204)
})
app.use("/api", router)

// a route registered in a return statement is still a route
function mountPages(webRouter) {
	return webRouter.get("/university/*", Pages.getPage)
}

function mcpCors(res) {
	res.header("Access-Control-Allow-Origin", "*")
	res.header("Access-Control-Allow-Credentials", "true")
}

function resolve(req, res) {
	res.json({})
}

module.exports = { app, mountPages, mcpCors }
