// a frontend service: HTTP client calls, not routes
export default client => ({
	dashboard(config) {
		return client.get("/admin/dashboard/", config)
	},
	async create(values) {
		return await client.post("/admin/auth-provider/", values)
	}
})
