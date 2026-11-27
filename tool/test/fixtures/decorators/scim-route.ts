const scimAuth = () => (req, res, next) => next()

export const scimRoute = {
	skipAuth: true,
	middlewares: [scimAuth()]
}
