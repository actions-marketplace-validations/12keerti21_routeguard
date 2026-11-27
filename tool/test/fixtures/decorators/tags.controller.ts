import { Delete, Get, GlobalScope, Param, Post, RestController, RootLevelController } from "@n8n/decorators"
import { scimRoute } from "./scim-route"

@RestController("/tags")
export class TagsController {
	constructor(private readonly tags: TagRepository) {}

	@Get("/")
	@GlobalScope("tag:list")
	async list() {
		return await this.tags.find()
	}

	@Post("/login", { skipAuth: true, ipRateLimit: true })
	async login(req: Request) {
		return req.body
	}

	@Delete("/:tagId")
	async remove(req: AuthenticatedRequest, _res: Response, @Param("tagId") tagId: string) {
		await this.tags.delete(tagId)
	}

	@Delete("/own/:tagId")
	async removeOwn(req: AuthenticatedRequest, _res: Response, @Param("tagId") tagId: string) {
		await this.tags.delete({ id: tagId, ownerId: req.user.id })
	}
}

@RootLevelController("/scim/v2")
export class ScimController {
	@Delete("/Users/:id", scimRoute)
	async deleteUser(req: Request) {
		await this.users.delete(req.params.id)
	}
}
