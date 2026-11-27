import { Controller, Delete, Get, Param, UseGuards } from "@nestjs/common"

@Controller("notes")
@UseGuards(JwtAuthGuard)
export class NotesController {
	@Get(":id")
	findOne(@Param("id") id: string, @CurrentUser() user: User) {
		return this.notes.findOne({ where: { id, ownerId: user.id } })
	}

	@Delete(":id")
	remove(@Param("id") id: string) {
		return this.notes.delete(id)
	}
}

@Controller("status")
export class StatusController {
	@Public()
	@Get("health")
	health() {
		return "ok"
	}

	@Get("me")
	me(@CurrentUser() user: User) {
		return user
	}
}
