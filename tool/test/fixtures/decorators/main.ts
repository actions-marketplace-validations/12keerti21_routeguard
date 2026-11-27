import { NestFactory } from "@nestjs/core"
import { APP_GUARD } from "@nestjs/core"

export const providers = [{ provide: APP_GUARD, useClass: JwtAuthGuard }]

async function bootstrap() {
	const app = await NestFactory.create(AppModule)
	app.setGlobalPrefix("api")
	await app.listen(3000)
}
bootstrap()
