import { Application, Router, Status } from "jsr:@oak/oak";
import Meme from "./meme.ts";

const app = new Application();
const router = new Router();

router
	.get("/", async (ctx) => {
		ctx.response.type = "text/html";
		ctx.response.body = await Deno.readTextFile("static/index.html");
	})
	.post("/api/generate", async (ctx) => {
		const body = await ctx.request.body.json();
		let { name, topText, bottomText } = body;
		name = name.toString();
		topText = topText.toString();
		bottomText = bottomText.toString();

		if (!name || (!topText && !bottomText) || !Meme.isValidName(name)) {
			ctx.response.status = Status.BadRequest;
			ctx.response.body = { error: "Failed to generate meme!" };
			return;
		}
		if ((topText && topText.length > 200) || (bottomText && bottomText.length > 200)) {
			ctx.response.status = Status.BadRequest;
			ctx.response.body = { error: "Error! Text too long." };
			return;
		}

		try {
			const output = await Meme.generate(name, topText, bottomText);
			ctx.response.body = { result: `meme/${output}` };
		} catch (err) {
			console.error(err);
			ctx.response.status = Status.InternalServerError;
			ctx.response.body = { error: "Internal Server Error!" };
		}
	})
	.get("/memes/:name", async (ctx) => {
		const { name } = ctx.params;
		if (!Meme.isValidName(name)) {
			ctx.response.status = Status.NotFound;
			ctx.response.body = { error: "The requested meme was not found." };
			return;
		}

		try {
			const output = await Meme.getSource(name);
			if (output) {
				ctx.response.type = "image/png";
				ctx.response.body = output;
			}
			else {
				ctx.response.status = Status.NotFound;
				ctx.response.body = 'The requested meme was not found.';
			}
		} catch (err) {
			console.error(err);
			ctx.response.status = Status.InternalServerError;
			ctx.response.body = { error: "Internal Server Error!" };
		}
	})
	.get("/meme/:filename", async (ctx) => {
		const { filename } = ctx.params;
		if (!Meme.isValidOutput(filename)) {
			ctx.response.status = Status.NotFound;
			ctx.response.body = { error: "The requested meme was not found." };
			return;
		}

		try {
			const output = await Meme.getOutput(filename);
			if (output) {
				ctx.response.type = "image/png";
				ctx.response.body = output;
			}
			else {
				ctx.response.status = Status.NotFound;
				ctx.response.body = 'The requested meme was not found.';
			}
		} catch (err) {
			console.error(err);
			ctx.response.status = Status.InternalServerError;
			ctx.response.body = { error: "Internal Server Error!" };
		}
	});

app.use(router.routes());
app.use(router.allowedMethods());

await app.listen({ port: 8000 });
