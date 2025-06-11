import crypto from 'node:crypto';
import { encodeBase64 } from "jsr:@std/encoding/base64";

export async function generate(name: string, topText: string, bottomText: string): Promise<string> {
	const imageBytes = await getSource(name);
	if (!imageBytes) return false;

	const randomId = crypto.hash('sha256', crypto.getRandomValues(new Uint8Array(32)), 'hex');
	const svgPath = `./output/${randomId}.svg`;
	const pngPath = `./output/${randomId}.png`;
	const outputFile = `${randomId}.png`;

	const base64Image = `data:image/png;base64,${encodeBase64(imageBytes)}`;
	const svgContent = (`
	<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
	<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
		<image href="${base64Image}" width="500" height="500"/>
		<text x="50%" y="50" font-size="40" font-family="Arial" fill="white" stroke="black" font-weight="bold" text-anchor="middle">${topText}</text>
		<text x="50%" y="450" font-size="40" font-family="Arial" fill="white" stroke="black" font-weight="bold" text-anchor="middle">${bottomText}</text>
	</svg>
	`).trim();

	await Deno.writeTextFile(svgPath, svgContent);
	await new Deno.Command("rsvg-convert", { args: [svgPath, "--format=png", "-o", pngPath] }).output();
	await Deno.remove(svgPath);
	return outputFile;
}

export function isValidName(name: string): boolean {
	return /^[a-zA-Z0-9_-]+$/.test(name);
}
export function isValidFile(filename: string): boolean {
	return /^[a-zA-Z0-9_-]+\.png$/.test(filename);
}

export async function isValidOutput(filename: string): Promise<boolean> {
	if (!isValidFile(filename)) return false;
	try {
		await Deno.readFile(`output/${filename}`);
		return true;
	} catch (err) {
		return false;
	}
}

export async function isValidSource(name: string): Promise<boolean> {
	if (!isValidName(name)) return false;
	try {
		await Deno.readFile(`static/memes/${name}.png`);
		return true;
	} catch (err) {
		return false;
	}
}

export async function getSource(name: string): Promise<boolean> {
	if (!isValidName(name)) return false;
	try {
		return await Deno.readFile(`static/memes/${name}.png`);
	} catch (err) {
		return false;
	}
}

export async function getOutput(filename: string): Promise<boolean> {
	if (!isValidFile(filename)) return false;
	try {
		return await Deno.readFile(`output/${filename}`);;
	} catch (err) {
		return false;
	}
}

export default { generate, isValidName, isValidFile, isValidOutput, isValidSource, getSource, getOutput };
