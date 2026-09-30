#!/usr/bin/env node
// Clean product screenshots for the README: log in, visit each view, shoot it.
// No cursor overlay, no captions — just the UI on demo data.
//
//   CHROMIUM_BIN=$(command -v chromium) node shots.mjs \
//     --url https://192.168.121.198:8444 --password PW --out ../docs/screenshots

import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';

const a = { url: 'https://127.0.0.1:8445', password: '', out: path.resolve('../docs/screenshots'), lang: 'en' };
for (let i = 2; i < process.argv.length; i++) {
	const v = process.argv[i + 1];
	if (process.argv[i] === '--url') { a.url = v; i++; }
	else if (process.argv[i] === '--password') { a.password = v; i++; }
	else if (process.argv[i] === '--out') { a.out = path.resolve(v); i++; }
	else if (process.argv[i] === '--lang') { a.lang = v; i++; }
}
const CHROMIUM = process.env.CHROMIUM_BIN || '/etc/profiles/per-user/acid/bin/chromium';

// Each view, and how long to let it settle (the dashboard animates its flow).
const views = [
	['dashboard', 1800],
	['activity', 1200],
	['shares', 900],
	['routes', 900],
	['settings', 900],
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
	fs.mkdirSync(a.out, { recursive: true });
	const browser = await chromium.launch({ executablePath: CHROMIUM, args: ['--no-sandbox'] });
	const context = await browser.newContext({ viewport: { width: 1600, height: 900 }, ignoreHTTPSErrors: true, locale: a.lang === 'de' ? 'de-DE' : 'en-US' });
	await context.addInitScript((lang) => { try { localStorage.setItem('scan-lang', lang); } catch (e) { } }, a.lang);
	const page = await context.newPage();

	await page.goto(a.url, { waitUntil: 'domcontentloaded' });
	await page.locator('#pw').waitFor({ state: 'visible', timeout: 30000 });
	await page.locator('#pw').fill(a.password);
	await page.locator('#unlock').click();
	await page.locator('#shell:not(.hide)').waitFor({ timeout: 30000 });

	for (const [view, settle] of views) {
		await page.locator(`#nav a[data-view="${view}"]`).click();
		await page.locator(`#v-${view}.on`).waitFor({ timeout: 15000 });
		await sleep(settle);
		// Park the mouse out of the frame so no row sits in a hover state.
		await page.mouse.move(1590, 890);
		await sleep(150);
		const file = path.join(a.out, `${view}.png`);
		await page.screenshot({ path: file });
		console.log(`shot ${path.relative(process.cwd(), file)}`);
	}

	await context.close();
	await browser.close();
}

main().catch((e) => { console.error(e.message); process.exit(1); });
