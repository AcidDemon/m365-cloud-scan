#!/usr/bin/env node
// Records one continuous take of the first-run wizard, and shoots one clean
// screenshot per step for the written setup guide (docs/EINRICHTUNG.md).
//
// The box must be FRESH: no share, no tenant, no route, so the wizard opens by
// itself after sign-in. Wipe it first (see demo/reset.sh, or the state wipe in
// the setup guide).
//
// The Microsoft device-code sign-in is done by a human while the recording
// runs. Nothing here touches the Microsoft login page and no Microsoft
// credential goes near this script.
//
//   node wizard.mjs --url https://192.168.121.198:8444 --password PW
//   node wizard.mjs --url ... --skip-onboarding      # dry run, no tenant (steps 3-4 skipped)
//
// Screenshots land in out/img/step-N.png; the video in out/wizard.webm plus
// out/captions.jsonl for render.sh.

import { chromium } from 'playwright-core';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

/* ============================================================ arguments */

function parseArgs(argv) {
	const a = { url: 'https://127.0.0.1:8445', out: path.join(HERE, 'out'), password: '', shareRoot: '', skipOnboarding: false, codeTimeout: 10 * 60 * 1000, pdfSize: 8 * 1024 * 1024 };
	const takesValue = new Set(['--url', '--password', '--out', '--share-root', '--pdf-size']);
	for (let i = 0; i < argv.length; i++) {
		const v = argv[i + 1];
		if (takesValue.has(argv[i]) && v === undefined) die(`${argv[i]} needs a value`);
		switch (argv[i]) {
			case '--url': a.url = v; i++; break;
			case '--password': a.password = v; i++; break;
			case '--out': a.out = path.resolve(v); i++; break;
			case '--share-root': a.shareRoot = path.resolve(v); i++; break;
			case '--pdf-size': a.pdfSize = sizeArg(v); i++; break;
			case '--skip-onboarding': a.skipOnboarding = true; break;
			case '-h': case '--help':
				console.log('wizard.mjs [--url U] [--password P] [--out DIR] [--share-root DIR] [--pdf-size 8M] [--skip-onboarding]');
				process.exit(0);
			default: die(`unknown argument ${argv[i]}`);
		}
	}
	return a;
}
const ARGS = parseArgs(process.argv.slice(2));

function die(msg) { console.error('\n' + msg + '\n'); process.exit(1); }

function adminPassword() {
	if (ARGS.password) return ARGS.password;
	if (process.env.SCAN_ADMIN_PASSWORD) return process.env.SCAN_ADMIN_PASSWORD;
	const log = path.join(REPO, '.dev-run.log');
	if (fs.existsSync(log)) {
		const m = fs.readFileSync(log, 'utf8').match(/^\s*password\s+(\S+)\s*$/m);
		if (m) { console.log(`password read from ${log}`); return m[1]; }
	}
	die('no box password. Pass --password or set SCAN_ADMIN_PASSWORD.');
}

/* ============================================================ preflight */

const CHROMIUM = process.env.CHROMIUM_BIN || '/etc/profiles/per-user/acid/bin/chromium';
const FFMPEG_LINK = path.join(os.homedir(), '.cache/ms-playwright/ffmpeg-1011/ffmpeg-linux');

function preflight() {
	if (!fs.existsSync(CHROMIUM)) die(`no chromium at ${CHROMIUM}. Set CHROMIUM_BIN=$(command -v chromium).`);
	if (!fs.existsSync(FFMPEG_LINK)) die(`Playwright wants ffmpeg at\n  ${FFMPEG_LINK}\nLink the system one:\n  mkdir -p ${path.dirname(FFMPEG_LINK)}\n  ln -s "$(command -v ffmpeg)" ${FFMPEG_LINK}`);
	fs.mkdirSync(path.join(ARGS.out, 'img'), { recursive: true });
	archivePreviousTake(ARGS.out);
}

/* ============================================================ the overlay
   A drawn cursor + highlight ring, injected so it survives the login reload.
   The screenshot helper clears the ring first, so the doc images are clean. */

function overlay() {
	try { localStorage.setItem('scan-lang', 'de'); } catch (e) { }
	const ID = 'demo-layer';
	function mount() {
		if (document.getElementById(ID) || !document.body) return document.getElementById(ID);
		const l = document.createElement('div');
		l.id = ID;
		l.style.cssText = 'position:fixed;inset:0;z-index:2147483000;pointer-events:none';
		l.innerHTML =
			'<svg id="demo-cursor" width="26" height="30" viewBox="0 0 26 30" style="position:fixed;left:0;top:0;filter:drop-shadow(0 3px 6px rgba(0,0,0,.55));will-change:transform">' +
			'<path d="M3 2 L3 22 L8.4 17.2 L11.8 25.2 L15.4 23.6 L12.1 15.9 L19.4 15.4 Z" fill="#fff" stroke="#14171E" stroke-width="1.6" stroke-linejoin="round"/></svg>' +
			'<div id="demo-ring" style="position:fixed;left:0;top:0;width:0;height:0;border:2px solid var(--amber,#EBA335);border-radius:10px;opacity:0;' +
			'box-shadow:0 0 0 4px rgba(235,163,53,.12);transition:opacity .18s ease,left .28s ease,top .28s ease,width .28s ease,height .28s ease"></div>';
		document.documentElement.appendChild(l);
		return l;
	}
	let pos = { x: 60, y: 60 };
	window.__demo = {
		cursorTo(x, y, ms) {
			const layer = mount(); if (!layer) return Promise.resolve();
			const c = document.getElementById('demo-cursor');
			const from = pos; pos = { x, y };
			return c.animate([{ transform: `translate(${from.x}px,${from.y}px)` }, { transform: `translate(${x}px,${y}px)` }],
				{ duration: ms, easing: 'cubic-bezier(.22,.61,.36,1)', fill: 'forwards' }).finished.then(() => undefined);
		},
		ripple() {
			const layer = mount(); if (!layer) return Promise.resolve();
			const r = document.createElement('div');
			r.style.cssText = `position:fixed;left:${pos.x}px;top:${pos.y}px;width:16px;height:16px;margin:-8px 0 0 -8px;border-radius:50%;border:2px solid var(--amber,#EBA335);pointer-events:none`;
			layer.appendChild(r);
			return r.animate([{ transform: 'scale(.35)', opacity: .95 }, { transform: 'scale(3.2)', opacity: 0 }], { duration: 430, easing: 'ease-out' }).finished.then(() => r.remove());
		},
		ring(b) {
			const layer = mount(); if (!layer) return;
			const r = document.getElementById('demo-ring');
			if (!b) { r.style.opacity = '0'; return; }
			r.style.left = (b.x - 7) + 'px'; r.style.top = (b.y - 7) + 'px';
			r.style.width = (b.width + 14) + 'px'; r.style.height = (b.height + 14) + 'px';
			r.style.opacity = '1';
		},
	};
	if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
	else mount();
}

/* ============================================================ driving the page */

let page = null;
let currentStep = 'startup';
const beat = (ms) => new Promise((r) => setTimeout(r, ms));

async function ui(sel, timeout = 15000) {
	const l = page.locator(sel).first();
	try { await l.waitFor({ state: 'visible', timeout }); }
	catch { throw new Error(`selector never became visible: ${sel}`); }
	return l;
}
async function point(sel, ms = 520) {
	const l = await ui(sel);
	await l.scrollIntoViewIfNeeded().catch(() => { });
	const box = await l.boundingBox();
	if (!box) throw new Error(`selector has no box on screen: ${sel}`);
	await page.evaluate(async ([b, d]) => { window.__demo.ring(b); await window.__demo.cursorTo(b.x + b.width / 2, b.y + b.height / 2, d); }, [box, ms]);
	return l;
}
async function click(sel) {
	const l = await point(sel);
	await page.evaluate(() => window.__demo.ripple());
	await l.click();
	return l;
}
async function typeInto(sel, text, { clear = false } = {}) {
	const l = await click(sel);
	if (clear) { await l.press('Control+a'); await l.press('Delete'); }
	await l.pressSequentially(text, { delay: 55 });
	return l;
}
async function pick(sel, label) {
	const l = await point(sel);
	await page.evaluate(() => window.__demo.ripple());
	try { await l.selectOption({ label }); }
	catch {
		const have = await l.locator('option').allTextContents();
		throw new Error(`${sel} has no option "${label}". It offers: ${have.join(', ') || '(none)'}`);
	}
	return l;
}
async function clearRing() { await page.evaluate(() => window.__demo.ring(null)); }

// A clean doc screenshot: ring off, cursor parked, then shoot the viewport.
async function shot(name) {
	if (!name) return;
	await clearRing();
	// A lingering toast dates the shot and differs step to step; hide it so the
	// doc images are consistent. It reappears on the next action.
	await page.evaluate(() => { const t = document.getElementById('toast'); if (t) t.classList.remove('on'); });
	await beat(300);
	const file = path.join(ARGS.out, 'img', `${name}.png`);
	await page.screenshot({ path: file });
	console.log(`           shot img/${name}.png`);
}

// Click a button inside the wizard body by its visible label.
async function wizButton(text) {
	const l = page.locator('#wz_body button, #wz_conn button').filter({ hasText: text }).first();
	await l.waitFor({ state: 'visible', timeout: 15000 });
	const box = await l.boundingBox();
	await page.evaluate(async ([b]) => { window.__demo.ring(b); await window.__demo.cursorTo(b.x + b.width / 2, b.y + b.height / 2, 460); await window.__demo.ripple(); }, [box]);
	await l.click();
	return l;
}
async function nextStep() { await click('#wz_next'); }

/* ============================================================ steps + captions */

const captions = [];
let t0 = 0;

async function runStep(s) {
	currentStep = s.id;
	const start = Date.now() - t0;
	console.log(`[${String(start / 1000).padStart(7)}s] ${s.id}`);
	try { await s.run(); }
	catch (e) {
		if (e instanceof SkipStep) throw e;
		throw new Error(`step "${s.id}" failed: ${e.message}`);
	}
	if (s.shot) await shot(s.shot);
	const end = Date.now() - t0;
	const line = JSON.stringify({ start, end, text: s.caption });
	captions.push(line);
	fs.appendFileSync(path.join(ARGS.out, 'captions.jsonl'), line + '\n');
}

const SHARE = 'scans-vertrieb';
const SERVER = 'm365scan';
const run = { smbPassword: '', pdfName: '', code: '', verifyUrl: '' };

const steps = [
	{
		id: '0-anmelden', caption: 'Anmeldung an der Box. Auf einer frisch installierten Box öffnet sich die Einrichtung von selbst.',
		async run() {
			await beat(800);
			await typeInto('#pw', adminPassword());
			await click('#unlock');
			// A fresh box auto-opens the wizard; give the boot() sequence its moment.
			await ui('#v-setup.on', 30000);
			await ui('#wz_body', 15000);
			await beat(1200);
		},
	},
	{
		id: '1-freigabe',
		caption: 'Schritt 1: die Scan-Freigabe. Name der Freigabe und der SMB-Name der Box. Die Box legt Freigabe, Dienstkonto und Passwort an.',
		async run() {
			await typeInto('#wz1_name', SHARE);
			if (await page.locator('#wz1_srv').count()) await typeInto('#wz1_srv', SERVER, { clear: true });
			await beat(500);
			await shot('step-1');   // the filled form, before it is submitted and collapses
			await wizButton('Hinzufügen');
			// The one-time SMB password appears in a code box; keep it for step 5.
			await ui('#wz_body code', 20000);
			run.smbPassword = (await page.locator('#wz_body code').first().textContent()).trim();
			await point('#wz_body code');
			await beat(2200);
		},
	},
	{
		id: '2-netzwerk', shot: 'step-2',
		caption: 'Schritt 2: Netzwerkzugriff. Alles nicht Freigegebene wird abgewiesen. Netz eintragen, Rolle wählen, hinzufügen. Kachel schaltet die Rolle je Netz.',
		async run() {
			await nextStep();
			await ui('#wz2_net', 15000);
			await typeInto('#wz2_net', '192.168.50.0/24');
			await pick('#wz2_use', 'Kopierer').catch(() => { });
			await beat(400);
			await wizButton('Hinzufügen').catch(() => wizButton('Add'));
			await beat(1600);
		},
	},
	{
		id: '3-tenant-start', shot: 'step-3-code',
		caption: 'Schritt 3: Microsoft 365 verbinden. Die Box zeigt einen Gerätecode und die Adresse der Anmeldeseite.',
		async run() {
			await nextStep();
			await wizButton('Anmeldung starten').catch(() => wizButton('Start sign-in'));
			await ui('#wz_conn code', 30000);
			run.code = (await page.locator('#wz_conn code').first().textContent()).trim();
			run.verifyUrl = (await page.locator('#wz_conn a').first().textContent()).trim();
			await point('#wz_conn');
			await beat(2500);
		},
	},
	{
		id: '4-microsoft-anmeldung', skipOnDryRun: true,
		caption: 'Ein Administrator meldet sich bei Microsoft an und gibt den Code ein. Die Box wartet auf den Abschluss.',
		async run() {
			printCodeBox(run.code, run.verifyUrl);
			await waitForSignIn(ARGS.codeTimeout);
			await ui('#wz_conn input[type=checkbox]', 30000);
			await clearRing();
		},
	},
	{
		id: '5-websites', skipOnDryRun: true,
		caption: 'Die freigegebenen SharePoint-Websites auswählen. Die Box erhält Schreibrechte nur auf diesen Websites.',
		async run() {
			const boxes = page.locator('#wz_conn input[type=checkbox]');
			const n = await boxes.count();
			if (n < 1) throw new Error('the sign-in returned no sites to grant');
			for (let i = 0; i < Math.min(n, 2); i++) {
				const cb = boxes.nth(i);
				if (await cb.isChecked()) continue;
				const box = await cb.boundingBox();
				await page.evaluate(async ([b]) => { window.__demo.ring(b); await window.__demo.cursorTo(b.x + b.width / 2, b.y + b.height / 2, 420); await window.__demo.ripple(); }, [box]);
				await cb.check();
			}
			await beat(600);
			await shot('step-3-sites');   // the site list, before granting redraws the page
			await wizButton('Rechte erteilen und abschließen').catch(() => wizButton('Grant access and finish'));
			// connectFinish registers the app; the step redraws as connected.
			await page.waitForFunction(() => (STATE.tenant && (STATE.tenant.sites || []).length > 0), null, { timeout: 180000 })
				.catch(() => { throw new Error('the tenant never reported granted sites'); });
			await beat(1500);
		},
	},
	{
		id: '6-ziel', skipOnDryRun: true,
		caption: 'Schritt 4: Ziel wählen. SharePoint-Website und Dokumentbibliothek. Ein Knopf speichert das Ziel und verbindet die Freigabe als Route.',
		async run() {
			await nextStep();
			await ui('#wz4_site', 30000);
			await beat(700);
			await point('#wz4_site'); await beat(500);
			await point('#wz4_lib'); await beat(500);
			await shot('step-4');   // site + library chosen, before Save advances the wizard
			await wizButton('Speichern und verbinden').catch(() => wizButton('Save and connect'));
			await page.waitForFunction(() => (STATE.routes || []).length > 0, null, { timeout: 60000 })
				.catch(() => { throw new Error('no route was created by step 4'); });
			await beat(1600);
		},
	},
	{
		id: '7-scannen', skipOnDryRun: true,
		caption: 'Schritt 5: eine Seite scannen. Adresse, Benutzer und Passwort am Kopierer eintragen. Die Box wartet auf den ersten Scan.',
		async run() {
			await ui('#wz_body', 15000);
			await beat(1200);
			await shot('step-5');   // the three values for the copier, before the scan lands
			// Put a real file into the share and watch the step report it landed.
			const pdf = writeSamplePdf();
			try {
				deliver(pdf, run.pdfName = path.basename(pdf));
			} catch (e) {
				if (e instanceof SkipStep) { console.log(`\n${e.message}\n`); return; }
				throw e;
			}
			await page.waitForFunction(
				() => { const r = ((STATE.stats || {}).recent || [])[0]; return r && /uploaded|confirmed/.test(r.status); },
				null, { timeout: 120000 })
				.catch(() => { throw new Error('the scan never reported as landed in step 5'); });
			await beat(1800);
		},
	},
	{
		id: '8-dashboard', shot: 'step-6-dashboard', skipOnDryRun: true,
		caption: 'Fertig. Das Dashboard zeigt die Freigabe, die Route und den ersten Upload im Verlauf.',
		async run() {
			await nextStep();   // "Zum Dashboard"
			await ui('#v-dashboard.on', 15000);
			await beat(1500);
			await point('#recentrows').catch(() => { });
			await beat(1500);
		},
	},
];

/* ============================================================ the manual seam */

function printCodeBox(code, url) {
	const bar = '='.repeat(66);
	console.log(['', bar,
		'  JETZT ANMELDEN — DIE AUFNAHME LÄUFT WEITER.', '',
		`    Code   ${code}`,
		`    URL    ${url}`, '',
		'  Diese URL an einem Rechner öffnen, an dem du dich als Tenant-',
		'  Administrator anmelden kannst. Code eingeben, Zustimmung erteilen.', '',
		`  Warte bis zu ${Math.round(ARGS.codeTimeout / 60000)} Minuten. Läuft der Code ab: Ctrl-C, neu starten.`,
		bar, ''].join('\n'));
}

async function waitForSignIn(timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const j = await page.evaluate(async () => {
			const r = await fetch('/api/tenant/connect/poll', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF }, body: '{}' });
			return r.json();
		});
		if (j.stage === 'sites' || j.stage === 'done') return;
		if (j.stage === 'failed') throw new Error(`the Microsoft sign-in failed: ${j.error || 'no reason given'}`);
		if (j.stage === 'idle') throw new Error('the box forgot the device code. Start the run again.');
		if (Date.now() > deadline) throw new Error('nobody finished the sign-in in time; the code expired. Start again.');
		await beat(5000);
	}
}

/* ============================================================ the file */

function sizeArg(v) {
	const m = /^(\d+(?:\.\d+)?)\s*([KMG]?)B?$/i.exec(String(v).trim());
	if (!m) die(`--pdf-size wants a size like 8M, got ${v}`);
	return Math.round(parseFloat(m[1]) * { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3 }[m[2].toUpperCase()]);
}
function archivePreviousTake(out) {
	const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
	for (const name of ['wizard.webm', 'captions.jsonl']) {
		const from = path.join(out, name);
		if (!fs.existsSync(from) || fs.statSync(from).size === 0) continue;
		const to = path.join(out, name.replace(/(\.[^.]+)$/, `-${stamp}$1`));
		fs.renameSync(from, to);
		console.log(`kept the previous ${name} as ${path.basename(to)}`);
	}
}
function writeSamplePdf() {
	const day = new Date().toISOString().slice(0, 10);
	const text = `BT /F1 26 Tf 64 742 Td (Rechnung ${day}) Tj ET`;
	const padBytes = Math.max(0, ARGS.pdfSize - 800);
	const pad = crypto.randomBytes(Math.ceil(padBytes / 2)).toString('hex').slice(0, padBytes);
	const objs = [
		'<< /Type /Catalog /Pages 2 0 R >>',
		'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
		'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
		`<< /Length ${text.length} >>\nstream\n${text}\nendstream`,
		'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
		`<< /Length ${pad.length} >>\nstream\n${pad}\nendstream`,
	];
	let body = '%PDF-1.4\n';
	const offsets = [];
	objs.forEach((o, i) => { offsets.push(body.length); body += `${i + 1} 0 obj\n${o}\nendobj\n`; });
	const startxref = body.length;
	body += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
	offsets.forEach((o) => { body += String(o).padStart(10, '0') + ' 00000 n \n'; });
	body += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${startxref}\n%%EOF\n`;
	const file = path.join(ARGS.out, `Rechnung_${day}.pdf`);
	fs.writeFileSync(file, Buffer.from(body, 'latin1'));
	return file;
}
function deliver(local, name) {
	const root = ARGS.shareRoot || process.env.DEMO_SHARE_ROOT;
	if (root && fs.existsSync(path.join(root, SHARE))) {
		const dir = path.join(root, SHARE);
		const tmp = path.join(dir, name + '.part');
		fs.copyFileSync(local, tmp); fs.renameSync(tmp, path.join(dir, name));
		console.log(`copied ${name} into ${dir}`); return;
	}
	const smb = smbclientCommand();
	if (smb) {
		const host = new URL(ARGS.url).hostname;
		const smbArgs = [`//${host}/${SHARE}`, '-U', `svc-${SHARE}`, '-c', `put "${local}" "${name}"`];
		const args = smb.viaNixShell ? ['-p', 'samba', '--run', ['smbclient', ...smbArgs].map(shq).join(' ')] : smbArgs;
		const r = spawnSync(smb.cmd, args, { env: { ...process.env, PASSWD: run.smbPassword }, encoding: 'utf8' });
		if (r.status !== 0) throw new Error(`smbclient could not write into //${host}/${SHARE}: ${(r.stderr || r.stdout || '').trim()}`);
		console.log(`put ${name} into //${host}/${SHARE}`); return;
	}
	throw new SkipStep(`no way to put a file into ${SHARE}. Pass --share-root, or install samba (nix-shell -p samba). Step 5's landing is skipped; the rest is recorded.`);
}
function smbclientCommand() {
	if (spawnSync('smbclient', ['--version'], { stdio: 'ignore' }).status === 0) return { cmd: 'smbclient', viaNixShell: false };
	if (spawnSync('nix-shell', ['-p', 'samba', '--run', 'smbclient --version'], { stdio: 'ignore' }).status === 0) return { cmd: 'nix-shell', viaNixShell: true };
	return null;
}
function shq(a) { return "'" + String(a).replaceAll("'", "'\\''") + "'"; }
class SkipStep extends Error { }

/* ============================================================ main */

async function main() {
	preflight();
	fs.writeFileSync(path.join(ARGS.out, 'captions.jsonl'), '');
	const browser = await chromium.launch({ executablePath: CHROMIUM, args: ['--no-sandbox'] });
	const context = await browser.newContext({
		viewport: { width: 1600, height: 900 },
		recordVideo: { dir: ARGS.out, size: { width: 1600, height: 900 } },
		ignoreHTTPSErrors: true, locale: 'de-DE',
	});
	await context.addInitScript(overlay);
	page = await context.newPage();
	t0 = Date.now();

	let failure = null;
	try {
		await page.goto(ARGS.url, { waitUntil: 'domcontentloaded' });
		await ui('#pw', 30000);
		for (const s of steps) {
			if (ARGS.skipOnboarding && s.skipOnDryRun) { console.log(`[  skip  ] ${s.id} (--skip-onboarding)`); continue; }
			try { await runStep(s); }
			catch (e) { if (e instanceof SkipStep) { console.log(`\n${e.message}\n`); break; } throw e; }
		}
	} catch (e) { failure = e; }

	const video = page.video();
	await context.close();
	await browser.close();

	let videoPath = '';
	if (video) {
		try { const raw = await video.path(); videoPath = path.join(ARGS.out, 'wizard.webm'); fs.renameSync(raw, videoPath); }
		catch (e) { console.error(`the video could not be renamed: ${e.message}`); }
	}
	console.log('');
	console.log(`captions   ${path.join(ARGS.out, 'captions.jsonl')} (${captions.length} lines)`);
	console.log(`screenshots ${path.join(ARGS.out, 'img')}/step-*.png`);
	if (videoPath) console.log(`video      ${videoPath}`);
	if (failure) { console.error(`\nthe take stopped at ${currentStep}:\n  ${failure.message}\n`); process.exitCode = 1; return; }
	console.log('\nRender the MP4 with:  ./render.sh out/wizard.webm');
	console.log('Reset the box before another take (state wipe in docs/EINRICHTUNG.md).');
}

main().catch((e) => { console.error(`\nthe take stopped at ${currentStep}:\n  ${e.message}\n`); process.exit(1); });
