#!/usr/bin/env node
// Records one continuous take of setting a box up, and writes the subtitle
// timings next to the video so nobody has to time them by hand.
//
// The Microsoft device-code sign-in is done by a human while the recording
// runs. Nothing here touches the Microsoft login page and no Microsoft
// credential goes near this script.
//
//   node demo.mjs --url https://192.168.121.10:8444
//   node demo.mjs --skip-onboarding          # dry run against a box with no tenant
//
// Reset before a second take: see the note printed at the end of a run.

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
	// 40 MB takes several seconds to upload on a normal line, which is what makes
	// the transfer visible in Activity instead of finishing between two polls.
	const a = { url: 'https://127.0.0.1:8445', out: path.join(HERE, 'out'), password: '', pdf: '', shareRoot: '', skipOnboarding: false, codeTimeout: 10 * 60 * 1000, pdfSize: 40 * 1024 * 1024 };
	// parseArgs runs at module load, so a missing value here would be an
	// uncaught throw with a stack rather than one line saying what is wrong.
	const takesValue = new Set(['--url', '--password', '--out', '--pdf', '--share-root', '--pdf-size']);
	for (let i = 0; i < argv.length; i++) {
		const v = argv[i + 1];
		if (takesValue.has(argv[i]) && v === undefined) die(`${argv[i]} needs a value`);
		switch (argv[i]) {
			case '--url': a.url = v; i++; break;
			case '--password': a.password = v; i++; break;
			case '--out': a.out = path.resolve(v); i++; break;
			case '--pdf': a.pdf = path.resolve(v); i++; break;
			case '--share-root': a.shareRoot = path.resolve(v); i++; break;
			case '--pdf-size': a.pdfSize = sizeArg(v); i++; break;
			case '--skip-onboarding': a.skipOnboarding = true; break;
			case '-h': case '--help':
				console.log('demo.mjs [--url U] [--password P] [--out DIR] [--pdf FILE] [--pdf-size 40M] [--share-root DIR] [--skip-onboarding]');
				process.exit(0);
			default:
				die(`unknown argument ${argv[i]}`);
		}
	}
	return a;
}

const ARGS = parseArgs(process.argv.slice(2));

function die(msg) {
	console.error('\n' + msg + '\n');
	process.exit(1);
}

// The password is read, never echoed. Only its source is named.
function adminPassword() {
	if (ARGS.password) return ARGS.password;
	if (process.env.SCAN_ADMIN_PASSWORD) return process.env.SCAN_ADMIN_PASSWORD;
	const log = path.join(REPO, '.dev-run.log');
	if (fs.existsSync(log)) {
		const m = fs.readFileSync(log, 'utf8').match(/^\s*password\s+(\S+)\s*$/m);
		if (m) { console.log(`password read from ${log}`); return m[1]; }
	}
	die('no box password. Pass --password, set SCAN_ADMIN_PASSWORD, or run scripts/dev.sh so .dev-run.log carries one.');
}

/* ============================================================ preflight */

const CHROMIUM = process.env.CHROMIUM_BIN || '/etc/profiles/per-user/acid/bin/chromium';
const FFMPEG_LINK = path.join(os.homedir(), '.cache/ms-playwright/ffmpeg-1011/ffmpeg-linux');

function preflight() {
	if (!fs.existsSync(CHROMIUM)) {
		die(`no chromium at ${CHROMIUM}.\nPlaywright's own browser download does not run here. Point CHROMIUM_BIN at the system binary:\n  CHROMIUM_BIN=$(command -v chromium) node demo.mjs`);
	}
	// Playwright would otherwise fail with its download instructions, which do
	// not apply on NixOS.
	if (!fs.existsSync(FFMPEG_LINK)) {
		die(`Playwright's video recorder wants an ffmpeg binary at\n  ${FFMPEG_LINK}\nIts bundled download does not run here. Link the system one:\n  mkdir -p ${path.dirname(FFMPEG_LINK)}\n  ln -s "$(command -v ffmpeg)" ${FFMPEG_LINK}`);
	}
	fs.mkdirSync(ARGS.out, { recursive: true });
	archivePreviousTake(ARGS.out);
}

/* ============================================================ the overlay
   Playwright's video has no mouse pointer, so the demo draws one. Injected as an
   init script so it survives the reload the login does.

   The caption text is deliberately not drawn here. It goes into captions.jsonl
   and render.sh burns it in, which keeps it restylable and retimable without
   shooting the take again. Drawing it twice put two copies on screen. */

function overlay() {
	try { localStorage.setItem('scan-lang', 'de'); } catch (e) { /* opaque origin on about:blank */ }

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
			const layer = mount();
			if (!layer) return Promise.resolve();
			const c = document.getElementById('demo-cursor');
			const from = pos;
			pos = { x, y };
			const a = c.animate(
				[{ transform: `translate(${from.x}px,${from.y}px)` }, { transform: `translate(${x}px,${y}px)` }],
				{ duration: ms, easing: 'cubic-bezier(.22,.61,.36,1)', fill: 'forwards' });
			return a.finished.then(() => undefined);
		},
		ripple() {
			const layer = mount();
			if (!layer) return Promise.resolve();
			const r = document.createElement('div');
			r.style.cssText = `position:fixed;left:${pos.x}px;top:${pos.y}px;width:16px;height:16px;margin:-8px 0 0 -8px;` +
				'border-radius:50%;border:2px solid var(--amber,#EBA335);pointer-events:none';
			layer.appendChild(r);
			return r.animate([{ transform: 'scale(.35)', opacity: .95 }, { transform: 'scale(3.2)', opacity: 0 }],
				{ duration: 430, easing: 'ease-out' }).finished.then(() => r.remove());
		},
		ring(b) {
			const layer = mount();
			if (!layer) return;
			const r = document.getElementById('demo-ring');
			if (!b) { r.style.opacity = '0'; return; }
			r.style.left = (b.x - 7) + 'px';
			r.style.top = (b.y - 7) + 'px';
			r.style.width = (b.width + 14) + 'px';
			r.style.height = (b.height + 14) + 'px';
			r.style.opacity = '1';
		},
	};

	if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
	else mount();
}

/* ============================================================ driving the page */

let page = null;
let currentStep = 'startup';

// Pacing only. Nothing is being waited for here; it gives the eye a beat.
const beat = (ms) => new Promise((r) => setTimeout(r, ms));

async function ui(sel, timeout = 15000) {
	const l = page.locator(sel).first();
	try {
		await l.waitFor({ state: 'visible', timeout });
	} catch {
		throw new Error(`selector never became visible: ${sel}`);
	}
	return l;
}

async function point(sel, ms = 520) {
	const l = await ui(sel);
	await l.scrollIntoViewIfNeeded().catch(() => { });
	const box = await l.boundingBox();
	if (!box) throw new Error(`selector has no box on screen: ${sel}`);
	await page.evaluate(async ([b, d]) => {
		window.__demo.ring(b);
		await window.__demo.cursorTo(b.x + b.width / 2, b.y + b.height / 2, d);
	}, [box, ms]);
	return l;
}

async function click(sel) {
	const l = await point(sel);
	await page.evaluate(() => window.__demo.ripple());
	await l.click();
	return l;
}

// type, never fill: the viewer reads these fields as they are written.
async function typeInto(sel, text, { clear = false } = {}) {
	const l = await click(sel);
	if (clear) { await l.press('Control+a'); await l.press('Delete'); }
	await l.pressSequentially(text, { delay: 60 });
	return l;
}

async function pick(sel, label) {
	const l = await point(sel);
	await page.evaluate(() => window.__demo.ripple());
	try {
		await l.selectOption({ label });
	} catch {
		const have = await l.locator('option').allTextContents();
		throw new Error(`${sel} has no option "${label}". It offers: ${have.join(', ') || '(none)'}`);
	}
	return l;
}

async function nav(view) {
	await click(`#nav a[data-view="${view}"]`);
	await ui(`#v-${view}.on`);
}

async function clearRing() {
	await page.evaluate(() => window.__demo.ring(null));
}

/* ============================================================ steps + captions */

const captions = [];
let t0 = 0;

async function runStep(s) {
	currentStep = s.id;
	const start = Date.now() - t0;
	console.log(`[${String(start / 1000).padStart(7)}s] ${s.id}`);
	try {
		await s.run();
	} catch (e) {
		if (e instanceof SkipStep) throw new SkipStep(`step "${s.id}" skipped: ${e.message}`);
		throw new Error(`step "${s.id}" failed: ${e.message}`);
	}
	const end = Date.now() - t0;
	const line = JSON.stringify({ start, end, text: s.caption });
	captions.push(line);
	fs.appendFileSync(path.join(ARGS.out, 'captions.jsonl'), line + '\n');
}

const SHARE = 'scans-vertrieb';
const SMB_USER = 'svc-scan-vertrieb';
const DEST1 = 'Vertrieb Eingang';
const DEST2 = 'Archiv Scans';

// Carried between steps: the SMB password is needed to put the file over SMB
// and is never written to the terminal or to disk.
const run = { smbPassword: '', pdfName: '', code: '', verifyUrl: '', dirtiedBox: false };

const steps = [
	{
		id: '1-anmelden',
		caption: 'Anmeldung an der Box mit dem Box-Admin-Passwort.',
		async run() {
			await beat(900); // pacing: let the sign-in card settle before the cursor arrives
			await typeInto('#pw', adminPassword());
			await click('#unlock');
			// A wrong password leaves the sign-in card in place with its error
			// filled in. Waiting only for the shell would report a missing
			// selector, which says nothing about the actual cause.
			const bad = await page.waitForFunction(() => {
				const err = document.querySelector('#loginerr');
				const shell = document.querySelector('#shell');
				if (shell && !shell.classList.contains('hide')) return 'ok';
				return err && err.textContent.trim() ? err.textContent.trim() : false;
			}, { timeout: 20000 }).then(h => h.jsonValue()).catch(() => 'ok');
			if (bad !== 'ok') {
				throw new Error(`the box rejected the admin password: ${bad}. ` +
					'Set a known one with: vagrant ssh -c "sudo m365-scan reset-password <new>"');
			}
			await ui('#shell', 20000);
			await ui('#statbox .l', 20000);
			await clearRing();
			await assertNothingToReset();
		},
	},
	{
		id: '2-tenant-start',
		caption: 'Tenant verbinden. Die Box zeigt einen Gerätecode und die Adresse der Anmeldeseite.',
		async run() {
			await nav('settings');
			await click('#v-settings button[onclick="connectStart()"]');
			await ui('#connectbox code', 30000);
			run.code = (await page.locator('#connectbox code').first().textContent()).trim();
			run.verifyUrl = (await page.locator('#connectbox a').first().textContent()).trim();
			await point('#connectbox');
			await beat(2500); // pacing: hold on the code long enough to read it
		},
	},
	{
		id: '3-anmeldung-microsoft',
		caption: 'Ein Administrator meldet sich bei Microsoft an und gibt den Code ein. Die Box wartet auf den Abschluss.',
		skipOnDryRun: true,
		async run() {
			printCodeBox(run.code, run.verifyUrl);
			await waitForSignIn(ARGS.codeTimeout);
			// The page has its own five second poll; it draws the site list as soon
			// as the token lands. Wait for that, never for a clock.
			await ui('#connectbox input[type=checkbox]', 30000);
			await clearRing();
		},
	},
	{
		id: '4-websites-freigeben',
		caption: 'Zwei SharePoint-Websites auswählen. Die Box bekommt Schreibrechte nur auf diesen Websites.',
		skipOnDryRun: true,
		async run() {
			const boxes = page.locator('#connectbox input[type=checkbox]');
			const n = await boxes.count();
			if (n < 2) throw new Error(`the sign-in returned ${n} site(s); the demo needs two`);
			let picked = 0;
			for (let i = 0; i < n && picked < 2; i++) {
				const cb = boxes.nth(i);
				if (await cb.isChecked()) { picked++; continue; }
				const box = await cb.boundingBox();
				await page.evaluate(async ([b]) => {
					window.__demo.ring(b);
					await window.__demo.cursorTo(b.x + b.width / 2, b.y + b.height / 2, 420);
					await window.__demo.ripple();
				}, [box]);
				await cb.check();
				picked++;
			}
			await click('#connectbox button.pri');
			// connectFinish registers the app and refreshes; the panel filling in is
			// the state to wait for.
			await page.waitForFunction(
				() => document.getElementById('set_m365pill').classList.contains('ok') &&
					document.getElementById('set_appid').value !== '',
				null, { timeout: 180000 },
			).catch(() => { throw new Error('the tenant panel never reported a connection (#set_m365pill / #set_appid)'); });
			await point('#tenantgrid');
			await beat(1800); // pacing: show the filled panel
			await point('#sitesrows');
			await beat(1800); // pacing: show the granted sites
			await clearRing();
		},
	},
	{
		id: '5-freigabe-anlegen',
		caption: `Die Freigabe ${SHARE} anlegen. Das SMB-Passwort wird genau einmal angezeigt.`,
		async run() {
			await nav('shares');
			await typeInto('#ns_name', SHARE);
			await typeInto('#ns_user', SMB_USER);
			await beat(700); // pacing: the UNC hint under the name updates as you type
			await click('#createbtn');
			const outcome = await page.waitForFunction(() => {
				const n = document.getElementById('createnote');
				if (n && !n.classList.contains('hide')) return 'ok';
				const t = document.getElementById('toast');
				if (t && t.classList.contains('on')) return 'err:' + t.textContent;
				return false;
			}, null, { timeout: 60000 }).then((h) => h.jsonValue())
				.catch(() => { throw new Error('neither #createnote nor a toast appeared after Create'); });
			if (outcome !== 'ok') throw new Error(`the box refused to create the share: ${outcome.slice(4)}`);
			run.dirtiedBox = true;
			// Needed for the smbclient path in step 10. Never logged, never written out.
			run.smbPassword = (await page.locator('#cn_pw').textContent()).trim();
			await point('#createnote');
			await beat(3000); // pacing: the password is shown once, so hold on it
			await point('#sharerows tr');
			await beat(1600); // pacing: show the share in the table with its UNC path
			await clearRing();
		},
	},
	{
		id: '6-ziel-speichern',
		caption: 'Ein Ziel speichern: Website, Dokumentbibliothek, Ordner und Unterordner-Vorlage mit Vorschau.',
		async run() { await buildDestination(DEST1, 0, '{yyyy}/{MM}/{share}', true); },
	},
	{
		id: '7-zweites-ziel',
		caption: 'Ein zweites Ziel, damit dieselbe Freigabe später an zwei Stellen schreibt.',
		async run() { await buildDestination(DEST2, 1, '{yyyy}', false); },
	},
	{
		id: '8-erste-route',
		caption: `Die erste Route: die Freigabe ${SHARE} schreibt in das Ziel ${DEST1}.`,
		async run() { await wireRoute(DEST1); },
	},
	{
		id: '9-zweite-route',
		caption: 'Die zweite Route aus derselben Freigabe in das zweite Ziel. Dieselbe Datei geht an beide Ziele.',
		async run() {
			await wireRoute(DEST2);
			await point('#routerows');
			await beat(2400); // pacing: both route cards side by side is the point of the step
			await clearRing();
		},
	},
	{
		id: '10-datei-in-freigabe',
		caption: 'Eine PDF-Datei landet über SMB in der Freigabe.',
		async run() {
			const local = ARGS.pdf || writeSamplePdf();
			run.pdfName = path.basename(local);
			deliver(local, run.pdfName);
		},
	},
	{
		id: '11-uebertragung',
		caption: 'Die Übertragung läuft. Auf den Verbindungen zeigt ein wandernder Punkt die Bewegung.',
		async run() {
			if (!run.pdfName) throw new Error('no file was delivered, so there is nothing to watch');
			await nav('dashboard');
			// The comets only appear while something is actually moving, so wait
			// for one rather than hoping the poll lands mid transfer. A fast line
			// can finish the upload before we look, which is not a failed take.
			const flowing = await page.waitForSelector('#flowrail .lnk.flow', { timeout: 120000 })
				.then(() => true).catch(() => false);
			if (flowing) {
				await point('#flowrail');
				await beat(7000); // pacing: hold on the moving dots, this is the product working
				await clearRing();
			} else {
				console.log('the upload finished before the dashboard could show it in flight');
			}
		},
	},
	{
		id: '12-aktivitaet',
		caption: 'Aktivität zeigt dieselbe Datei in der Warteschlange, mit Fortschritt je Route.',
		async run() {
			await nav('activity');
			await page.waitForFunction((f) => {
				const q = document.getElementById('queuerows-a');
				const d = document.getElementById('donerows');
				return (q && q.textContent.includes(f)) || (d && d.textContent.includes(f));
			}, run.pdfName, { timeout: 120000 })
				.catch(() => { throw new Error(`${run.pdfName} never showed up in #queuerows-a or #donerows`); });
			await point('#actrail');
			await beat(3000); // pacing: watch the transfer move along the rail
			await clearRing();
			// Then wait for it to land, so the finished list is populated on camera.
			await page.waitForFunction((f) => {
				const d = document.getElementById('donerows');
				return d && d.textContent.includes(f);
			}, run.pdfName, { timeout: 180000 })
				.catch(() => { throw new Error(`${run.pdfName} never reached the finished list`); });
			await point('#donerows');
			await beat(2600);
			await clearRing();
		},
	},
	{
		id: '13-dashboard',
		caption: 'Das Dashboard danach: der Upload steht im Verlauf.',
		async run() {
			await nav('dashboard');
			await page.waitForFunction((f) => document.getElementById('recentrows').textContent.includes(f),
				run.pdfName, { timeout: 120000 })
				.catch(() => { throw new Error(`${run.pdfName} never reached the dashboard history (#recentrows)`); });
			await point('#recentrows');
			await beat(3000); // pacing: closing shot on the history
			await clearRing();
		},
	},
];

/* ============================================================ step bodies */

// A second take over the same objects fails halfway, which wastes the human's
// sign-in. Refuse before anybody is asked to do anything.
async function assertNothingToReset() {
	const clash = await page.evaluate(([sh, d1, d2]) => {
		const has = (arr, n) => arr.some((x) => x.name === n);
		const out = [];
		if (has(STATE.shares, sh)) out.push('share ' + sh);
		if (has(STATE.destinations, d1)) out.push('destination ' + d1);
		if (has(STATE.destinations, d2)) out.push('destination ' + d2);
		return out;
	}, [SHARE, DEST1, DEST2]);
	if (clash.length) throw new Error(`the box already carries ${clash.join(', ')}, so this take would stop halfway.`);
}

async function buildDestination(name, siteIndex, template, showFolders) {
	await nav('destinations');
	await click('#v-destinations button[onclick="newDest()"]');
	await ui('#sitelist .opt', 30000);
	const sites = page.locator('#sitelist .opt');
	const have = await sites.count();
	if (have <= siteIndex) throw new Error(`the picker offers ${have} site(s), so index ${siteIndex} does not exist. Grant a second site in Settings.`);
	await typeInto('#destname', name);
	await clickNth('#sitelist .opt', siteIndex);
	await ui('#liblist .opt', 30000);
	await clickNth('#liblist .opt', 0);
	// The root row is always drawn, so the list is present even in an empty library.
	await ui('#foldlist .opt', 30000);
	if (showFolders) {
		const folders = page.locator('#foldlist .opt');
		if (await folders.count() > 1) {
			await clickNth('#foldlist .opt', 1);
			await ui('#foldlist .opt', 30000);
		}
	}
	await typeInto('#tmpl', template, { clear: true });
	await page.waitForFunction(() => document.getElementById('tmplprev').textContent.trim() !== '',
		null, { timeout: 10000 })
		.catch(() => { throw new Error('#tmplprev stayed empty, so the preview never rendered') });
	await point('#tmplprev');
	await beat(2200); // pacing: the live preview is the reason the template field exists
	await click('#v-destinations button[onclick="saveDest()"]');
	await page.waitForFunction((n) => document.getElementById('destrows').textContent.includes(n),
		name, { timeout: 30000 })
		.catch(() => { throw new Error(`the destination "${name}" never appeared in #destrows`) });
	await point('#destrows');
	await beat(1600); // pacing: show the saved destination in the table
	await clearRing();
}

async function wireRoute(dest) {
	await nav('routes');
	await pick('#nr_share', SHARE);
	await pick('#nr_dest', dest);
	await beat(900); // pacing: the hint under each select explains what the route will do
	// A route card shows the share and the destination's site path, never the
	// destination's own name, so count cards instead of looking for the name.
	const before = await page.locator('#routerows .route').count();
	await click('#v-routes button[onclick="createRoute()"]');
	await page.waitForFunction((n) => document.querySelectorAll('#routerows .route').length > n,
		before, { timeout: 30000 })
		.catch(async () => {
			const err = (await page.locator('#toast, .err').allTextContents()).join(' ').trim();
			throw new Error(`the route to "${dest}" was not added${err ? `: ${err}` : ''}`);
		});
}

async function clickNth(sel, i) {
	const l = page.locator(sel).nth(i);
	try {
		await l.waitFor({ state: 'visible', timeout: 15000 });
	} catch {
		throw new Error(`selector never became visible: ${sel} (nth ${i})`);
	}
	await l.scrollIntoViewIfNeeded().catch(() => { });
	const box = await l.boundingBox();
	if (!box) throw new Error(`selector has no box on screen: ${sel} (nth ${i})`);
	await page.evaluate(async ([b]) => {
		window.__demo.ring(b);
		await window.__demo.cursorTo(b.x + b.width / 2, b.y + b.height / 2, 460);
		await window.__demo.ripple();
	}, [box]);
	await l.click();
}

/* ============================================================ the manual seam */

function printCodeBox(code, url) {
	const bar = '='.repeat(66);
	console.log([
		'', bar,
		'  A HUMAN HAS TO SIGN IN NOW. THE RECORDING KEEPS ROLLING.',
		'',
		`    code   ${code}`,
		`    url    ${url}`,
		'',
		'  Open that URL on a machine where you can sign in as a tenant',
		'  admin, enter the code, and accept the consent prompt.',
		'',
		`  Waiting up to ${Math.round(ARGS.codeTimeout / 60000)} minutes. If the code expires, stop this run`,
		'  with Ctrl-C and start it again; a new code is issued each time.',
		bar, '',
	].join('\n'));
}

// Polls the box's own endpoint from inside the signed-in page, so the session
// cookie and the CSRF token are the page's. The page polls on its own timer too;
// Microsoft answers a second poller with slow_down, which the box treats as
// "keep waiting", so the two do not fight.
async function waitForSignIn(timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const j = await page.evaluate(async () => {
			const r = await fetch('/api/tenant/connect/poll', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
				body: '{}',
			});
			return r.json();
		});
		if (j.stage === 'sites' || j.stage === 'done') return;
		if (j.stage === 'failed') throw new Error(`the Microsoft sign-in failed: ${j.error || 'no reason given'}`);
		if (j.stage === 'idle') throw new Error('the box forgot the device code. Start the run again.');
		if (Date.now() > deadline) {
			throw new Error(`nobody finished the sign-in within ${Math.round(timeoutMs / 60000)} minutes. The code has expired; start the run again for a fresh one.`);
		}
		await beat(5000); // pacing between polls, matching the interval Microsoft asks for
	}
}

/* ============================================================ the file */

// A one page PDF built by hand, so a take does not need a prop file lying around.
// sizeArg accepts plain bytes or a K/M/G suffix.
function sizeArg(v) {
	const m = /^(\d+(?:\.\d+)?)\s*([KMG]?)B?$/i.exec(String(v).trim());
	if (!m) die(`--pdf-size wants a size like 40M, got ${v}`);
	return Math.round(parseFloat(m[1]) * { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3 }[m[2].toUpperCase()]);
}

// A take costs a real sign-in, so nothing here may overwrite one. Anything left
// from a previous run is moved aside before recording starts.
function archivePreviousTake(out) {
	const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
	for (const name of ['demo.webm', 'captions.jsonl']) {
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
	// A real scan is megabytes, and the size is the point: a tiny file uploads
	// between two polls, so the queue looks empty and nobody sees the transfer.
	// The padding is a stream object nothing references, which keeps the file a
	// valid single page PDF at any size.
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

// Two ways in: a share root this host can write to, or smbclient. Neither being
// available is a skip, not a failure: the rest of the take is still usable.
function deliver(local, name) {
	const root = ARGS.shareRoot || process.env.DEMO_SHARE_ROOT || configuredShareRoot();
	if (root && fs.existsSync(path.join(root, SHARE))) {
		// Land it under a name the extension filter ignores, then rename, so the
		// watcher never sees a half written file.
		const dir = path.join(root, SHARE);
		const tmp = path.join(dir, name + '.part');
		fs.copyFileSync(local, tmp);
		fs.renameSync(tmp, path.join(dir, name));
		console.log(`copied ${name} into ${dir}`);
		return;
	}
	const smb = smbclientCommand();
	if (smb) {
		const host = new URL(ARGS.url).hostname;
		const smbArgs = [`//${host}/${SHARE}`, '-U', SMB_USER, '-c', `put "${local}" "${name}"`];
		// nix-shell takes its command as one string, so the smbclient arguments
		// have to be quoted into it. Passed as separate argv entries, nix-shell
		// reads -U as its own flag and refuses.
		const args = smb.viaNixShell
			? ['-p', 'samba', '--run', ['smbclient', ...smbArgs].map(shq).join(' ')]
			: smbArgs;
		const r = spawnSync(smb.cmd, args, { env: { ...process.env, PASSWD: run.smbPassword }, encoding: 'utf8' });
		if (r.status !== 0) throw new Error(`smbclient could not write into //${host}/${SHARE}: ${(r.stderr || r.stdout || '').trim()}`);
		console.log(`put ${name} into //${host}/${SHARE}`);
		return;
	}
	throw new SkipStep(
		`no way to put a file into ${SHARE}. Either mount the share and pass --share-root, ` +
		'or install samba so smbclient is on PATH (nix-shell -p samba). ' +
		'The rest of the take is recorded; steps 11 and 12 are skipped.');
}

// Only the box on this machine keeps its share root here. Trusting the repo
// config against a remote box would drop the file on the wrong machine.
function configuredShareRoot() {
	const host = new URL(ARGS.url).hostname;
	if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') return '';
	const cfg = path.join(REPO, '.dev/etc/config.json');
	if (!fs.existsSync(cfg)) return '';
	try { return JSON.parse(fs.readFileSync(cfg, 'utf8')).shareRoot || ''; } catch { return ''; }
}

function smbclientCommand() {
	if (spawnSync('smbclient', ['--version'], { stdio: 'ignore' }).status === 0) {
		return { cmd: 'smbclient', viaNixShell: false };
	}
	// nix-shell is the documented way to get samba here without installing it.
	if (spawnSync('nix-shell', ['-p', 'samba', '--run', 'smbclient --version'], { stdio: 'ignore' }).status === 0) {
		return { cmd: 'nix-shell', viaNixShell: true };
	}
	return null;
}

// shq quotes one argument for a POSIX shell. The password never travels this
// way, it goes through the PASSWD environment variable.
function shq(a) { return "'" + String(a).replaceAll("'", "'\\''") + "'"; }

class SkipStep extends Error { }

/* ============================================================ main */

const RESET_NOTE = [
	`To record again, reset the box first. On the workstation box:`,
	'  scripts/dev.sh --fresh',
	`Anywhere else, remove in the UI: both routes, the destinations "${DEST1}" and`,
	`"${DEST2}", then the share "${SHARE}". The tenant connection can stay; the`,
	'connect step tolerates an already connected tenant and pre-checks granted sites.',
].join('\n');

async function main() {
	preflight();
	fs.writeFileSync(path.join(ARGS.out, 'captions.jsonl'), '');

	const browser = await chromium.launch({ executablePath: CHROMIUM, args: ['--no-sandbox'] });
	const context = await browser.newContext({
		viewport: { width: 1600, height: 900 },
		recordVideo: { dir: ARGS.out, size: { width: 1600, height: 900 } },
		ignoreHTTPSErrors: true,
		locale: 'de-DE',
	});
	await context.addInitScript(overlay);
	page = await context.newPage();
	t0 = Date.now();   // Playwright starts the recording with the page, so this is frame zero.

	let failure = null;
	try {
		// Loading the page is setup, not a step: the first caption should start
		// with the first thing the viewer is asked to watch.
		await page.goto(ARGS.url, { waitUntil: 'domcontentloaded' });
		await ui('#pw', 30000);
		for (const s of steps) {
			if (ARGS.skipOnboarding && s.skipOnDryRun) {
				console.log(`[  skip  ] ${s.id} (--skip-onboarding)`);
				continue;
			}
			try {
				await runStep(s);
			} catch (e) {
				// A skip ends the take without failing it: everything after the file
				// delivery is about watching that file move.
				if (e instanceof SkipStep) { console.log(`\n${e.message}\n`); break; }
				throw e;
			}
			if (ARGS.skipOnboarding && s.id === '2-tenant-start') {
				// Nothing will finish this device code, so stop the page polling
				// Microsoft every five seconds for the rest of the dry run.
				await page.evaluate(() => { try { connStop(); } catch (e) { } });
			}
		}
	} catch (e) {
		failure = e;
	}

	const video = page.video();
	await context.close();
	await browser.close();

	let videoPath = '';
	if (video) {
		try {
			const raw = await video.path();
			videoPath = path.join(ARGS.out, 'demo.webm');
			fs.renameSync(raw, videoPath);
		} catch (e) {
			console.error(`the video could not be renamed: ${e.message}`);
		}
	}

	console.log('');
	console.log(`captions  ${path.join(ARGS.out, 'captions.jsonl')} (${captions.length} lines)`);
	if (videoPath) console.log(`video     ${videoPath}`);
	if (failure) {
		console.error(`\nthe take stopped at ${currentStep}:\n  ${failure.message}\n`);
		if (run.dirtiedBox) console.error(RESET_NOTE);
		process.exitCode = 1;
		return;
	}
	console.log('');
	console.log(RESET_NOTE);
}

main().catch((e) => {
	console.error(`\nthe take stopped at ${currentStep}:\n  ${e.message}\n`);
	process.exit(1);
});
