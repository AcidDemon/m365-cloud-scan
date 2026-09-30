// Rebuilds captions.jsonl from what a take printed to the terminal.
//
// The run logs one "[ 12.345s] step-id" line per finished step, which is the
// same clock the captions use, so a lost captions.jsonl can be reconstructed
// exactly as long as the scrollback survives.
//
//   node rebuild-captions.mjs run.log > out/captions.jsonl
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const log = fs.readFileSync(process.argv[2] || '/dev/stdin', 'utf8');

// The step texts live in demo.mjs. Reading the source avoids importing it,
// which would start a real take.
const src = fs.readFileSync(path.join(HERE, 'demo.mjs'), 'utf8');
const texts = new Map();
const re = /id:\s*'([^']+)',\s*\n\s*caption:\s*(`[^`]*`|'[^']*')/g;
for (let m; (m = re.exec(src));) {
	let t = m[2].slice(1, -1);
	// Only the interpolations the steps actually use.
	t = t.replace(/\$\{SHARE\}/g, 'scans-vertrieb').replace(/\$\{DEST1\}/g, 'Vertrieb Eingang')
		.replace(/\$\{DEST2\}/g, 'Archiv Scans');
	texts.set(m[1], t);
}

const out = [];
let prev = 0;
for (const line of log.split('\n')) {
	const m = /^\[\s*([\d.]+)s\]\s+(\S+)/.exec(line.trim());
	if (!m) continue;
	const end = Math.round(parseFloat(m[1]) * 1000);
	const text = texts.get(m[2]);
	if (!text) {
		process.stderr.write(`no caption for step ${m[2]}, skipped\n`);
		prev = end;
		continue;
	}
	out.push({ start: prev, end, text });
	prev = end;
}
if (!out.length) {
	process.stderr.write('no "[ 1.234s] step-id" lines found in that log\n');
	process.exit(1);
}
process.stderr.write(`rebuilt ${out.length} captions, ending at ${(prev / 1000).toFixed(1)}s\n`);
process.stdout.write(out.map((c) => JSON.stringify(c)).join('\n') + '\n');
