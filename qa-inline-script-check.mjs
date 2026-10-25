import fs from 'node:fs';
const html = fs.readFileSync('index.html', 'utf8');
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)];
let fail = 0;
for (const [i, s] of scripts.entries()) {
  try { new Function(s[1]); }
  catch (e) { fail++; console.log(`script #${i} ERROR: ${e.message}`); }
}
console.log(`checked ${scripts.length} inline scripts, ${fail} error(s)`);
process.exit(fail ? 1 : 0);
