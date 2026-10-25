// فحص نهائي: هل كل سكربتات index.html تُجمَّع؟
import fs from 'node:fs';
import vm from 'node:vm';
const html = fs.readFileSync('index.html', 'utf8');
const re = /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g;
let m, i = 0, bad = 0;
while ((m = re.exec(html))) {
  i++;
  try { new vm.Script(m[1]); }
  catch (e) {
    bad++;
    const base = html.slice(0, m.index).split('\n').length;
    console.log(`script#${i} (file line ~${base}): ${e.message}`);
    // حدد السطر
    const lines = m[1].split('\n');
    let lo = 1, hi = lines.length, ff = -1, msg = '';
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      try { new vm.Script(lines.slice(0, mid).join('\n')); lo = mid + 1; }
      catch (er) { ff = mid; msg = er.message; hi = mid - 1; }
    }
    if (ff > 0) {
      console.log(`  first fail at script line ${ff}: ${msg}`);
      for (let k = Math.max(0, ff - 3); k < Math.min(lines.length, ff + 2); k++)
        console.log(`   ${k + 1}: ${JSON.stringify(lines[k].slice(0, 140))}`);
    }
  }
}
console.log(`scripts: ${i}, failing: ${bad}`);
