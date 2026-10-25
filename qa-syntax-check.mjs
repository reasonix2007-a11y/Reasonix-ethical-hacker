import fs from 'node:fs';
import vm from 'node:vm';
const html = fs.readFileSync('index.html', 'utf8');
const re = /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g;
let m, i = 0;
while ((m = re.exec(html))) {
  i++;
  try { new vm.Script(m[1], { filename: `inline-${i}.js` }); console.log(`script ${i}: ok (${m[1].length} chars)`); }
  catch (e) { console.log(`script ${i}: FAIL — ${e.message}`); }
}
