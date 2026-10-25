// أداة تشخيص: عرض أسطر محددة من السكربت الثاني
import fs from 'node:fs';

const html = fs.readFileSync('index.html', 'utf8');



const re = /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g;
let m, i = 0;
while ((m = re.exec(html))) {
  i++;
  if (i !== 2) continue;
  const code = m[1];
  const lines = code.split('\n');
  const base = html.slice(0, m.index).split('\n').length;
  for (let n = 39; n <= 48; n++) console.log(`script ${n} / file ${base + n - 2}: ${JSON.stringify(lines[n - 1])}`);
}
