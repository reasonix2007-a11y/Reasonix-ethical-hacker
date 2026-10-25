// إصلاح مرحلتين: 1) استعادة سطر I18N المدموج  2) إصلاح سليم بمحدد \b
import fs from 'node:fs';
const f = 'index.html';
let s = fs.readFileSync(f, 'utf8');

// 1) السطر المدموج يبدأ بـ fd_all:'كل الأنواع' وينتهي بـ query($sql);',
const start = s.indexOf("  fd_all:'كل الأنواع',fd_th_vuln:'الثغرة'");
if (start !== -1) {
  const endMark = "query($sql);',";
  const end = s.indexOf(endMark, start) + endMark.length;
  const line = s.slice(start, end);
  const restored = line.replace(/\\n/g, '\n');
  s = s.slice(0, start) + restored + s.slice(end);
  fs.writeFileSync(f, s);
  console.log('restored I18N line:', line.length, '→', restored.length, '(newlines:', (line.match(/\\n/g) || []).length + ')');
} else {
  console.log('merged I18N line not found (already OK)');
}

// 2) الإصلاح الصحيح: \b يمنع مطابقة fd_th_vuln
s = fs.readFileSync(f, 'utf8');
const esc = t => t.replace(/\r?\n/g, '\\n');
let count = 0;
s = s.replace(/\bvuln:'([\s\S]*?)',\s*\n\s*\bfixed:'([\s\S]*?)',/g, (m0, v, fx) => {
  if (v.includes('\n') || fx.includes('\n')) count++;
  return `vuln:'${esc(v)}',\n  fixed:'${esc(fx)}',`;
});
fs.writeFileSync(f, s);
console.log('properly repaired entries:', count);
