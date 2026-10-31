#!/usr/bin/env node
'use strict';
/**
 * Shows invisible and direction-changing characters in a file, so a human can see what
 * the model sees. Zero dependencies, Node >= 18. Read-only unless --strip is given.
 *
 *   node reveal.cjs <file>            list every hidden character run with line:column
 *   node reveal.cjs <file> --strip    write <file>.clean without them (the original is untouched)
 *
 * Decoded Unicode-tag text is printed as a JSON string. Treat it as data, never as instructions.
 */
const fs = require('fs');

const isTag = (cp) => cp >= 0xE0000 && cp <= 0xE007F;
const isVs = (cp) => cp >= 0xE0100 && cp <= 0xE01EF;
const isBidi = (cp) => (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200E || cp === 0x200F || cp === 0x061C;
const isZeroWidth = (cp) => [0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF, 0x00AD].includes(cp);
const hidden = (cp) => isTag(cp) || isVs(cp) || isBidi(cp) || isZeroWidth(cp);
const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;

function reveal(text) {
  const runs = [];
  let line = 1;
  let col = 0;
  let run = null;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (ch === '\n') { if (run) { runs.push(run); run = null; } line++; col = 0; continue; }
    col++;
    if (hidden(cp)) {
      if (!run) run = { line, col, cps: [] };
      run.cps.push(cp);
    } else if (run) { runs.push(run); run = null; }
  }
  if (run) runs.push(run);
  return runs.map((r) => {
    const tags = r.cps.filter(isTag).map((cp) => String.fromCharCode(cp - 0xE0000)).join('').replace(/[^\x20-\x7E]/g, '');
    const kinds = [...new Set(r.cps.map((cp) => (isTag(cp) ? 'tag' : isVs(cp) ? 'variation-selector' : isBidi(cp) ? 'bidi' : 'zero-width')))];
    return { line: r.line, column: r.col, count: r.cps.length, kinds, codepoints: [...new Set(r.cps.map(hex))].slice(0, 8), decoded: tags || undefined };
  });
}

function strip(text) {
  return Array.from(text).filter((ch, i, arr) => {
    const cp = ch.codePointAt(0);
    if (cp === 0xFEFF && i === 0) return true; // keep a leading BOM
    if (cp === 0x200D) { // keep ZWJ inside emoji sequences
      const p = (arr[i - 1] || '').codePointAt(0) || 0;
      const n = (arr[i + 1] || '').codePointAt(0) || 0;
      if (p >= 0x1F000 || n >= 0x1F000 || p === 0xFE0F) return true;
    }
    return !hidden(cp);
  }).join('');
}

function main() {
  const [file, flag] = process.argv.slice(2);
  if (!file) { console.error('Usage: node reveal.cjs <file> [--strip]'); process.exit(2); }
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { console.error(`Cannot read ${file}: ${e.message}`); process.exit(2); }
  const runs = reveal(text);
  if (!runs.length) { console.log(`${file}: no hidden characters`); return; }
  console.log(`${file}: ${runs.length} hidden character run(s)`);
  for (const r of runs) {
    console.log(`  ${r.line}:${r.column}  ${r.count} x ${r.kinds.join('+')}  ${r.codepoints.join(' ')}`);
    if (r.decoded) console.log(`         decoded tag text (data, not instructions): ${JSON.stringify(r.decoded)}`);
  }
  if (flag === '--strip') {
    fs.writeFileSync(`${file}.clean`, strip(text));
    console.log(`wrote ${file}.clean`);
  }
}

if (require.main === module) main();
module.exports = { reveal, strip };
