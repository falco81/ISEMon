#!/usr/bin/env node
/* Every piece of text the page can show, found in web/index.php.

   Not part of the program: a tool for whoever updates the language files.
   It needs Node and the `acorn` and `acorn-walk` packages
   (NODE_PATH=/path/to/node_modules node tools/i18n/extract.js web/index.php).
   It prints JSON on stdout: {"strings": [...], "patterns": [...]} - each a
   source text exactly as the page shows it, whitespace folded to one space;
   a pattern holds {0}, {1}... where the page puts something of its own (a
   number, a name). `tools/i18n/build.py` turns that into web/lang/en.json and
   carries every existing translation over by its ID. */
'use strict';
const fs = require('fs');
const acorn = require('acorn');
const walk = require('acorn-walk');

const path = process.argv[2] || 'web/index.php';
const raw = fs.readFileSync(path, 'utf8');
const strings = new Set();
const patterns = new Set();
/* A sentence with words in bold or in code in it is one thing to translate,
   not three: the page swaps the whole of such an element at once when it
   can (`rich`), and the pieces stay as well for when it cannot. */
const rich = new Set();
const INLINE = /^(b|i|em|strong|code|kbd|br)$/i;
function richKey(text) {
  /* Tags reduced to their bare names; entities decoded; spaces folded. */
  let out = text.replace(/<\s*(\/?)\s*([a-z]+)[^>]*>/gi, (m, slash, name) =>
    INLINE.test(name) ? '<' + slash + name.toLowerCase() + '>' : '\u0002');
  if (out.indexOf('\u0002') >= 0) return '';
  out = out.replace(/<br>/g, '<br>');
  return fold(decode(out));
}

const ENT = {amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', bull: '•',
  mdash: '—', ndash: '–', hellip: '…', rarr: '→', larr: '←',
  middot: '·', times: '×', copy: '©', rsquo: '’', lsquo: '‘',
  ldquo: '“', rdquo: '”', '#39': "'"};
function decode(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, n) => {
    if (ENT[n] !== undefined) return ENT[n];
    if (n[0] === '#') {
      const code = n[1] === 'x' || n[1] === 'X' ? parseInt(n.slice(2), 16) : parseInt(n.slice(1), 10);
      return isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return m;
  });
}
function fold(s) { return s.replace(/\s+/g, ' ').trim(); }
/* Worth a translator's time: at least two letters in a row outside the
   placeholders, and not a lone placeholder. */
function worth(s) {
  const bare = s.replace(/\{\d+\}/g, '');
  if (!/[A-Za-z]{2}/.test(bare)) return false;
  /* A selector, a class list, an id, a URL, a field name: not words. */
  if (/^[#.\[]/.test(s) || /^(https?:|\/|\?api=|api=)/.test(s)) return false;
  if (/^[a-z0-9_]+(=|:)/.test(s) && !/\s/.test(s)) return false;
  if (/^[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*$/.test(s)) return false;     // camelCase
  if (/^[a-z0-9]+([_-][a-z0-9]+)+$/.test(s)) return false;              // snake / kebab
  return true;
}
function addRich(text) {
  if (!/<\s*\/?\s*(b|i|em|strong|code|kbd|br)\b/i.test(text)) return;
  const key = richKey(text);
  if (!key || !worth(key.replace(/<[^>]*>/g, ' '))) return;
  let n = 0;
  const map = {};
  const t = key.replace(/\{(\d+)\}/g, (m, k) => {
    if (map[k] === undefined) map[k] = n++;
    return '{' + map[k] + '}';
  });
  rich.add(t);
}
function add(text, js) {
  /* In the scripts a newline is a line break (`richText` turns it into a
     <br>); in the markup it is only the way the source is laid out. */
  if (!js) text = text.replace(/\s*\n\s*/g, ' ');
  addRich(text.replace(/\n/g, '<br>'));
  /* Inline tags split a sentence into the pieces the page holds as text;
     a line break (a newline turned into <br>) does the same. */
  const pieces = decode(text.replace(/<br\s*\/?>/gi, '\n')).split(/<[^>]*>|\n/);
  if (pieces.length > 1) {
    const whole = fold(decode(text.replace(/<[^>]*>/g, ' ')));
    if (whole && !/</.test(text)) put(whole);
  }
  pieces.forEach((p) => put(fold(p)));
}
function put(s) {
  if (!s || !worth(s)) return;
  /* Placeholders renumbered from nought in each piece. */
  let n = 0;
  const map = {};
  const t = s.replace(/\{(\d+)\}/g, (m, k) => {
    if (map[k] === undefined) map[k] = n++;
    return '{' + map[k] + '}';
  });
  if (/\{\d+\}/.test(t)) {
    /* Too little of its own to be found by: "{0} {1}", "{0}s". */
    const own = t.replace(/\{\d+\}/g, '').replace(/[^A-Za-z]/g, '');
    if (own.length < 3) return;
    patterns.add(t);
  } else {
    strings.add(t);
  }
}

/* ---- the HTML of the page, outside its scripts ---- */
const PHP = '\u0001';
const html = raw.replace(/<\?(?:php|=)?[\s\S]*?\?>/g, PHP)
  .replace(/<!--[\s\S]*?-->/g, ' ')
  .replace(/<script[\s\S]*?<\/script>/gi, ' ')
  .replace(/<style[\s\S]*?<\/style>/gi, ' ');
html.split(/(<[^>]*>)/).forEach((bit) => {
  if (bit[0] === '<') {
    for (const m of bit.matchAll(/\b(title|placeholder|aria-label|alt)="([^"]*)"/g)) {
      add(m[2].split(PHP).map((x, i) => (i ? '{' + (i - 1) + '}' : '') + x).join(''));
    }
    return;
  }
  if (!bit.trim()) return;
  let k = 0;
  add(bit.replace(new RegExp(PHP, 'g'), () => '{' + (k++) + '}'));
});

/* ...and every element of it holding only words and inline tags, whole. */
(function () {
  const stack = [];
  const VOID = /^(br|hr|img|input|meta|link|col|wbr|source|area|base|param|track|embed)$/i;
  const re = /<\s*(\/?)\s*([a-zA-Z0-9]+)[^>]*?(\/?)>/g;
  let m;
  while ((m = re.exec(html))) {
    const name = m[2].toLowerCase();
    if (m[1]) {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].name === name) {
          const inner = html.slice(stack[i].end, m.index);
          stack.length = i;
          if (/<\s*\/?\s*(b|i|em|strong|code|kbd|br)\b/i.test(inner)) {
            let k = 0;
            addRich(inner.replace(/\s*\n\s*/g, ' ')
              .replace(new RegExp(PHP, 'g'), () => '{' + (k++) + '}'));
          }
          break;
        }
      }
    } else if (!VOID.test(name) && !m[3]) {
      stack.push({name: name, end: re.lastIndex});
    }
  }
})();

/* ---- the JavaScript ---- */
const SKIP_ARGS = {
  $: [0], getElementById: [0], querySelector: [0], querySelectorAll: [0], closest: [0],
  matches: [0], el: [0, 1], createElement: [0], createElementNS: [0, 1], setAttribute: [0],
  getAttribute: [0], removeAttribute: [0], hasAttribute: [0], addEventListener: [0],
  removeEventListener: [0], api: [0], iconMarkup: [0], setButtonIcon: [1], cmdButton: [1, 2],
  add: [0], remove: [0], toggle: [0], contains: [0], getItem: [0], setItem: [0, 1],
  removeItem: [0], fetch: [0, 1], laneOf: [0], stopLane: [0], showTab: [0], showPane: [0],
  tShowPage: [0], sortMark: [1], startsWith: [0], endsWith: [0], indexOf: [0],
  lastIndexOf: [0], split: [0], join: [0], replace: [0], test: [0], match: [0],
  getPropertyValue: [0], setProperty: [0, 1], log: [0], error: [0], warn: [0],
  dirMark: [1, 2], tOpen: [1], goToRecords: [0, 1], postMessage: [0], execCommand: [0]
};
function calleeName(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed) return node.property.name;
  return '';
}
function flatten(node, out) {
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    flatten(node.left, out);
    flatten(node.right, out);
  } else if (node.type === 'Literal' && typeof node.value === 'string') {
    out.push({text: node.value});
  } else if (node.type === 'TemplateLiteral') {
    node.quasis.forEach((q, i) => {
      out.push({text: q.value.cooked});
      if (i < node.expressions.length) out.push({expr: true});
    });
  } else {
    out.push({expr: true});
  }
  return out;
}
function template(parts) {
  let k = 0, s = '';
  parts.forEach((p) => { s += p.expr ? '{' + (k++) + '}' : p.text.replace(/\{/g, '(').replace(/\}/g, ')'); });
  return s;
}

const flat = raw.replace(/<\?[\s\S]*?\?>/g, (m) => 'null' + '\n'.repeat((m.match(/\n/g) || []).length));
let blocks = 0;
for (const m of flat.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)) {
  blocks += 1;
  let ast;
  try {
    ast = acorn.parse(m[1], {ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true});
  } catch (e) {
    console.error('block ' + blocks + ': ' + e.message);
    continue;
  }
  const skip = new Set();
  walk.fullAncestor(ast, (node, ancestors) => {
    if (node.type === 'Property' && !node.computed && node.key.type === 'Literal') skip.add(node.key);
    if (node.type === 'MemberExpression' && node.computed && node.property.type === 'Literal') skip.add(node.property);
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const name = calleeName(node.callee);
      const which = Object.prototype.hasOwnProperty.call(SKIP_ARGS, name) ? SKIP_ARGS[name] : null;
      if (which) which.forEach((i) => { if (node.arguments[i]) skip.add(node.arguments[i]); });
    }
    if (node.type === 'BinaryExpression' && ['===', '!==', '==', '!=', 'in'].indexOf(node.operator) >= 0) {
      skip.add(node.left); skip.add(node.right);
    }
    if (node.type === 'SwitchCase' && node.test) skip.add(node.test);
  });
  walk.fullAncestor(ast, (node, ancestors) => {
    if (skip.has(node)) return;
    const parent = ancestors[ancestors.length - 2];
    const isPlus = node.type === 'BinaryExpression' && node.operator === '+';
    if (isPlus) {
      if (parent && parent.type === 'BinaryExpression' && parent.operator === '+') return;
      const parts = flatten(node, []);
      if (!parts.some((p) => !p.expr && /[A-Za-z]{2}/.test(p.text))) return;
      add(template(parts), true);
      return;
    }
    if (node.type === 'TemplateLiteral') {
      if (parent && parent.type === 'BinaryExpression' && parent.operator === '+') return;
      if (parent && parent.type === 'TaggedTemplateExpression') return;
      add(template(flatten(node, [])), true);
      return;
    }
    if (node.type === 'Literal' && typeof node.value === 'string') {
      if (parent && parent.type === 'BinaryExpression' && parent.operator === '+') return;
      if (ancestors.some((a) => skip.has(a))) return;
      add(node.value, true);
    }
  });
}
process.stdout.write(JSON.stringify({strings: [...strings].sort(), patterns: [...patterns].sort(),
                                     rich: [...rich].sort()}, null, 1));
console.error('%d block(s), %d string(s), %d pattern(s), %d rich', blocks, strings.size,
              patterns.size, rich.size);
