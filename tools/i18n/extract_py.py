#!/usr/bin/env python3
"""The words the daemon hands the page to show, found in isemon.py.

Not part of the program: a tool for whoever updates the language files. The
settings' names and what each one says, the words for where a value comes
from and for each choice, and the sentences an answer of the API carries
when something is refused (`fail`, `Refused`) or explained (`says`,
`message`). Printed as JSON in the shape `extract.js` prints.

    python3 tools/i18n/extract_py.py isemon.py
"""
import ast
import json
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'isemon.py'
tree = ast.parse(open(path, encoding='utf-8').read())
strings, patterns, rich = set(), set(), set()
INLINE = re.compile(r'<\s*/?\s*(b|i|em|strong|code|kbd|br)\b', re.I)


def fold(s):
    return re.sub(r'\s+', ' ', s).strip()


def worth(s):
    bare = re.sub(r'\{\d+\}', '', s)
    if not re.search(r'[A-Za-z]{2}', bare):
        return False
    if re.match(r'^[a-z0-9]+([_-][a-z0-9]+)+$', s):
        return False
    return True


def put(s):
    if not s or not worth(s):
        return
    seen = {}
    s = re.sub(r'\{(\d+)\}', lambda m: '{%d}' % seen.setdefault(m.group(1), len(seen)), s)
    if re.search(r'\{\d+\}', s):
        own = re.sub(r'[^A-Za-z]', '', re.sub(r'\{\d+\}', '', s))
        if len(own) >= 3:
            patterns.add(s)
    else:
        strings.add(s)


def add(text):
    """As `richText` shows it: a newline is a line break, <b> and <code>
    are tags; the whole, and the pieces between."""
    if INLINE.search(text) or '\n' in text:
        key = fold(re.sub(r'<\s*(/?)\s*([a-z]+)[^>]*>', lambda m: '<%s%s>' % (m.group(1),
                          m.group(2).lower()), text.replace('\n', '<br>')))
        if INLINE.search(key) and worth(re.sub(r'<[^>]*>', ' ', key)):
            seen = {}
            rich.add(re.sub(r'\{(\d+)\}',
                            lambda m: '{%d}' % seen.setdefault(m.group(1), len(seen)), key))
    put(fold(re.sub(r'<[^>]*>', ' ', text)))
    for piece in re.split(r'<[^>]*>|\n', text):
        put(fold(piece))


def template(node):
    """A string out of an expression: literals as they are, anything else
    as {0}, {1}...; None when there is no literal in it."""
    parts = []

    def walk(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(('s', n.value))
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) \
                and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
            bits = re.split(r'(%(?:\([a-z_]+\))?[-#0 +]*\d*(?:\.\d+)?[sdirf%])', n.left.value)
            for b in bits:
                if re.match(r'^%(?:\([a-z_]+\))?[-#0 +]*\d*(?:\.\d+)?[sdirf]$', b):
                    parts.append(('x', None))
                elif b == '%%':
                    parts.append(('s', '%'))
                elif b:
                    parts.append(('s', b))
        elif isinstance(n, ast.JoinedStr):
            for v in n.values:
                if isinstance(v, ast.Constant):
                    parts.append(('s', v.value))
                else:
                    parts.append(('x', None))
        else:
            parts.append(('x', None))
    walk(node)
    if not any(k == 's' and re.search(r'[A-Za-z]{2}', v) for k, v in parts):
        return None
    out, k = '', 0
    for kind, v in parts:
        if kind == 's':
            out += v.replace('{', '(').replace('}', ')')
        else:
            out += '{%d}' % k
            k += 1
    return out


TABLES = {'NAMES', 'SAYS', 'WHERE_FROM', 'CHOICE_WORDS', 'FEEDS', 'BAN_MODE_WORDS',
          'OTP_SAYS', 'OTP_MODES', 'CODE_UNUSED_WORDS'}
KEYS = {'says', 'message', 'words', 'said_words', 'source_says', 'why', 'fix_says'}

for node in ast.walk(tree):
    # The tables of words: every string value in them, however deep.
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in TABLES
                                            for t in node.targets):
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Dict):
                for v in sub.values:
                    t = template(v) if v is not None else None
                    if t:
                        add(t)
            elif isinstance(sub, (ast.Tuple, ast.List)):
                for v in sub.elts:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and ' ' in v.value:
                        add(v.value)
    # What a refusal says.
    if isinstance(node, ast.Call):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else '')
        if name in ('fail', 'Refused', 'StorageError') and node.args:
            t = template(node.args[0])
            if t:
                add(t)
    # ...and what an answer explains.
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value in KEYS and v is not None:
                t = template(v)
                if t:
                    add(t)

# Keys and arguments that hold words for the page only some of the time - a
# `name` is as often a column or a file - so only where the value is plainly
# words: a few of them, with a space, and nothing that looks like a path.
PROSE_KEYS = {'name', 'about', 'what', 'note', 'label', 'title', 'hint', 'reason', 'detail',
              'help', 'explain', 'text', 'summary', 'tip', 'holds'}


def prose(v):
    return (isinstance(v, ast.Constant) and isinstance(v.value, str)
            and re.search(r'[a-z]{2,}\s+[a-z]{2,}', v.value) and '/' not in v.value
            and not re.search(r'[=%{}\\]|\.(py|json|log|sql|php)\b', v.value))


for node in ast.walk(tree):
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value in PROSE_KEYS and v is not None:
                for one in (v.body, v.orelse) if isinstance(v, ast.IfExp) else (v,):
                    if prose(one):
                        add(one.value)
                    elif isinstance(one, ast.BinOp) and isinstance(one.op, ast.Mod) \
                            and prose(one.left):
                        t = template(one)
                        if t:
                            add(t)
    if isinstance(node, ast.Call):
        for kw in node.keywords:
            if kw.arg in PROSE_KEYS and prose(kw.value):
                add(kw.value.value)

# Functions that put the daemon's own sentences together for the page - how
# a ban is earned, how long it lasts, what the firewall log is: everything
# worded in them.
WORDING = {'blocking_words', 'trigger_words', 'block_steps', 'fwlog_words', 'watch_words',
           'refusal_words_on', 'directory_words', 'burst_words', 'beat_words', 'ago_words',
           'radius_words', 'dump_words_for', 'roll_said', 'what_directory_says',
           'country_says', 'base_words', 'trouble_words'}


def worded(v):
    return re.search(r'[A-Za-z]{2,}\s+[A-Za-z]{2,}', v) and not re.search(
        r'^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE)\b|\.(py|json|log|sql|php)\b', v)


for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in WORDING:
        # Not its docstring: that is for whoever reads the code.
        doc = (node.body[0].value if node.body and isinstance(node.body[0], ast.Expr)
               and isinstance(node.body[0].value, ast.Constant) else None)
        for sub in ast.walk(node):
            if sub is doc:
                continue
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod) \
                    and isinstance(sub.left, ast.Constant) and isinstance(sub.left.value, str):
                t = template(sub)
                if t and worded(t):
                    add(t)
            elif isinstance(sub, ast.JoinedStr):
                t = template(sub)
                if t and worded(t):
                    add(t)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and worded(sub.value) and '%' not in sub.value:
                add(sub.value)

print(json.dumps({'strings': sorted(strings), 'patterns': sorted(patterns),
                  'rich': sorted(rich)}, indent=1, ensure_ascii=False))
print('%d string(s), %d pattern(s), %d rich' % (len(strings), len(patterns), len(rich)),
      file=sys.stderr)
