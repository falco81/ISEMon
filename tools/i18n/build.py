#!/usr/bin/env python3
"""web/lang/en.json made afresh from what the page and the daemon can show,
and every other language file brought up to it.

Not part of the program: a tool for whoever updates the language files.

    NODE_PATH=/path/to/node_modules python3 tools/i18n/build.py

Each text has an ID made of what it says (its first words) and a short hash
of its exact English: the same English is the same ID in every version, so a
translation made once stays where it belongs, and English that changes is a
new ID to translate. A language file keeps everything it has, the texts no
longer used included (under `unused`, so they come back if the English does);
what it has not translated yet is listed by `--missing`.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(os.path.dirname(HERE))
LANG = os.path.join(TREE, 'web', 'lang')
sys.path.insert(0, TREE)


def slug(text, most=6):
    words = re.findall(r'[a-z0-9]+', re.sub(r'\{\d+\}|<[^>]*>', ' ', text.lower()))
    return '-'.join(words[:most]) or 'text'


def ident(kind, text):
    digest = hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]
    return '%s.%s.%s' % (kind, slug(text), digest)


def version():
    for line in open(os.path.join(TREE, 'isemon.py'), encoding='utf-8'):
        m = re.match(r"__version__ = '([^']+)'", line)
        if m:
            return m.group(1)
    return ''


# What the page writes as a string but never shows as words: lengths and
# colours for a style, and anything with no two letters in a row.
NOT_WORDS = re.compile(r'^[^A-Za-z]*$|^[^A-Za-z]*[A-Za-z]?[^A-Za-z]*$'
                       r'|^-?[\d.]+(px|em|rem|vh|vw|ms|s|%)\b|var\(--|rgba?\(|calc\(')


def extract():
    js = subprocess.run(['node', os.path.join(HERE, 'extract.js'),
                         os.path.join(TREE, 'web', 'index.php')],
                        capture_output=True, text=True, check=True)
    py = subprocess.run([sys.executable, os.path.join(HERE, 'extract_py.py'),
                         os.path.join(TREE, 'isemon.py')],
                        capture_output=True, text=True, check=True)
    a, b = json.loads(js.stdout), json.loads(py.stdout)
    out = {}
    for kind, key in (('s', 'strings'), ('p', 'patterns'), ('r', 'rich')):
        for text in sorted(set(a.get(key, [])) | set(b.get(key, []))):
            if not NOT_WORDS.search(text):
                out[ident(kind, text)] = {'source': text}
    return out


SECTIONS = (('s', 'strings'), ('p', 'patterns'), ('r', 'rich'))


def load(path):
    try:
        return json.load(open(path, encoding='utf-8'))
    except FileNotFoundError:
        return None


def write(path, meta, entries, unused):
    data = {'_meta': meta}
    for kind, name in SECTIONS:
        data[name] = {k: v for k, v in sorted(entries.items()) if k.startswith(kind + '.')}
    if unused:
        data['unused'] = dict(sorted(unused.items()))
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.write('\n')


def main():
    os.makedirs(LANG, exist_ok=True)
    found = extract()
    ver = version()
    # English: the text is the source, unless somebody has changed it in the
    # file - then theirs stays.
    old_en = load(os.path.join(LANG, 'en.json')) or {}
    had = {}
    for _kind, name in SECTIONS:
        had.update(old_en.get(name, {}))
    en = {}
    for k, v in found.items():
        text = (had.get(k) or {}).get('text') or v['source']
        en[k] = {'source': v['source'], 'text': text}
    write(os.path.join(LANG, 'en.json'),
          {'code': 'en', 'name': 'English', 'english': 'English', 'version': ver,
           'made': time.strftime('%Y-%m-%d'),
           'about': 'The words of the dashboard in English. Every other language file has the '
                    'same IDs. Change "text", never "source": the source is what the page is '
                    'looked through for.'}, en, {})
    print('en.json: %d text(s)' % len(en))
    for fname in sorted(os.listdir(LANG)):
        if not fname.endswith('.json') or fname == 'en.json':
            continue
        path = os.path.join(LANG, fname)
        data = load(path) or {}
        have = {}
        for _kind, name in SECTIONS + (('u', 'unused'),):
            have.update(data.get(name, {}))
        entries, missing = {}, 0
        for k, v in found.items():
            mine = have.pop(k, None)
            if mine and mine.get('text'):
                entries[k] = {'source': v['source'], 'text': mine['text']}
            else:
                entries[k] = {'source': v['source'], 'text': ''}
                missing += 1
        meta = dict(data.get('_meta') or {})
        meta['version'] = ver
        write(path, meta, entries, {k: v for k, v in have.items() if v.get('text')})
        print('%s: %d text(s), %d not translated yet' % (fname, len(entries), missing))


if __name__ == '__main__':
    if '--missing' in sys.argv:
        lang = sys.argv[sys.argv.index('--missing') + 1]
        data = load(os.path.join(LANG, lang + '.json')) or {}
        for _kind, name in SECTIONS:
            for k, v in data.get(name, {}).items():
                if not v.get('text'):
                    print(json.dumps({'id': k, 'source': v['source']}, ensure_ascii=False))
    else:
        main()
