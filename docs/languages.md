# The languages of the page

From 1.10.153 the dashboard can be shown in a language other than English.
Each person chooses theirs under their name, top right → *Language*. The
choice is kept with their account and also in a cookie in that browser, so
the sign-in page is shown in it too.

English is what the page is written in. It is what everybody gets until
they choose something else, and it is what is left whenever anything below
is missing.

## Where the words are

```
/var/www/isemon/lang/en.json     English
/var/www/isemon/lang/cs.json     Czech
```

The folder is beside `index.php`, wherever the web directory is. Both
files come with every installation and upgrade. An upgrade replaces these
two and leaves any other file in the folder alone.

## What a file looks like

```json
{
 "_meta": {
  "code": "cs",
  "name": "Čeština",
  "english": "Czech",
  "version": "1.10.153",
  "made": "2026-10-02",
  "about": "..."
 },
 "strings": {
  "s.overview.5b4a1f2e": {"source": "Overview", "text": "Přehled"}
 },
 "patterns": {
  "p.0-row-s.1c2d3e4f": {"source": "{0} row(s)", "text": "{0} řádků"}
 },
 "rich": {
  "r.edit-the-columns-br-while.9a8b7c6d": {
   "source": "<b>Edit the columns</b><br>While this is on, ...",
   "text": "<b>Upravit sloupce</b><br>Když je tato volba zapnutá, ..."
  }
 }
}
```

- **`_meta`** is the file's header. It must come first and must not
  contain `{` or `}`, because the page reads only the start of each file to
  build the list of languages.
  - `code` is the language code and must match the file name (`cs` in
    `cs.json`).
  - `name` is the language in its own words; that is what the list shows.
  - `english` is its English name, shown beside it.
- **The ID** of a text is its first words plus a short hash of the exact
  English. The same English has the same ID in every version, so a
  translation stays where it belongs. English that changes gets a new ID.
- **`source`** is the English exactly as the page shows it. Never change
  it: the page finds the text by it.
- **`text`** is what to show instead. Empty means "show the English".
- **`strings`** are whole texts.
- **`patterns`** have `{0}`, `{1}` where the page puts a number, a name or
  another text. Every one must appear in the translation, in any order.
- **`rich`** are sentences with bold, code or line breaks in them. Keep
  the same tags. What is inside `<code>` stays as it is.

## What is never translated

- Data: names, addresses, MACs, anything in an input box, in code, in a
  monospaced cell, and what a device wrote in its own log.
- The daemon's log file, the stored events, the command line and these
  docs.

## Adding a language

1. Copy `cs.json` to e.g. `de.json`.
2. Set `_meta.code` to `de`, `name` to `Deutsch`, `english` to `German`.
3. Translate the `text` of each entry, or empty it to leave that one in
   English.
4. Put the file in the `lang` folder of the web directory. It appears in
   the list at the next page load; nothing needs restarting.

## Keeping a file up to date

From the source tree (needs `node` with `acorn` and `acorn-walk`):

```bash
NODE_PATH=/path/to/node_modules python3 tools/i18n/build.py
python3 tools/i18n/build.py --missing de      # what is not translated yet
```

`build.py` writes `en.json` afresh from the page and the daemon. It then
brings every other file up to it: a new text is added with an empty
`text`, and a text no longer used moves to `unused`, from where it comes
back if the English ever does. A translation is never lost.

## Getting back to English

Any of these is a complete way back:

1. Choose *English* under your name. The choice is per person.
2. Delete `cs.json`, or the whole `lang` folder, from the web directory.
   The page is then exactly what it was before languages existed. Nothing
   extra is loaded, and Czech is not even offered.
3. Install 1.10.152 again. Its database is unchanged. The one new table,
   `user_prefs`, is ignored by it.

A file that is broken (not valid JSON, `_meta` missing, a code that does
not match its name) is not offered. Anybody who had chosen it sees English.
