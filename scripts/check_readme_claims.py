#!/usr/bin/env python3
"""Assert every counted claim in README.md matches matrix.json.

The README states counts (tactics, techniques, attack classes, evidence tiers)
and coverage claims (detection, defensive control, lab scenario). Those are
measurements, not prose, so they are checked here and in CI rather than
maintained by hand.

The attack-class tables are a rendering of matrix.json.attackClasses, held
between the BEGIN/END GENERATED markers. Typed by hand, they reworded 34 of the
40 class descriptions and four of them described a different attack. The block
must re-render byte-identically; run with ``--fix`` to rewrite only that block.

The README also states figures about related projects. Those are measured in the
other project, so they are pinned in related-projects.json with the release and
commit each was read from, and every README line naming the project must state the
pinned number wherever it uses one of the wordings read here. For DVAA those are
"N agents", "N deliberately vulnerable", "N hardened reference", "N control-protected
variant(s)", "N vulnerable agent(s)" and "N categories", where up to two words, each a
run of ASCII letters and hyphens, may stand between the number and "categories". Each
is read in any letter case with one space between words; a figure worded any other way
is not checked. DVAA was described as "21 vulnerable agents" while DVAA labels one of
the 21 a hardened reference and four control-protected variants.

A line naming DVAA fails when it carries a format character (Unicode category Cf, such
as U+00AD SOFT HYPHEN or U+200B ZERO WIDTH SPACE), a control character (category Cc)
other than a tab, a Hangul filler (U+115F, U+1160, U+3164, U+FFA0), one of the
combining marks Unicode lists as default ignorable (U+034F, U+17B4, U+17B5, U+180B to
U+180D, U+180F, U+FE00 to U+FE0F, U+E0100 to U+E01EF) or one of the code points Unicode
lists as default ignorable without assigning them (U+2065, U+FFF0 to U+FFF8, U+E0000,
U+E0002 to U+E001F, U+E0080 to U+E00FF, U+E01F0 to U+E0FFF). Inside a wording such a
character keeps the wording from being read, and a Hangul filler or combining mark does
so directly beside a DVAA wording, while a character that renders as nothing leaves the
figure in the rendered line. A line names DVAA when it contains "DVAA" with no combining
mark (Unicode category M) directly after it once such characters are removed, either as
it then stands or after three more steps, so "DVAA" followed by U+0301 COMBINING ACUTE
ACCENT does not name DVAA. A mark counts as directly after "DVAA" only where it is
written as itself, not as a character reference, directly after a letter or another mark,
so "DV**AA**" U+20DD and "DVAA&#x20dd;" name DVAA. First, going along the line, its HTML
is removed wherever it stands, also where it starts inside a link destination or title
and ends after the ) that closes them: each comment, processing instruction, CDATA
section and declaration from its opening <!--, <?, <![CDATA[ or <! and an ASCII letter to
the first -->, ?>, ]]> or > after it, respectively, or to the end of the line when none
follows, and each tag from < or </ and a name, which is an ASCII letter followed by any
ASCII letters, digits and hyphens, to a > right after the name or, after / or a character
Unicode lists as white space (such as U+00A0 NO-BREAK SPACE), to the first > after that
if no < comes first. Where white space other than a space or tab follows a tag name, the
line is also read with only a space, a tab or / ending a tag name, and names DVAA when
either reading does. Second, going along what remains, each ] followed by ( is removed
with the text after it to the first ) if no further ( comes first, and each ] followed by
[ with the text after it to the first ] if no further [ comes first, whether or not they
make a link, then each ! directly before a [, and then the Markdown characters
* _ ~ ` \\ [ ]. Third, its character references are decoded, each to the characters it
stands for less any such character, so "&#8203;" (U+200B) leaves nothing, and it is
brought to NFKC with each character Unicode lists as confusable with A, D or V read as
that letter (U+0410 CYRILLIC CAPITAL LETTER A reads as A). So the name written as
"DV&#8203;AA", "**DV**AA", "DV<!-- -->AA", "<b>DV</b>AA", "[DV](url)AA",
"DV![](x.png)AA", "[DV](url "<b" U+00A0 "x=")AA" or in fullwidth letters does not take
the line out of the check, while "DV!AA" does not name DVAA. On a line that carries one
of the characters above, a combining mark after "DVAA" does not keep the line from naming
DVAA, so "DVAA" U+200B U+0301 names DVAA and the line fails on U+200B. A line that states
one of the matrix.json counts once such characters are removed fails the same way when it
carries one. Each failure names the line, the column of the character's first occurrence
on it, counted in characters from 1, and the character.

Exit 0 when every claim matches the data, 1 otherwise. ``--help`` (or ``-h``) prints
the usage and exits 0. Any other argument, such as a mistyped ``--fixx``, prints the
usage and exits 2 without checking or writing anything. Help takes precedence over an
argument the script does not know: given together in either order, as in
``--fixx --help`` or ``-h --bogus``, they print the usage and exit 0, again without
checking or writing anything.
"""

import argparse
import html
import json
import pathlib
import re
import sys
import unicodedata

# The docstring's first line, held apart so --help still works under python3 -OO.
DESCRIPTION = "Assert every counted claim in README.md matches matrix.json."

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
README = ROOT / "README.md"
RELATED = ROOT / "related-projects.json"

CLASS_BEGIN = "<!-- BEGIN GENERATED: attack-class-tables -->"
CLASS_END = "<!-- END GENERATED: attack-class-tables -->"

# Section labels for matrix.json attackClasses[].category. A category missing here
# is titled from its slug, so a new category still renders.
CATEGORY_LABELS = {
    "governance": "Governance",
    "supply-chain": "Supply Chain",
    "infrastructure": "Infrastructure",
    "nemoclaw": "NemoClaw-Specific",
    "identity": "Identity",
    "sandbox": "Sandbox",
}

# Letters (category Lo) that render as blank space. Each is a word character, so a DVAA
# wording directly beside one is not read, and neither is a matrix.json count wording
# bounded by \b, which does not hold between a filler and a digit or letter beside it.
HANGUL_FILLERS = (
    "\N{HANGUL CHOSEONG FILLER}\N{HANGUL JUNGSEONG FILLER}"
    "\N{HANGUL FILLER}\N{HALFWIDTH HANGUL FILLER}"
)

# The combining marks (category Mn) Unicode lists as default ignorable code points, which
# render as nothing: U+034F COMBINING GRAPHEME JOINER, two Khmer inherent vowels, the
# Mongolian free variation selectors and the variation selectors, 263 code points.
IGNORABLE_MARKS = frozenset(
    chr(code)
    for low, high in ((0x034F, 0x034F), (0x17B4, 0x17B5), (0x180B, 0x180D), (0x180F, 0x180F),
                      (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
    for code in range(low, high + 1)
)

# The code points Unicode lists as default ignorable without assigning them (category Cn):
# U+2065, U+FFF0 to U+FFF8 and the unassigned part of the tag and variation selector
# blocks, 3,769 code points. A renderer may draw one as nothing.
UNASSIGNED_IGNORABLES = frozenset(
    chr(code)
    for low, high in ((0x2065, 0x2065), (0xFFF0, 0xFFF8), (0xE0000, 0xE0000),
                      (0xE0002, 0xE001F), (0xE0080, 0xE00FF), (0xE01F0, 0xE0FFF))
    for code in range(low, high + 1)
)

# Raw HTML and text that only starts like it: a comment, processing instruction, CDATA
# section or declaration, each from its opening to the first close after that opening, or
# to the end of the line when none follows, and a tag from "<" or "</" and a name to a ">"
# right after the name or, after "/" or white space, to the first ">" before any "<".
# CommonMark reads a comment, processing instruction, CDATA section or declaration as raw
# HTML only when its close follows, on this line or a later one, so it shows "DV<!-- AA"
# or "DV<!X AA" as text when no line closes it. The tag alternative does not read
# attributes, so it also matches '<b x=")AA>' and '</b ")AA>', which CommonMark shows as
# text. White space is what \s matches: a space, a tab or any other character Unicode
# lists as white space, such as U+00A0 NO-BREAK SPACE, which CommonMark does not take
# inside a tag. An autolink such as <https://example.org> is not matched and stays. A tag
# ends at the first ">" before any "<", so a failed match scans no further than the next
# "<" and the pattern reads a line in linear time.
RAW_HTML = re.compile(
    r"<!--.*?(?:-->|$)|<\?.*?(?:\?>|$)|<!\[CDATA\[.*?(?:\]\]>|$)|<![A-Za-z][^>]*(?:>|$)"
    r"|</?[A-Za-z][A-Za-z0-9-]*(?:[\s/][^<>]*)?>"
)

# RAW_HTML with a tag name ending at a space, a tab, "/" or ">" only, so "<b" U+00A0 "x>" is
# not removed as a tag. The other ASCII white space characters are control characters,
# removed before a line is read.
SPACE_OR_TAB_HTML = re.compile(
    RAW_HTML.pattern.replace(r"(?:[\s/][^<>]*)?>", r"(?:[ \t/][^<>]*)?>"))

# A tag name followed by white space other than a space or tab, such as U+00A0 NO-BREAK
# SPACE: only on a line that holds one do RAW_HTML and SPACE_OR_TAB_HTML remove different
# text.
OTHER_SPACE_AFTER_TAG_NAME = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*[^\S \t]")

# A "]" followed by "(" with the text after it to the first ")" if no further "(" comes
# first, or a "]" followed by "[" with the text after it to the first "]" if no further "["
# comes first, whether or not they make a link: "[DV](url)AA" shows "DVAA".
LINK_TARGET = re.compile(r"\]\([^()]*\)|\]\[[^\[\]]*\]")

# A "!" directly before a "[", removed so that an image reads as its alternative text:
# "DV![](x.png)AA" names DVAA, while "DV!AA" does not.
IMAGE = re.compile(r"!(?=\[)")

# Markdown characters that mark up text without showing: emphasis, strikethrough, code
# span, escape and link text delimiters.
MARKUP = str.maketrans("", "", "*_~`\\[]")

# A control character, which no line read for the name holds, put before a combining mark
# written after something other than a letter or another mark, and before a character
# reference to a mark: "DVAA" `BREAK` U+20DD holds "DVAA" with no mark directly after it.
BREAK = "\x01"

# A named, decimal or hexadecimal character reference, as CommonMark reads one.
REFERENCE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")

# The characters Unicode lists as confusable with A, D, V or a run of them, other than
# those NFKC already maps to such letters: every code point whose UTS #39 skeleton in the
# confusables data of Unicode 17.0 is such a run and that NFKC leaves unchanged, 26 code
# points. With NFKC first, every code point whose skeleton is such a run reads as it.
CONFUSABLES = {
    0x0391: "A", 0x0410: "A", 0x0474: "V", 0x0667: "V", 0x06F7: "V", 0x13A0: "D",
    0x13AA: "A", 0x13D9: "V", 0x142F: "V", 0x15C5: "A", 0x15DE: "D", 0x15EA: "D",
    0x2D38: "V", 0xA4D3: "D", 0xA4E6: "V", 0xA4EE: "A", 0xA6DF: "V", 0xA732: "AA",
    0xA738: "AV", 0xA73A: "AV", 0x102A0: "A", 0x1051D: "V", 0x118A0: "V", 0x16F08: "V",
    0x16F40: "A", 0x1D20D: "V",
}


def is_mark(code):
    """Whether code point `code` is a combining mark (Unicode category M: Mn, Mc or Me).
    A value outside 0 to sys.maxunicode is no code point, so it is no mark."""
    return 0 <= code <= sys.maxunicode and unicodedata.category(chr(code)).startswith("M")


def combining_marks_in(text):
    """A regex character class body holding, as one range each, the runs of consecutive
    combining marks that hold a mark occurring in `text`. A mark that occurs nowhere in
    `text` can stand beside no wording in it, so the class need not hold every mark there
    is. Listed one by one, each mark outside the Basic Multilingual Plane is a separate
    entry that every test of the class walks; as runs, the class has no more ranges than
    a table of every mark."""
    ranges = []
    for code in sorted(ord(c) for c in set(text) if is_mark(ord(c))):
        if ranges and code <= ranges[-1][1]:
            continue
        lo = hi = code
        while is_mark(lo - 1):
            lo -= 1
        while is_mark(hi + 1):
            hi += 1
        ranges.append((lo, hi))
    return "".join(f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi in ranges)


def table_cell(text):
    """A matrix.json string as one Markdown table cell. A spaced em dash becomes a
    colon, as on the attack-classes/ pages, and a pipe is escaped."""
    return text.replace(" — ", ": ").replace("|", "\\|")


def render_class_tables(matrix):
    """The attack-class tables: one per category, in order of first appearance in
    matrix.json, classes sorted by id. Members are the techniques the class declares
    plus those whose primary attackClass is the class, as on the class pages."""
    primary = {}
    for t in matrix["techniques"]:
        primary.setdefault(t.get("attackClass"), set()).add(t["id"])

    by_category = {}
    for cls in matrix.get("attackClasses", []):
        by_category.setdefault(cls["category"], []).append(cls)

    sections = []
    for category, classes in by_category.items():
        label = CATEGORY_LABELS.get(category, category.replace("-", " ").title())
        noun = "class" if len(classes) == 1 else "classes"
        lines = [
            f"### {label} ({len(classes)} {noun})",
            "| Class | Description | Techniques |",
            "|-------|-------------|------------|",
        ]
        for cls in sorted(classes, key=lambda c: c["id"]):
            members = sorted(set(cls.get("techniques") or []) | primary.get(cls["id"], set()))
            lines.append(
                f"| [{cls['id']}](attack-classes/{cls['id']}.md) "
                f"| {table_cell(cls['description'])} | {', '.join(members)} |"
            )
        sections.append("\n".join(lines))
    return f"{CLASS_BEGIN}\n\n" + "\n\n".join(sections) + f"\n\n{CLASS_END}"


def class_block_span(readme):
    """(start, end) offsets of the generated block including its markers, or None
    unless each marker occurs exactly once, BEGIN first."""
    if readme.count(CLASS_BEGIN) != 1 or readme.count(CLASS_END) != 1:
        return None
    start = readme.index(CLASS_BEGIN)
    end = readme.index(CLASS_END)
    if end < start:
        return None
    return start, end + len(CLASS_END)


def check_class_tables(matrix, readme):
    """Failure lines for the generated attack-class block; empty when it is current."""
    span = class_block_span(readme)
    if span is None:
        return [
            f"README.md: the attack-class tables need exactly one '{CLASS_BEGIN}' "
            f"followed by exactly one '{CLASS_END}'"
        ]
    start, end = span
    have = readme[start:end].split("\n")
    want = render_class_tables(matrix).split("\n")
    first_line = readme.count("\n", 0, start) + 1
    for i, (h, w) in enumerate(zip(have, want)):
        if h != w:
            return [
                f"README.md:{first_line + i}: the attack-class tables differ from matrix.json "
                f"(expected \"{w}\"); run python3 scripts/check_readme_claims.py --fix"
            ]
    if len(have) != len(want):
        line = first_line + min(len(have), len(want))
        return [
            f"README.md:{line}: the attack-class tables have {len(have)} lines, matrix.json "
            f"renders {len(want)}; run python3 scripts/check_readme_claims.py --fix"
        ]
    return []


def fix_class_tables(matrix, readme):
    """README text with only the generated block re-rendered; unchanged when the
    markers are missing or out of order."""
    span = class_block_span(readme)
    if span is None:
        return readme
    start, end = span
    return readme[:start] + render_class_tables(matrix) + readme[end:]


def lines_naming(lines, naming):
    """The README with every line blanked that does not name DVAA, so a match offset still
    converts to its README line number. `lines` holds each README line as `classified`
    returns it, and `naming` whether `names` finds DVAA on it."""
    return "\n".join(line if named else "" for (line, _, _), named in zip(lines, naming))


def decoded(reference):
    """A character reference match as the characters it stands for, less those `hiding_kind`
    names: "&#8203;" stands for U+200B, which shows nothing."""
    return "".join(c for c in html.unescape(reference.group()) if not hiding_kind(c))


def nfkc(text):
    """`text` brought to NFKC, as unicodedata.normalize gives it, in O(n log n) time.
    unicodedata.normalize puts each run of characters with a nonzero canonical combining
    class in order by moving one character at a time, which takes quadratic time on a long
    run out of order: U+0301 U+0316 repeated to 100,000 characters took about 2 s. Here
    each character is decomposed alone, each such run is put in order by a stable sort on
    the combining class, and unicodedata.normalize composes the text, which is then already
    in order. ASCII text is its own NFKC."""
    if text.isascii():
        return text
    decomposed = "".join(unicodedata.normalize("NFKD", c) for c in text)
    ordered = []
    run = []
    for c in decomposed:
        if unicodedata.combining(c):
            run.append(c)
            continue
        ordered.extend(sorted(run, key=unicodedata.combining))
        run.clear()
        ordered.append(c)
    ordered.extend(sorted(run, key=unicodedata.combining))
    return unicodedata.normalize("NFKC", "".join(ordered))


def name_form(stripped, raw_html=RAW_HTML):
    """`stripped` as a name in it reads, by the three steps the module description states:
    the raw HTML `raw_html` matches removed, `RAW_HTML` unless another is given; each
    "](...)" and "][...]" span `LINK_TARGET` matches removed, whether or not it makes a
    link, then each "!" `IMAGE` matches, and the Markdown characters in `MARKUP`; then the
    character references decoded, less the characters `hiding_kind` names, and the text
    brought to NFKC with each character in `CONFUSABLES` read as the letters it resembles.
    The HTML is removed before the link spans, as HTML can start inside a link destination
    or title and end after the ")" that closes them, and the markup before the references
    are decoded, as a reference to "*" shows a star."""
    text = raw_html.sub("", stripped)
    text = IMAGE.sub("", LINK_TARGET.sub("", text)).translate(MARKUP)
    text = REFERENCE.sub(decoded, text)
    return nfkc(text).translate(CONFUSABLES)


def holds(text, name):
    """Whether `text` holds `name` at some place with no combining mark directly after it,
    so "DVAA" U+0301 does not hold DVAA and "DVAA" U+20DD " DVAA" does. Only a character
    after `name` outside ASCII has its category looked up; no ASCII character is a mark."""
    start = text.find(name)
    while start >= 0:
        after = text[start + len(name):start + len(name) + 1]
        if after.isascii() or not is_mark(ord(after)):
            return True
        start = text.find(name, start + 1)
    return False


def detached(stripped):
    """`stripped` with `BREAK` put before each combining mark that does not stand directly
    after a letter or another combining mark, and before each character reference to a
    combining mark. In "DV**AA**" U+20DD the mark stands after "*" and in "DVAA&#x20dd;" it
    is written as a reference, so each is put apart from the name, while in "DVAA" U+20DD
    it stays directly after it."""
    out = []
    i = 0
    while i < len(stripped):
        reference = REFERENCE.match(stripped, i) if stripped[i] == "&" else None
        piece = reference.group() if reference else stripped[i]
        shown = html.unescape(piece)[:1] if reference else piece
        if i and not shown.isascii() and is_mark(ord(shown)):
            if reference or not unicodedata.category(stripped[i - 1]).startswith(("L", "M")):
                out.append(BREAK)
        out.append(piece)
        i += len(piece)
    return "".join(out)


def names(stripped, name, hiding=False):
    """Whether a line that is `stripped` once the characters `hiding_kind` names are
    removed names `name`: it `holds` `name` as it stands or in its `name_form`, read with
    `RAW_HTML` and, where a tag name is followed by white space other than a space or
    tab, with `SPACE_OR_TAB_HTML` too. Where a name form holds `name` only with a
    combining mark directly after it or only once its letters are decomposed, the name
    form of the line `detached` is read too, so a mark counts only where it is written as
    itself directly after a letter or another mark: "DVAA" U+20DD does not name DVAA,
    while "DV**AA**" U+20DD and "DV**AA&#x20dd;**" do. "DV" U+200B "AA", "DV&#8203;AA",
    "**DV**AA", "DV<!-- -->AA", "DVA" U+0410 and the fullwidth letters each name DVAA;
    "DVAA" U+0301 does not. On a line that carried such a character, `hiding` true, a
    combining mark after `name` does not keep the line from naming it: removing the
    character can put a mark directly after the name, so "DVAA" U+200B U+0301 names
    DVAA."""
    def found(text):
        return name in text if hiding else holds(text, name)

    if found(stripped):
        return True
    readings = [RAW_HTML]
    if OTHER_SPACE_AFTER_TAG_NAME.search(stripped):
        readings.append(SPACE_OR_TAB_HTML)
    for raw_html in readings:
        form = name_form(stripped, raw_html)
        if found(form):
            return True
        decomposed = unicodedata.normalize("NFKD", form).translate(CONFUSABLES)
        if name in decomposed and found(name_form(detached(stripped), raw_html)):
            return True
    return False


def hiding_kind(c):
    """What `c` is when it fails a line that names DVAA or states a count, else None: a
    character that can keep a wording from being read."""
    category = unicodedata.category(c)
    if category == "Cf":
        return "a format character"
    if category == "Cc" and c != "\t":
        return "a control character"
    if c in HANGUL_FILLERS:
        return "a Hangul filler"
    if c in IGNORABLE_MARKS:
        return "a default-ignorable combining mark"
    if c in UNASSIGNED_IGNORABLES:
        return "an unassigned default-ignorable code point"
    return None


def classified(line):
    """(line, stripped, hidden) for `line`: `stripped` is `line` with every character
    `hiding_kind` names removed, and `hidden` holds (column, character) for the first
    occurrence of each such character, the column counted in characters from 1. One
    lookup per character gives both; a repeat of a character already found is removed
    without another."""
    stripped = []
    hidden = []
    seen = set()
    for column, c in enumerate(line, 1):
        if c in seen:
            continue
        if hiding_kind(c):
            seen.add(c)
            hidden.append((column, c))
        else:
            stripped.append(c)
    return line, "".join(stripped), hidden


def empty(value):
    """A mapping field counts as absent when null, empty, or all-empty strings."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple)):
        return all(empty(v) for v in value) if value else True
    return False


def main(argv):
    # An argument this script does not know ends the run with exit 2 before anything is
    # read or written: a mistyped --fix must not report the README as checked. argparse
    # acts on --help or -h where it stands and names the arguments it does not know only
    # once it has read them all, so help beside such an argument prints the usage and
    # exits 0; that run reads and writes nothing either.
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("--fix", action="store_true",
                        help="rewrite the attack-class tables in README.md from matrix.json")
    args = parser.parse_args(argv)

    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    readme = README.read_text(encoding="utf-8")

    if args.fix:
        fixed = fix_class_tables(matrix, readme)
        if fixed != readme:
            README.write_text(fixed, encoding="utf-8")
            readme = fixed
            print("FIXED: rewrote the attack-class tables from matrix.json")
        else:
            print("OK: attack-class tables already current")

    tactics = matrix["tactics"]
    techniques = matrix["techniques"]
    classes = matrix.get("attackClasses", [])

    tiers = {}
    for t in techniques:
        tiers[t.get("evidenceTier")] = tiers.get(t.get("evidenceTier"), 0) + 1

    with_detection = sum(1 for t in techniques if not empty(t.get("hmaChecks")))
    with_control = sum(1 for t in techniques if not empty(t.get("oasbControls")))
    with_lab = sum(1 for t in techniques if not empty(t.get("dvaaValidation")))

    total = len(techniques)
    failures = []

    def require(pattern, expected, label, text=readme, source="matrix.json", stated=True,
                flags=0):
        """The README states this wording at least once, and every occurrence carries
        the measured number(s).

        `pattern` captures each stated number as a group, in the order of `expected`.
        Checking every occurrence, rather than that the right number appears
        somewhere, is what catches a count repeated in a second section (Use cases,
        Purpose) going stale while the first copy still matches. `text` is the README
        or a line-preserving subset of it; with `stated=False` the wording may be
        absent, but any occurrence must still carry the measured number(s).
        """
        want = tuple(str(v) for v in expected)
        found = list(re.finditer(pattern, text, flags))
        if not found and stated:
            failures.append(f"README does not state {label} ({', '.join(want)})")
        for m in found:
            if m.groups() != want:
                line = text.count("\n", 0, m.start()) + 1
                failures.append(
                    f"README.md:{line}: \"{m.group(0)}\" does not match {source} "
                    f"({label}: {', '.join(want)})"
                )

    count_wordings = []

    def count(pattern, expected, label):
        """`require` for a matrix.json count, which any README line may state."""
        count_wordings.append(pattern)
        require(pattern, expected, label)

    observed = tiers.get("observed", 0)
    validated = tiers.get("validated", 0)
    adapted = tiers.get("adapted", 0)

    count(r"\b(\d+) tactics\b", [len(tactics)], "tactics")
    count(r"\*\*(\d+) techniques\*\*", [total], "techniques")
    count(r"\b(\d+) tactics and (\d+) techniques\b", [len(tactics), total],
          "tactics and techniques")
    count(r"\b(\d+) attack classes\b", [len(classes)], "attack classes")
    count(r"\*\*(\d+) attack classes\*\*", [len(classes)], "attack classes")

    # Evidence tiers, in the overview wording and in the Use cases wording.
    count(r"\*\*(\d+) techniques with real-world evidence\*\*", [observed], "observed")
    count(r"\b(\d+) of the (\d+) techniques carry real-world evidence\b",
          [observed, total], "observed of total")
    count(r"\*\*(\d+) techniques validated in controlled lab environments\*\*",
          [validated], "validated")
    count(r"\b(\d+) are validated in controlled lab environments\b", [validated],
          "validated")
    count(r"\*\*(\d+) techniques adapted from traditional environments\*\*",
          [adapted], "adapted")
    count(r"\b(\d+) are adapted from traditional environments\b", [adapted], "adapted")

    # Coverage claims. Detection and defensive control are stated as universal,
    # so they must actually hold for every technique. The lab-scenario claim is
    # stated as a ratio because it does not.
    if with_detection != total:
        gaps = [t["id"] for t in techniques if empty(t.get("hmaChecks"))]
        failures.append(
            f"README claims every technique maps to automated detection, "
            f"but {total - with_detection} do not: {gaps}"
        )
    if with_control != total:
        gaps = [t["id"] for t in techniques if empty(t.get("oasbControls"))]
        failures.append(
            f"README claims every technique maps to a defensive control, "
            f"but {total - with_control} do not: {gaps}"
        )
    count(
        r"\b(\d+) of the (\d+) (?:also )?carry a reproducible lab scenario\b",
        [with_lab, total],
        "lab scenario of total",
    )

    failures.extend(check_class_tables(matrix, readme))

    # Related-project figures, read only from the README lines that name the project.
    related = json.loads(RELATED.read_text(encoding="utf-8"))
    dvaa = related["dvaa"]
    kinds = {kind: entry["count"] for kind, entry in dvaa["agentsByKind"].items()}
    if sum(kinds.values()) != dvaa["agents"]:
        failures.append(
            f"related-projects.json: dvaa.agentsByKind counts sum to {sum(kinds.values())}, "
            f"dvaa.agents is {dvaa['agents']}"
        )
    # Each README line is classified once: the lookups that find the characters failing a
    # line also give the line with such characters removed, which decides whether it names
    # DVAA.
    lines = [classified(line) for line in readme.split("\n")]
    naming = [names(stripped, "DVAA", bool(hidden)) for _, stripped, hidden in lines]
    dvaa_lines = lines_naming(lines, naming)
    pinned = "related-projects.json"
    # Every DVAA wording is read in any letter case: DVAA itself writes "Attack Categories".
    # re.ASCII keeps that to ASCII letters and digits: without it "[A-Za-z]" also matches
    # U+0130, U+0131, U+017F (long s) and U+212A (Kelvin sign), and an "i" or "s" in a
    # wording matches the first three. re.ASCII would also narrow \b to ASCII word
    # characters and read "é21 agents" as "21 agents". A Unicode \b is not enough either:
    # it counts no combining mark as a word character, so "é" written as "e" and U+0301
    # was read. Each wording is bounded instead by the absence of a Unicode word character
    # or a combining mark on either side: a wording glued to a letter, digit or combining
    # mark of any script is not read. Both bounds stay inside the pattern, so that where
    # one start position matches at several lengths ("13 categories x categories" holds
    # "13 categories") a mark glued to the longer wording leaves the shorter one read.
    # The mark part of the class is built from the DVAA lines alone, not from every code
    # point: a mark that stands on none of them can stand beside no wording. It holds each
    # run of consecutive marks that has a mark on those lines, so it is never larger than
    # a table of every mark.
    on_dvaa_lines = dict(text=dvaa_lines, source=pinned, flags=re.IGNORECASE | re.ASCII)
    glue = r"(?u:[\w" + combining_marks_in(dvaa_lines) + r"])"

    def wording(words):
        """The pattern for "N <words>", with no Unicode word character and no combining
        mark directly before or after it."""
        return r"(?<!" + glue + r")(\d+) " + words + r"(?!" + glue + r")"

    require(wording("agents"), [dvaa["agents"]], "DVAA agents", **on_dvaa_lines)
    require(wording("deliberately vulnerable"), [kinds["deliberatelyVulnerable"]],
            "DVAA deliberately vulnerable agents", **on_dvaa_lines)
    require(wording("hardened reference"), [kinds["hardenedReference"]],
            "DVAA hardened reference agents", **on_dvaa_lines)
    require(wording("control-protected variants?"), [kinds["controlProtectedVariant"]],
            "DVAA control-protected variants", **on_dvaa_lines)
    # "N vulnerable agents" counts only the agents DVAA labels vulnerable.
    require(wording("(?:deliberately )?vulnerable agents?"), [kinds["deliberatelyVulnerable"]],
            "DVAA vulnerable agents", stated=False, **on_dvaa_lines)
    # The count is read under any name: "N categories" with up to two words, each a run
    # of ASCII letters and hyphens, between the number and the noun.
    require(wording("(?:[A-Za-z-]+ ){0,2}categories"), [dvaa["vulnerabilityCategories"]],
            "DVAA vulnerability categories", **on_dvaa_lines)

    # A wording is not read when a character `hiding_kind` names stands inside it ("age"
    # U+00AD "nts", "22" U+200B " agents", "tac" U+00AD "tics"), or when a Hangul filler or
    # combining mark is glued to a DVAA wording (U+3164 "22 agents", "agents" U+034F), so
    # the character fails the line instead of leaving its figure unchecked. That holds for
    # every line that names DVAA or states a matrix.json count once such characters are
    # removed: "DV" U+200B "AA" names DVAA, and "8 tac" U+00AD "tics" states a count the
    # check cannot read.
    for number, ((line, stripped, hidden), named) in enumerate(zip(lines, naming), 1):
        if not hidden:
            continue
        readers = []
        if named:
            readers.append(("naming DVAA", "DVAA"))
        if any(re.search(pattern, stripped) for pattern in count_wordings):
            readers.append(("stating a matrix.json count", "count"))
        if not readers:
            continue
        where = " and ".join(phrase for phrase, _ in readers)
        wordings = " and ".join(name for _, name in readers)
        for column, c in hidden:
            label = " ".join(filter(None, (f"U+{ord(c):04X}", unicodedata.name(c, ""))))
            failures.append(
                f"README.md:{number}:{column}: a line {where} carries {label}, "
                f"{hiding_kind(c)}, which can hide a figure from the {wordings} wordings; "
                f"remove it"
            )

    dvaa_summary = (
        f"DVAA {dvaa['sourceVersion']}: {dvaa['agents']} agents "
        f"({', '.join(f'{k}={v}' for k, v in kinds.items())}), "
        f"{dvaa['vulnerabilityCategories']} vulnerability categories"
    )

    tier_total = sum(tiers.values())
    if tier_total != total:
        failures.append(
            f"evidence tiers sum to {tier_total}, expected {total} "
            f"(every technique needs exactly one tier; got {tiers})"
        )

    if failures:
        print("README claims do not match matrix.json and related-projects.json:\n",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\nmeasured: {len(tactics)} tactics, {total} techniques, "
            f"{len(classes)} attack classes, tiers={tiers}, "
            f"detection={with_detection}/{total}, control={with_control}/{total}, "
            f"lab={with_lab}/{total}\npinned: {dvaa_summary}",
            file=sys.stderr,
        )
        return 1

    print(
        f"README claims match matrix.json: {len(tactics)} tactics, {total} techniques, "
        f"{len(classes)} attack classes, tiers={tiers}, "
        f"detection={with_detection}/{total}, control={with_control}/{total}, "
        f"lab={with_lab}/{total}; and related-projects.json: {dvaa_summary}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
