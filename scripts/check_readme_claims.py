#!/usr/bin/env python3
"""Assert every counted claim in README.md and its pages matches matrix.json.

The README states counts (tactics, techniques, attack classes, evidence tiers)
and coverage claims (detection, defensive control, lab scenario). Those are
measurements, not prose, so they are checked here and in CI rather than
maintained by hand.

README.md hands its reference text to the pages PAGES lists after it: the purpose and
scope to docs/overview.md, the attack-class tables to docs/attack-classes.md, the
cross-framework mapping with the related-project figures to
docs/cross-framework-mapping.md, and the evidence-tier table to docs/evidence-tiers.md,
among others. The check reads README.md and those pages
as one text, in that order, each page ending in a line break: a claim may stand on any of
them, every occurrence on any of them is checked, and each failure names the page and its
line there. A page PAGES lists that does not exist fails the check. Below, "the README"
is README.md together with those pages.

The attack-class tables are a rendering of matrix.json.attackClasses, held
between the BEGIN/END GENERATED markers, both on one page, with each link written
relative to that page. Typed by hand, they reworded 34 of the 40 class descriptions
and four of them described a different attack. The block must re-render
byte-identically; run with ``--fix`` to rewrite only that block.

The per-tactic table and the evidence-tier table are measurements over matrix.json too.
A tactic row is read where a line starts ``| [Name](tactics/<id>.md) | N | N |``, and a
tier row where a line starts ``| **Tier** |`` and ends ``| N (P%) |`` with nothing after
the last "|", each spaced exactly as shown; a row written any other way is not read. Each
tactic row read must state the tactic's name, kill chain stage and technique count, and
each tier row read its technique count and that count as a whole percentage of all
techniques, rounded half up; a row read that names no tactic or tier, a second row read for
one, and a tactic or tier with no row read each fail. The "## Attack Classes (N)" heading
must state the number of attack classes.

The README also states figures about related projects. Those are measured in the
other project, so they are pinned in related-projects.json with the release each was
read from, and for DVAA the commit, and every README line naming DVAA must state the
pinned number wherever it uses one of the wordings read here. For DVAA those are
"N agents", "N deliberately vulnerable", "N hardened reference", "N control-protected
variant(s)", "N vulnerable agent(s)" and "N categories", where up to two words, each a
run of ASCII letters and hyphens, may stand between the number and "categories". Each
is read in any letter case with one space between words; a figure worded any other way
is not checked. DVAA was described as "21 vulnerable agents" while DVAA labels one of
the 21 a hardened reference and four control-protected variants.

The HackMyAgent and OASB figures are pinned in related-projects.json too, with the
HackMyAgent release they were read from, and are read on every README line: "N static
checks" and "N payloads" or "N attack payloads" must state the pinned HackMyAgent figures,
and "N controls" and "N domains" the pinned OASB figures. Each wording is read in the
letter case written here. The README stated 310 static checks after HackMyAgent 0.33.2
reported 318, and no check read the figure.

A line naming DVAA fails when it carries a format character (Unicode category Cf, such
as U+00AD SOFT HYPHEN or U+200B ZERO WIDTH SPACE), a control character (category Cc)
other than a tab, a Hangul filler (U+115F, U+1160, U+3164, U+FFA0), one of the
combining marks Unicode lists as default ignorable (U+034F, U+17B4, U+17B5, U+180B to
U+180D, U+180F, U+FE00 to U+FE0F, U+E0100 to U+E01EF) or one of the code points Unicode
lists as default ignorable without assigning them (U+2065, U+FFF0 to U+FFF8, U+E0000,
U+E0002 to U+E001F, U+E0080 to U+E00FF, U+E01F0 to U+E0FFF). Inside a wording such a
character keeps the wording from being read, and a Hangul filler or combining mark does
so directly beside a DVAA wording, while a character that renders as nothing leaves the
figure in the rendered line. A line names DVAA when it contains "DVAA" once such
characters are removed, either as it then stands or after three more steps, with no
combining mark (Unicode category M) directly after it that NFKC joins to the last A. So
"DVAA" followed by U+0301 COMBINING ACUTE ACCENT, which NFKC joins to the A as U+00C1,
does not name DVAA, nor does "DVAA" followed by U+0332 COMBINING LOW LINE and U+0301,
while "DVAA" followed by U+0332, U+0335 COMBINING SHORT STROKE OVERLAY, U+0338 COMBINING
LONG SOLIDUS OVERLAY or U+20DD COMBINING ENCLOSING CIRCLE, which NFKC leaves apart from
the A, names DVAA. A mark counts as directly after "DVAA" only where it is written as
itself, not as a character reference, directly after a letter or another mark, and a mark
that does not is kept apart from the name, so that NFKC in the third step below does not
join it to the last A: "DV**AA**" U+0301, "DVAA&#x301;", "DV**AA**&#x301;" and
"DV**AA&#x301;**" name DVAA, while NFKC alone gives "DVA" U+00C1. First, going along the
line, its HTML is removed wherever it stands, also where it starts inside a link
destination or title
and ends after the ) that closes them: each comment, processing instruction, CDATA
section and declaration from its opening <!--, <?, <![CDATA[ or <! and an ASCII letter to
the first -->, ?>, ]]> or > after it, respectively, or to the end of the line when none
follows, and each tag from < or </ and a name, which is an ASCII letter followed by any
ASCII letters, digits and hyphens, to a > right after the name or, after / or a character
Unicode lists as white space (such as U+00A0 NO-BREAK SPACE), to the first > after that
if no < comes first. Where white space other than a space or tab follows a tag name, the
line is also read with only a space, a tab or / ending a tag name. Where a character other
than an ASCII letter, digit, hyphen, tab, line feed, form feed, space, / or > follows a tag
name, such as \\, < or U+00A0, or where a tab, line feed, form feed, space or / follows a
tag name and a < follows that before any >, the line is also read as a browser reads a tag
in an HTML block, with a name that is an ASCII letter followed by any characters other
than a tab, line feed, form feed, space, / and >, the six characters at which a browser
ends a tag name, so that U+00A0 and U+3000 IDEOGRAPHIC SPACE do not end one, and after the
name and a tab, line feed, form feed, space or / a tag runs to the first > after it, past
any <, which a browser reads there as part of an attribute name or value: "DV<x\\>AA",
"D<D\\\\</b>VAA", "DV<x" U+00A0 "<y>AA", "DV<a <b>AA" and "D<a <b" U+00A0 "D<x\\>VAA"
name DVAA. Where / or white space follows a tag
name and a " or ' follows that before any < or >, the line is also read with each " or '
in a tag after that / or white space passed over whole with the text up to the next such
quote on the line, as an attribute value in quotes, which CommonMark and a browser read
past any < or > it holds: a tag then runs to the first > that stands in no such value if
no < that stands in none comes first, so "DV<b x="<">AA" and "DV<b title='>'>AA" name
DVAA. A quote that no such quote follows on the line is read there as any other
character. Where & stands directly before #, the line is also read as a browser reads an
HTML block: its tags are read as a browser reads them, as above, and each numeric
character reference, & and # followed by one or more ASCII digits or by x or X and one or
more hexadecimal digits, with a ; directly after the last digit where one stands, is
decoded in the first step where it stands as written, with or without the ; and whatever
its number of digits, and what it stands for, less any such character, is kept as text. As
a browser reads a reference before it reads any tag, its digits end at the first character
after them that is not such a digit in the line as written, such as < or *, so
"&#x30<b>D<x\\>VAA" reads "0DVAA" and names DVAA, as do "DVA&#65", "DVA&#x41" and
"DVA&#00000065;", where CommonMark reads a reference only with the ; and at most seven
decimal or six hexadecimal digits and shows each of the three as written in a paragraph.
No such reference starts inside HTML or a code span, or at an escaped &. Each of these
readings is also made with the text of each style, script and
template element removed, as a browser shows none of it: going along the line, a start
tag removed as above whose name is style, script or template opens that element unless a
style or script element is open, and an end tag removed as above closes the element
opened last where it has that element's name, each name read in any ASCII letter case and,
whichever reading removed the tag, as the HTML block reading reads a tag name, to the
first tab, line feed, form feed, space, / or >; where a start tag opens an element while
none is open, what stands from that start tag to the end of the end tag that closes the
element, or to the end of the line where none does, is removed. So "DV<style>x</style>AA",
"DV<script>x</script>AA", "DV<template>x</template>AA" and
"DV<template><template></template>x</template>AA" name DVAA, while
"DV<style>x</script>AA", "DV<style" U+00A0 ">x</style>AA" and "DV<style>x</style" U+00A0
">AA" do not. The line names DVAA when any reading does. On the way, as
CommonMark reads them, the character a \\ escapes and
the text of a code span are kept as text, which no later step reads as markup, HTML, a
link span or a character reference, and the \\ and the backticks around the code span are
removed. A \\ escapes the ASCII punctuation character directly after it and stays before
any other character. A run of backticks, or where a \\ escapes a backtick the run that
starts after it, opens a code span that the next run of as many backticks on the line
closes, and the text between them loses one space at each end when it starts and ends
with a space and holds another character. No HTML starts inside a code span or at an
escaped <, and no escape or code span starts inside HTML. So "DV\\*AA" and "`DV*AA`" read
"DV*AA" and do not name DVAA, as "DV&#42;AA" does not, while "` DV `AA" names DVAA. Going
along the line, no code span is read from the first of these places on, where a backtick
after it could be read another way, and each backtick from there is removed with the
Markdown characters in the second step: a code span whose text holds a |, which starts
another cell in a table row, or a < or &, which a browser reads in an HTML block as the
start of a tag or a character reference; a < at which HTML starts, read with any white
space ending a tag name, that holds a backtick, ' or ", or that runs to the end of the
line with no close; any other < followed by an ASCII character other than a space or tab,
when no > follows it or a backtick, ' or " stands between it and the first > after it;
and a ] followed by ( or [ when no ) or ] follows it with no further ( or [ first, or
when a backtick, ', ", \\ or < stands between them. No code span is read on a line that
carries one of the characters above, nor on the lines after a line on which, read with no
link label removed as below, code spans are not read or stop being read, or that holds a
run of backticks that no run closes, up to a blank line (empty or of spaces and tabs
only): a code span, HTML or link span still open at the end of that line could close on
one of them. Going along the line, where a ] that no \\ escapes and that stands in no code
span or HTML is directly followed by a link label, the [ and the text after it to the
first ] that no \\ escapes, with no [ that no \\ escapes before that ], as CommonMark bounds
a label though of any length, the ] is removed with the label when the label is blank,
empty or of white space only, or one that the page holding the line defines, and no HTML,
escape, code span or reference decoded in the first step starts inside the label;
otherwise the ] stays, and the [ and what
follows it are read on. A page defines a label where, once such characters are removed, it
holds a [ that no \\ escapes followed by that label and ]:, two labels being the same when
they are after Unicode case folding, with white space at either end removed and each run
of white space inside read as one space. A page holding a definition-like text that
CommonMark does not read as a definition, such as one in a fenced code block, defines the
label here too. Where a ] is so directly followed by a [, the line is also read with no
label removed and, where two or three labels the page defines stand directly after a ] on
it, with each other mix of them removed and kept, and it names DVAA when any of its
readings does. A line holding four or more such labels is read with all of them removed
and with none and, where one to three of them are labels the page defines on no
definition line, with each other mix of those removed and kept and the others removed. A
definition-like text stands on a definition line where its [ starts a line, after at most
three spaces, outside a fenced code block: so "[t]: x" does as a line of its own, also
after one to three spaces, while "`[t]: x`", "[t]: x" after four spaces or a tab, and
"[t]: x" on a line in a fenced code block do not. A fenced code block runs from a line
that, after at most three spaces, starts with a run of three or more backticks with no
backtick after it on the line, or of three or more tildes, to the first later line that
is, after at most three spaces, a run of that character at least as long followed by
nothing but spaces and tabs, or to the end of the page. So "[x][DV](url)AA", which
CommonMark shows as "[x]DVAA" where the page does not define the label DV, names DVAA, as
does "[x][DV](u)[A][t]A" on a page that defines t, with DV only in a fenced code block,
which CommonMark shows as "[x]DVAA", and "[x][DV](u)[A][t]A [y][a] [z][b]" on such a page
that also defines a and b, which CommonMark shows as "[x]DVAA y z", while "[DV][dvaa]AA"
names DVAA only where the page defines the label dvaa. Second, going along
what remains, each ] followed by ( is removed with the text after
it to the first ) if no further ( comes first, whether or not they make a link, then each
! directly before a [, and then the Markdown characters * _ ~ ` [ ]. Third, its character
references are
decoded, each to the characters it stands for less any such character, so "&#8203;"
(U+200B) leaves nothing, and it is
brought to NFKC with each character Unicode lists as confusable with A, D or V read as
that letter (U+0410 CYRILLIC CAPITAL LETTER A reads as A). So the name written as
"DV&#8203;AA", "**DV**AA", "DV<!-- -->AA", "<b>DV</b>AA", "[DV](url)AA",
"DV![](x.png)AA", "[DV](url "<b" U+00A0 "x=")AA>" or in fullwidth letters does not take
the line out of the check, while "DV!AA" does not name DVAA. On a line that carries one
of the characters above, a combining mark after "DVAA" does not keep the line from naming
DVAA, so "DVAA" U+200B U+0301 names DVAA and the line fails on U+200B. A line that states
one of the matrix.json counts once such characters are removed fails the same way when it
carries one. Each failure names the line, the column of the character's first occurrence
on it, counted in characters from 1, and the character.

The matrix version is read where the README states it as "Version N", as on the line under
the title, or as "Threat Matrix vN", as in the framework citation, each in the letter case
written here, where N is digits separated by dots, such as 1.2. Every occurrence must state
the version in matrix.json as written there, and the README must state the second wording.
On a line holding either wording, each English month name followed by a space and a
four-digit year, such as "September 2026", must be the month and year that CHANGELOG.md gives the
release of that version: the date on the first line of CHANGELOG.md that is "## v", that
version, characters other than digits and a date written YYYY-MM-DD, where a version that
differs only by trailing ".0" parts is the same version (v1.2.0 for 1.2). A line holding
either wording once the characters above are removed fails when it carries one of them, as
a line stating a count does. A version or month worded any other way is not read.

A technique id is "T-" and digits, with an optional "." and digits, such as T-2001, with no
ASCII letter or digit directly before or after it, so "T-1XXX" is not read. Every id on
README.md and its pages, in code as in prose, must be the id of a technique in matrix.json.
Where an id is followed by a space and a parenthesis, as in "T-2001 (Direct Prompt
Injection)", the text up to the first ")" must be that technique's name in matrix.json.
Where an id directly follows a space and "(", as in "Indirect Prompt Injection (T-2002,
initial access, observed in the wild)", the text before them on the line must end with the
technique's name, with no letter, digit, "_" or "-" directly before the name, and each item
after the id up to the ")", each starting ", ", is read: an item that is a tactic name in
any letter case must be the technique's tactic, and an item whose first word is an evidence
tier in any letter case must be the technique's tier. The README must state the technique
citation, "Threat Matrix " and an id. On a line holding it, every id must be the cited one,
so the link names the technique cited, and each four digits standing as a year, as in
"OpenA2A, 2026.", with no ASCII letter, digit, ".", "/" or "-" directly before them and no
ASCII letter, digit, "/", "-", or "." and a digit, directly after them, must be the year
CHANGELOG.md gives the release of the matrix version, read as for the month. A line holding
an id once the characters above are removed fails when it carries one of them, as a line
stating a count does. An id, name, tactic, tier or year written any other way is not read.

The STIX version is read where the README states it as "STIX N", as in "ships as a STIX 2.1
bundle", in the letter case written here, where N is digits separated by dots with no ASCII
letter or digit, or "." and a digit, directly after it. Every occurrence must be the
spec_version that the objects of stix/agent-threat-matrix-bundle.json carry; the check fails
when that file is missing or its objects carry more than one spec_version, and a README that
does not state the STIX version passes. A line holding the wording once the characters above
are removed fails when it carries one of them, as a line stating a count does. A STIX version
worded any other way is not read.

Exit 0 when every claim matches the data, 1 otherwise. ``--help`` (or ``-h``) prints
the usage and exits 0. Any other argument, such as a mistyped ``--fixx``, prints the
usage and exits 2 without checking or writing anything. Help takes precedence over an
argument the script does not know: given together in either order, as in
``--fixx --help`` or ``-h --bogus``, they print the usage and exit 0, again without
checking or writing anything. A read of matrix.json that raises an OSError, a ValueError or
a RecursionError (see ``read_matrix``) is reported in one line on standard error,
``matrix.json is missing or does not parse: <reason>``, and the run exits 1 without
checking or writing anything. So is a matrix.json that parses but does not hold what this
check needs from it (see ``SHAPE``), in the line
``matrix.json parses but has the wrong shape: <reason>``: an object whose ``techniques``
array holds objects with a string ``id`` and ``name`` and a ``tactic``, ``attackClass`` and
``evidenceTier`` that are each absent, null or a string, whose ``tactics`` array holds
objects with a string ``id`` and ``name`` and an ``order``, and whose ``attackClasses``, when
present, is an array of objects with a string ``id``, ``category`` and ``description`` and
``techniques`` that are absent, null or an array of strings.
"""

import argparse
import bisect
import html
import itertools
import json
import pathlib
import re
import string
import sys
import unicodedata

# The docstring's first line, held apart so --help still works under python3 -OO.
DESCRIPTION = "Assert every counted claim in README.md and its pages matches matrix.json."

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix.json"
RELATED = ROOT / "related-projects.json"
CHANGELOG = ROOT / "CHANGELOG.md"
# The committed STIX bundle, whose objects carry the spec_version the README states.
STIX_BUNDLE = ROOT / "stix" / "agent-threat-matrix-bundle.json"

# README.md and the pages that took its reference text, read as one text in this order.
PAGES = (
    "README.md",
    "docs/overview.md",
    "docs/use-cases.md",
    "docs/attack-classes.md",
    "docs/cross-framework-mapping.md",
    "docs/attack-paths.md",
    "docs/evidence-tiers.md",
    "docs/schema.md",
    "CONTRIBUTING.md",
)

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

# The evidence tiers, each with one row in the README evidence-tier table.
TIERS = ("observed", "validated", "adapted")

# Related-project figures other than DVAA's, read on every README line: the project and
# field each is pinned under in related-projects.json, and the wording that states it.
RELATED_WORDINGS = (
    ("hackmyagent", "staticChecks", r"\b(\d+) static checks\b"),
    ("hackmyagent", "attackPayloads", r"\b(\d+) (?:attack )?payloads\b"),
    ("oasb", "controls", r"\b(\d+) controls\b"),
    ("oasb", "domains", r"\b(\d+) domains\b"),
)

# The wordings that state the matrix version, each with whether the README must state it:
# the line under the title ("**Version 1.2**") and the framework citation.
VERSION_WORDINGS = (
    (r"\bVersion (\d+(?:\.\d+)*)", False),
    (r"\bThreat Matrix v(\d+(?:\.\d+)*)", True),
)
MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August",
          "September", "October", "November", "December")
MONTH_YEAR = re.compile(r"\b(" + "|".join(MONTHS) + r") (\d{4})\b")
# A CHANGELOG.md release heading, "## v1.2.0 (2026-09-08)": its version, and the year and
# month of the first date after it.
RELEASE_HEADING = re.compile(r"(?m)^## v(\d+(?:\.\d+)*)(?!\d)[^\n\d]*(\d{4})-(\d{2})-\d{2}")
# The STIX version as the README states it, "STIX 2.1", with no ASCII letter or digit, or
# "." and a digit, directly after it, so "STIX 2.1a" is not read as 2.
STIX_VERSION = re.compile(r"\bSTIX (\d+(?:\.\d+)*)(?![A-Za-z0-9]|\.\d)")

# A technique id as the README writes one, "T-2001" or "T-2001.001", with no ASCII letter or
# digit directly before or after it: "T-1XXX" in CONTRIBUTING.md is not an id.
TECHNIQUE_ID = re.compile(r"(?<![A-Za-z0-9])T-\d+(?:\.\d+)?(?![A-Za-z0-9])")
# The technique citation, "AI Agent Threat Matrix T-2001 (...)": the id it cites.
TECHNIQUE_CITATION = re.compile(r"\bThreat Matrix (" + TECHNIQUE_ID.pattern + ")")
# A technique id followed by a space and a parenthesis, "T-2001 (Direct Prompt Injection)":
# the text in it, which names the technique.
NAME_AFTER = re.compile(r" \(([^()]*)\)")
# The items after a technique id that opens a parenthesis, "(T-2002, initial access,
# observed in the wild)": each ", " and the text after it, up to the ")" that closes it.
ITEMS_AFTER = re.compile(r"((?:, [^,()]+)*)\)")
# A four-digit year on its own, "OpenA2A, 2026.": no ASCII letter, digit, ".", "/" or "-"
# directly before it, and no ASCII letter, digit, "/" or "-", or a "." and a digit, after.
YEAR = re.compile(r"(?<![A-Za-z0-9./-])\d{4}(?![A-Za-z0-9/-]|\.\d)")

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
# text, while it ends a tag at a ">" in a quoted attribute value and finds no tag where a
# "<" in one comes first, as in '<b x="<">', which QUOTED_HTML reads as a tag. White space
# is what \s matches: a space, a tab or any other character Unicode lists as white space,
# such as U+00A0 NO-BREAK SPACE, which CommonMark does not take inside a tag. An autolink
# such as <https://example.org> is not matched and stays. A tag ends at the first ">"
# before any "<", so a failed match scans no further than the next "<" and the pattern
# reads a line in linear time.
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

# RAW_HTML with a tag read as a browser reads one in an HTML block: a tag name of an ASCII
# letter followed by any characters other than a tab, line feed, form feed, space, "/" and
# ">", where those six characters alone end a tag name, and after the name and a tab, line
# feed, form feed, space or "/", the text to the first ">", past any "<", which a browser
# reads there as part of an attribute name or value. "<x\>" is a tag named "x\", "<D\\</b>"
# a tag named "d\\<" with an attribute "b", "<x" U+00A0 "<y>" a tag named "x" U+00A0 "<y",
# and "<a <b>" a tag named "a" with an attribute "<b", so "DV<x\>AA", "D<D\\</b>VAA",
# "DV<x" U+00A0 "<y>AA" and "DV<a <b>AA" between "<div>" and "</div>" show "DVAA". After the
# name, only a tab, line feed, form feed, space or "/" lets the tag run on to a ">", so a
# match takes the name to the first of the six: no shorter name is followed by one of them.
# A tag ends at the first ">" after it, as RAW_HTML ends one, also where that ">" stands in
# a quoted attribute value, which QUOTED_HTML passes over.
HTML_BLOCK_HTML = re.compile(RAW_HTML.pattern.replace(
    r"[A-Za-z0-9-]*(?:[\s/][^<>]*)?>", r"[^\t\n\f />]*(?:[\t\n\f /][^>]*)?>"))

# A tag name followed by a character other than an ASCII letter, digit, hyphen, tab, line
# feed, form feed, space, "/" or ">", such as "\", "<" or U+00A0 NO-BREAK SPACE, and a tag
# name followed by a tab, line feed, form feed, space or "/" and then by a "<" before any
# ">": only on a line that holds one of the two do RAW_HTML and HTML_BLOCK_HTML remove
# different text.
OTHER_CHARACTER_IN_TAG_NAME = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*[^A-Za-z0-9\t\n\f />-]")
LESS_THAN_AFTER_TAG_NAME = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*[\t\n\f /][^<>]*<")

# The tag name HTML_BLOCK_HTML reads from its first letter.
HTML_BLOCK_TAG_NAME = re.compile(r"[^\t\n\f />]*")


class HtmlBlockHtml:
    """The HTML `HTML_BLOCK_HTML` matches, with `match` as a compiled pattern has it, read
    over a line in linear time. A tag there, from "<" or "</" and an ASCII letter, runs past
    any "<" in its name and attributes to the first ">" after it, so it finds a ">" exactly
    where one stands after its "<" on the line: a tag after the last ">" finds none, and
    looked for from each "<" on a line of "<a", every look would scan to the end of the
    line. Where the last ">" of the line stands is held for the line last read, and a tag
    after it is not looked for. That place turns on the line alone, so one instance gives
    what the pattern gives however many times it reads a line, and also in readings that
    pass over different parts of the line, as the reading that removes a link label passes
    over the label and the reading that removes none does not: `names` reads a line with one
    instance in each of its label readings, and in the readings that remove the text of
    style, script and template elements."""

    def __init__(self):
        self.text, self.last = None, -1

    def match(self, text, pos):
        letter = pos + 2 if text.startswith("</", pos) else pos + 1
        if letter < len(text) and text[letter] in string.ascii_letters:
            if text is not self.text:
                self.text, self.last = text, text.rfind(">")
            if self.last < pos:
                return None
        return HTML_BLOCK_HTML.match(text, pos)


# RAW_HTML with each '"' or "'" in a tag after the "/" or white space that follows its name
# passed over whole with the text up to the next such quote, as an attribute value in
# quotes, which CommonMark and a browser read past any "<" or ">" it holds: '<b x="<">' and
# "<b title='>'>" are tags, so 'DV<b x="<">AA' and "DV<b title='>'>AA" show "DVAA". A quote
# that no such quote follows on the line is read as any other character, so '<b x=")AA>' is
# removed as RAW_HTML removes it. A quote is read so wherever it stands in a tag, not only
# after an "=" as CommonMark reads a value: read only there, a tag that starts inside a
# quoted value of another can fall into step with it and read the rest of the line again,
# and a line of 120,010 characters built so took about 17 s.
QUOTED_HTML = re.compile(RAW_HTML.pattern.replace(
    r"[\s/][^<>]*", r"""[\s/](?:[^<>"']|"[^"]*"|'[^']*'|"(?![^"]*")|'(?![^']*'))*"""))

# A tag name followed by "/" or white space and then, before any "<" or ">", by a quote:
# only on a line that holds one do RAW_HTML and QUOTED_HTML remove different text.
QUOTE_AFTER_TAG_NAME = re.compile(r"""</?[A-Za-z][A-Za-z0-9-]*[\s/][^<>"']*["']""")

# The elements a browser shows no text of, named in lower case: a style or script element
# holds raw text, which runs to an end tag of its name, and the content of a template
# element is not rendered. "DV<style>x</style>AA" shows "DVAA".
HIDDEN_ELEMENTS = frozenset({"style", "script", "template"})

# The elements of HIDDEN_ELEMENTS that hold raw text, inside which no tag opens an element:
# in "<style><template></style>" the template is text, and so is the first "</template>" in
# "<template><style></template></style></template>", where the last end tag closes the
# template.
RAW_TEXT_ELEMENTS = frozenset({"style", "script"})

# "<" or "</" and the name of a tag that RAW_HTML, SPACE_OR_TAB_HTML, HTML_BLOCK_HTML or
# QUOTED_HTML matches, read whichever pattern matched the tag as HTML_BLOCK_HTML reads a tag
# name, with HTML_BLOCK_TAG_NAME after its first letter: an ASCII letter followed by any
# characters other than a tab, line feed, form feed, space, "/" and ">", the six characters
# at which a browser ends one. RAW_HTML and QUOTED_HTML also end a name at U+00A0 NO-BREAK
# SPACE or U+3000 IDEOGRAPHIC SPACE, and a tag either removes there is named past that
# character: "<style" U+00A0 ">" opens no style element, and "</style" U+00A0 ">" closes
# none, which a browser reads as text inside a style element.
TAG_START = re.compile(r"<(/?)([A-Za-z]" + HTML_BLOCK_TAG_NAME.pattern + ")")

# A "<" followed by the name of an element in HIDDEN_ELEMENTS, in any ASCII letter case: a
# line that holds none holds no start tag of one, and the reading that removes their text
# reads it as the others do.
HIDDEN_ELEMENT_START = re.compile(r"<(?:style|script|template)", re.IGNORECASE | re.ASCII)

# A "]" followed by "(" with the text after it to the first ")" if no further "(" comes
# first, which the second step removes whether or not they make a link: "[DV](url)AA" shows
# "DVAA".
PAREN_SPAN = re.compile(r"\]\([^()]*\)")

# PAREN_SPAN, or a "]" followed by "[" with the text after it to the first "]" if no further
# "[" comes first: where a "]" followed by "(" or "[" starts neither, or the one it starts
# holds a character in LINK_UNSURE, the first step stops reading code spans. Whether a "]"
# followed by "[" is removed with the label after it is read apart from this (`label_end`).
LINK_TARGET = re.compile(PAREN_SPAN.pattern + r"|\]\[[^\[\]]*\]")

# The most labels the page defines, each directly after a "]", that a line can hold for
# `label_removals` to read it with every mix of them removed and kept, which is at most
# 2 to the power of this many readings of the line; and, on a line holding more, the most
# of them in `unsure_labels` for it to read the line with every mix of those removed and
# kept and the others removed.
MIXED_LABELS = 3

# A line that opens or closes a fenced code block where `unsure_labels` reads one: up to
# three spaces, a run of three or more backticks or tildes, and the rest of the line. A
# backtick run opens a block only where the rest of its line holds no backtick, and a run
# closes the open block only where it is of that block's character, at least as long as
# the run that opened it, with nothing but spaces and tabs in the rest of its line.
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")

# A "!" directly before a "[", removed so that an image reads as its alternative text:
# "DV![](x.png)AA" names DVAA, while "DV!AA" does not.
IMAGE = re.compile(r"!(?=\[)")

# Markdown characters that mark up text without showing: emphasis, strikethrough, code
# span and link text delimiters. A backslash is not one: the first step removes each that
# escapes a character, and any other shows.
MARKUP = str.maketrans("", "", "*_~`[]")

# The ASCII punctuation characters, which a backslash escapes.
PUNCTUATION = frozenset(string.punctuation)

# Each printable ASCII character other than the space mapped to its fullwidth form, U+FF01
# to U+FF5E. The first step writes what it keeps as text in these forms, which no later
# step reads as markup, HTML, a link span or a character reference, and NFKC in the third
# step brings each back to the ASCII character.
AS_TEXT = {code: code + 0xFEE0 for code in range(0x21, 0x7F)}

# A run of backticks.
BACKTICKS = re.compile(r"`+")

# The characters that stop code spans being read where they stand in the text of a code
# span: a "|" starts another cell in a table row, and in an HTML block a browser reads a
# "<" as the start of a tag and a "&" as the start of a character reference.
SPAN_UNSURE = frozenset("|<&")

# The characters that stop code spans being read where they stand in HTML, or between a
# "<" that starts none and the first ">" after it: a backtick there could open a code span
# or stand inside HTML, and a quote could hold a ">" that does not end a tag.
HTML_UNSURE = frozenset("`'\"")

# The characters that stop code spans being read where they stand between a "](" and the
# first ")" after it, or a "][" and the first "]": a link title, an escaped parenthesis
# or a destination in "<" and ">" can run past that ")".
LINK_UNSURE = frozenset("`'\"\\<")

# The kinds of HTML that run to the end of the line when no close follows, each as its
# opening and close; the declaration comes last, as "<!" opens the others too.
HTML_CLOSES = (("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>"), ("<!", ">"))

# A control character, which no line read for the name holds, put before a combining mark
# written after something other than a letter or another mark, and before a character
# reference to a mark: "DVAA" `BREAK` U+20DD holds "DVAA" with no mark directly after it.
BREAK = "\x01"

# A named, decimal or hexadecimal character reference, as CommonMark reads one.
REFERENCE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")

# A decimal or hexadecimal character reference of any number of digits, the closing ";"
# optional, as a browser reads a numeric character reference in an HTML block: between
# "<div>" and "</div>", "DVA&#65" and "DVA&#x41" show "DVAA", while CommonMark shows each
# as written in a paragraph. A browser reads it where it stands as written, before any tag
# is read, so its digits end at the first character after them that is not such a digit:
# "&#x30<b>D<x\>VAA" shows "0DVAA", where "<" ends "&#x30".
HTML_BLOCK_REFERENCE = re.compile(r"&#(?:[0-9]+|[xX][0-9A-Fa-f]+);?")

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


def render_class_tables(matrix, base=""):
    """The attack-class tables: one per category, in order of first appearance in
    matrix.json, classes sorted by id. Members are the techniques the class declares
    plus those whose primary attackClass is the class, as on the class pages. `base`
    leads each link from the page holding the tables to the repository root ("../" for a
    page in docs/)."""
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
                f"| [{cls['id']}]({base}attack-classes/{cls['id']}.md) "
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


class Pages:
    """README.md and each page in PAGES that exists, read as one text: each page in turn,
    each ending in a line break, so no line of one page runs into the next. A line of the
    text is named by its page and its line on that page."""

    def __init__(self, root):
        self.names, self.texts, self.missing = [], [], []
        for name in PAGES:
            path = root / name
            if path.is_file():
                self.names.append(name)
                self.texts.append(path.read_text(encoding="utf-8"))
            else:
                self.missing.append(name)
        parts = [text if text.endswith("\n") else text + "\n" for text in self.texts]
        self.starts, self.first_lines = [], []
        offset, line = 0, 1
        for part in parts:
            self.starts.append(offset)
            self.first_lines.append(line)
            offset += len(part)
            line += part.count("\n")
        self.text = "".join(parts)

    def page_of(self, offset):
        """The index of the page holding the character at `offset` of the text."""
        return bisect.bisect_right(self.starts, offset) - 1

    def where(self, line):
        """Line `line` of the text as "<page>:<line on that page>"."""
        i = bisect.bisect_right(self.first_lines, line) - 1
        return f"{self.names[i]}:{line - self.first_lines[i] + 1}"


def link_base(name):
    """The path from page `name` to the repository root: "" for README.md, "../" for a
    page in docs/."""
    return "../" * name.count("/")


def class_block(pages):
    """(page index, start, end) of the generated block, offsets in `pages.text` including
    its markers, or None unless each marker occurs exactly once, BEGIN first, both on one
    page."""
    span = class_block_span(pages.text)
    if span is None or pages.page_of(span[0]) != pages.page_of(span[1] - 1):
        return None
    return (pages.page_of(span[0]), *span)


def check_class_tables(matrix, pages):
    """Failure lines for the generated attack-class block; empty when it is current."""
    block = class_block(pages)
    if block is None:
        return [
            f"README.md and the pages in PAGES: the attack-class tables need exactly one "
            f"'{CLASS_BEGIN}' followed by exactly one '{CLASS_END}', both on one page"
        ]
    page, start, end = block
    have = pages.text[start:end].split("\n")
    want = render_class_tables(matrix, link_base(pages.names[page])).split("\n")
    first_line = pages.text.count("\n", 0, start) + 1
    for i, (h, w) in enumerate(zip(have, want)):
        if h != w:
            return [
                f"{pages.where(first_line + i)}: the attack-class tables differ from "
                f"matrix.json (expected \"{w}\"); run python3 scripts/check_readme_claims.py --fix"
            ]
    if len(have) != len(want):
        line = first_line + min(len(have), len(want))
        return [
            f"{pages.where(line)}: the attack-class tables have {len(have)} lines, matrix.json "
            f"renders {len(want)}; run python3 scripts/check_readme_claims.py --fix"
        ]
    return []


def fix_class_tables(matrix, pages):
    """(page, text): the page holding the generated block and its text with only the block
    re-rendered; None when the markers are missing, out of order or on two pages."""
    block = class_block(pages)
    if block is None:
        return None
    page, start, end = block
    text, offset = pages.texts[page], pages.starts[page]
    rendered = render_class_tables(matrix, link_base(pages.names[page]))
    return pages.names[page], text[:start - offset] + rendered + text[end - offset:]


def lines_naming(lines, naming):
    """The README with every line blanked that does not name DVAA, so a match offset still
    converts to its README line number. `lines` holds each README line as `classified`
    returns it, and `naming` whether `names` finds DVAA on it."""
    return "\n".join(line if named else "" for (line, _, _), named in zip(lines, naming))


def span_lines(lines):
    """For each README line, as `classified` returns it, whether code spans are read on it:
    not on the lines after one on which code spans are not read or stop being read, or that
    holds a run of backticks no run closes, up to a blank line, one that is empty or holds
    only spaces and tabs as written. A code span, HTML or link span still open at the end of
    such a line could close on a later line of its paragraph. A line that carries a
    character `hiding_kind` names reads no code span, which `names` sees to, and so leaves
    the lines after it with none read too. Each line is read with no link label removed,
    which leaves code spans unread wherever removing any of the labels the page defines
    would."""
    reads, open_ = [], False
    for line, stripped, hidden in lines:
        if not line.strip(" \t"):
            open_ = False
        reads.append(not open_)
        if not open_:
            open_ = step_one(stripped, spans=not hidden)[1]
    return reads


def page_labels(pages, lines):
    """For each README line, as `classified` returns it, (labels, unsure): the link labels
    that the page holding it defines (`defined_labels`), and those of them that it defines
    only in definition-like texts CommonMark may not read as definitions (`unsure_labels`),
    each read from that page's lines with the characters `hiding_kind` names removed: a
    link reference definition holds on its own page only, as each page is a document of
    its own."""
    labels = []
    starts = [first - 1 for first in pages.first_lines] + [len(lines)]
    for start, end in zip(starts, starts[1:]):
        text = "\n".join(stripped for _, stripped, _ in lines[start:end])
        labels.extend([(defined_labels(text), unsure_labels(text))] * (end - start))
    return labels or [(frozenset(), frozenset())] * len(lines)


def reference_text(reference):
    """The characters that `reference`, a character reference as `REFERENCE` or
    `HTML_BLOCK_REFERENCE` matches one, stands for, as html.unescape gives them. A numeric
    reference is read with its leading zeros dropped, and one with more digits left than
    U+10FFFF has, seven decimal or six hexadecimal, stands for U+FFFD, as html.unescape gives
    for a number past U+10FFFF: html.unescape reads the digits with int, which by default
    refuses a decimal string of more than 4,300 digits, and `HTML_BLOCK_REFERENCE` matches a
    reference of any length."""
    if not reference.startswith("&#"):
        return html.unescape(reference)
    hexadecimal = reference[2:3] in ("x", "X")
    digits = reference[3 if hexadecimal else 2:].rstrip(";").lstrip("0") or "0"
    if len(digits) > (6 if hexadecimal else 7):
        return "\N{REPLACEMENT CHARACTER}"
    return html.unescape(f"&#{'x' if hexadecimal else ''}{digits};")


def decoded(reference):
    """A character reference match as the characters it stands for (`reference_text`), less
    those `hiding_kind` names: "&#8203;" stands for U+200B, which shows nothing."""
    return "".join(c for c in reference_text(reference.group()) if not hiding_kind(c))


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


def unclosed(found):
    """Whether `found`, HTML `RAW_HTML` matches, is a comment, processing instruction, CDATA
    section or declaration that runs to the end of the line because no close follows its
    opening. "<!-->" ends in "-->", but no close follows its opening "<!--"."""
    for opening, close in HTML_CLOSES:
        if found.startswith(opening):
            return not (found.endswith(close) and len(found) >= len(opening) + len(close))
    return False


def label_end(text, start):
    """The offset just past the link label that opens with the "[" at text[start], or None
    where none does. As CommonMark bounds a link label, it runs to the first "]" that no
    backslash escapes, with no "[" that no backslash escapes before that "]"; a backslash
    escapes the ASCII punctuation character directly after it. CommonMark's limit of 999
    characters is not applied. No code span, HTML or character reference is read inside
    it."""
    if text[start:start + 1] != "[":
        return None
    i = start + 1
    while i < len(text):
        c = text[i]
        if c == "\\" and text[i + 1:i + 2] in PUNCTUATION:
            i += 2
        elif c == "[":
            return None
        elif c == "]":
            return i + 1
        else:
            i += 1
    return None


def label_key(label):
    """Link label `label`, the text between its brackets, as two labels are compared: after
    Unicode case folding, with white space at either end removed and each run of white space
    inside read as one space, as CommonMark compares them. A blank label, empty or of white
    space only, gives "". `BREAK` is dropped, so a label reads alike in the line `detached`
    gives."""
    return " ".join(label.replace(BREAK, "").casefold().split())


def definitions(text):
    """(start, key) for each definition-like text page `text` holds: each label, as
    `label_end` reads one, that a "[" no backslash escapes opens at offset `start` and ":"
    directly follows, `key` being the label as `label_key` gives it, such as "dvaa" in
    "[DVAA]: https://example.org". A blank label defines nothing. Each "[" scans only up to
    the first "[" or "]" after it that no backslash escapes, and a label found is passed
    over whole, so a page is read in linear time."""
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and text[i + 1:i + 2] in PUNCTUATION:
            i += 2
            continue
        if c == "[":
            end = label_end(text, i)
            if end is not None:
                key = label_key(text[i + 1:end - 1])
                if key and text[end:end + 1] == ":":
                    yield i, key
                i = end
                continue
        i += 1


def defined_labels(text):
    """The link labels page `text` defines, each as `label_key` gives it: the label of each
    definition-like text `definitions` finds, such as "dvaa" in
    "[DVAA]: https://example.org". A definition-like text that CommonMark does not read as
    one, such as one in a fenced code block, is counted too, which `names` allows for by
    also reading each line with the removals `label_removals` gives."""
    return frozenset(key for _, key in definitions(text))


def unsure_labels(text):
    """The labels page `text` defines (`defined_labels`) only in definition-like texts that
    CommonMark may not read as definitions: those whose "[" does not start a line, after at
    most three spaces, outside a fenced code block, as in "`[t]: x`", in "[t]: x" after four
    spaces or a tab, and in "[t]: x" on a line in a fenced code block. A fenced code block
    runs from a line that `FENCE` matches, where a backtick run has no backtick after it on
    the line, to the first later line that `FENCE` matches with a run of that character at
    least as long and nothing but spaces and tabs after it, or to the end of the page. Each
    line is read once, and `definitions` reads the page in linear time."""
    starts = set()
    fence = None
    offset = 0
    for line in text.split("\n"):
        found = FENCE.match(line)
        if fence:
            run = found.group(1) if found else ""
            if (run[:1] == fence[0] and len(run) >= len(fence)
                    and not found.group(2).strip(" \t")):
                fence = None
        elif found and not (found.group(1)[0] == "`" and "`" in found.group(2)):
            fence = found.group(1)
        else:
            indent = len(line) - len(line.lstrip(" "))
            if indent <= 3 and line[indent:indent + 1] == "[":
                starts.add(offset + indent)
        offset += len(line) + 1
    sure, keys = set(), set()
    for start, key in definitions(text):
        (sure if start in starts else keys).add(key)
    return frozenset(keys - sure)


def label_removals(stripped, labels, unsure=frozenset()):
    """The `labels` arguments `names` reads line `stripped` with, `labels` being the labels
    the page holding it defines (`defined_labels`) and `unsure` those of them it defines
    only in definition-like texts CommonMark may not read as definitions (`unsure_labels`):
    `labels`, then None, which removes no label, and, where two to `MIXED_LABELS` of those
    labels stand directly after a "]" on the line, each other set of them that holds at
    least one, so that every mix of them removed and kept is read. `defined_labels` also
    counts a text that only looks like a definition, so of two labels on a line CommonMark
    can remove one and keep the other: on a page that defines t, with DV only in a fenced
    code block, "[x][DV](u)[A][t]A" shows "[x]DVAA", and of these readings only the one
    that removes t alone names DVAA there. A line holding more such labels is read with all
    of them removed and with none and, where one to `MIXED_LABELS` of them are in `unsure`,
    with each other mix of those removed and kept and the others removed: on a page that
    defines t, a and b, with DV only in a fenced code block, "[x][DV](u)[A][t]A [y][a] [z][b]"
    shows "[x]DVAA y z", which the reading that removes t, a and b names. Each reading
    reads the whole line, and k labels have 2 to the power k mixes. Each "[" after a "]"
    scans its label only up to the first "[" or "]" after it that no backslash escapes, as
    `label_end` does."""
    keys = {}
    i = stripped.find("][")
    while i >= 0:
        end = label_end(stripped, i + 1)
        if end is not None:
            key = label_key(stripped[i + 2:end - 1])
            if key in labels:
                keys[key] = None
        i = stripped.find("][", i + 1)
    removals = [labels, None]
    if 1 < len(keys) <= MIXED_LABELS:
        for size in range(1, len(keys)):
            removals.extend(map(frozenset, itertools.combinations(keys, size)))
    elif len(keys) > MIXED_LABELS:
        mixed = [key for key in keys if key in unsure]
        if len(mixed) <= MIXED_LABELS:
            removed = frozenset(key for key in keys if key not in unsure)
            for size in range(len(mixed)):
                removals.extend(removed.union(chosen)
                                for chosen in itertools.combinations(mixed, size))
    return removals


def step_one(stripped, raw_html=RAW_HTML, spans=True, labels=None, references=None,
             hide_elements=False):
    """(text, open): `stripped` after the first step the module description states. Its HTML
    is removed as `raw_html` matches it, `RAW_HTML` unless another is given; the character
    each backslash escapes and the text of each code span are kept as text, written in the
    `AS_TEXT` forms, and the backslash and the backticks around the code span removed; a
    backtick in no code span is left for the second step to remove. With `references`,
    `HTML_BLOCK_REFERENCE` in the HTML block reading, each character reference it matches
    at an "&" this step reaches, where it stands as written, is decoded here, and what it
    stands for, less the characters `hiding_kind` names, is kept as text, so no removal
    after it can run its digits on: "&#x30<b>D" reads "0D". Code spans are read
    until the first place where a backtick after it could be read another way, the places
    the module description lists, which `RAW_HTML` decides whichever HTML `raw_html`
    removes; with `spans` false none is read. A "]" directly followed by a link label, as
    `label_end` reads one, is removed with the label, which is not read further, where the
    label is blank or its `label_key` is in `labels`, the labels the page holding the line
    defines; with `labels` None no label is removed. `open` is whether the lines after this
    one, up to a blank line, read no code span: whether code spans were not read here or
    stopped being read, or a run of backticks here found no closing run. A removed label is
    passed over, so neither the "]" that closes it nor a backtick, "<" or backslash in it
    stops code spans being read, while the "]" before a label holding one of the last three
    has already stopped them: `open` is never true with `labels` where it is false with
    `labels` None, the reading `span_lines` takes. With `hide_elements` true, the text of
    each element in `HIDDEN_ELEMENTS` is removed too, from the start tag that opens it while
    none is open to the end of the end tag that closes it, or to the end of the line where
    none does, each tag named as `TAG_START` reads the HTML `raw_html` matches, to the first
    tab, line feed, form feed, space, "/" or ">" whatever `raw_html` is, as `HTML_BLOCK_HTML`
    and a browser end a tag name: a start tag opens such an element unless one in
    `RAW_TEXT_ELEMENTS` is open, and an end tag closes the element opened last where it has
    that element's name. Removing the text of an element passes over no place on the line,
    so `open`, and the places `raw_html` is asked to match at, are the same whether or not
    `hide_elements` is true.

    Each closing run is looked up in the runs of its length, in order, past the ones already
    passed, a "<" that starts no HTML looks for the first ">" after it once for all the "<"
    before that ">", and a link label is scanned only up to the first "[" or "]" after its
    "[" that no backslash escapes, where the next one can start; the text of an element is
    removed once, when the element that opened while none was open closes or the line ends:
    a line is read in linear time."""
    runs = {}
    for run in BACKTICKS.finditer(stripped):
        runs.setdefault(len(run.group()), []).append(run.start())
    passed = dict.fromkeys(runs, 0)
    out = []
    reading, unmatched = spans, False
    # The first ">" after the last "<" that starts no HTML, when no character in
    # HTML_UNSURE stands before it; a later "<" before it needs no new look.
    clear_to = -1
    # The elements in HIDDEN_ELEMENTS open here, the one opened last at the end, and the
    # length `out` had where the first of them opened.
    elements, hidden_from = [], 0
    i, n = 0, len(stripped)
    while i < n:
        c = stripped[i]
        if c == "<":
            if reading:
                found = RAW_HTML.match(stripped, i)
                if found:
                    reading = not (unclosed(found.group())
                                   or any(h in HTML_UNSURE for h in found.group()))
                elif stripped[i + 1:i + 2] not in ("", " ", "\t") and stripped[i + 1].isascii():
                    if clear_to < i:
                        end = stripped.find(">", i + 1)
                        if end < 0 or any(h in HTML_UNSURE for h in stripped[i + 1:end]):
                            reading = False
                        clear_to = end
            found = raw_html.match(stripped, i)
            if found:
                tag = TAG_START.match(found.group()) if hide_elements else None
                if tag and tag.group(2).isascii():
                    name = tag.group(2).lower()
                    if tag.group(1):
                        if elements and elements[-1] == name:
                            elements.pop()
                            if not elements:
                                del out[hidden_from:]
                    elif name in HIDDEN_ELEMENTS and not (
                            elements and elements[-1] in RAW_TEXT_ELEMENTS):
                        if not elements:
                            hidden_from = len(out)
                        elements.append(name)
                i = found.end()
                continue
        elif c == "\\" and stripped[i + 1:i + 2] in PUNCTUATION:
            out.append(stripped[i + 1].translate(AS_TEXT))
            i += 2
            continue
        elif c == "`":
            end = i + 1
            while end < n and stripped[end] == "`":
                end += 1
            if reading:
                starts = runs.get(end - i, [])
                k = passed.get(end - i, 0)
                while k < len(starts) and starts[k] < end:
                    k += 1
                if starts:
                    passed[end - i] = k
                if k == len(starts):
                    unmatched = True
                else:
                    text = stripped[end:starts[k]]
                    if any(s in SPAN_UNSURE for s in text):
                        reading = False
                    else:
                        if text[:1] == text[-1:] == " " and text.strip(" "):
                            text = text[1:-1]
                        out.append(text.translate(AS_TEXT))
                        i = starts[k] + end - i
                        continue
            out.append(stripped[i:end])
            i = end
            continue
        elif c == "]" and stripped[i + 1:i + 2] in ("(", "["):
            if reading:
                link = LINK_TARGET.match(stripped, i)
                if not link or any(u in LINK_UNSURE for u in link.group()):
                    reading = False
            end = None if labels is None else label_end(stripped, i + 1)
            if end is not None:
                key = label_key(stripped[i + 2:end - 1])
                if not key or key in labels:
                    i = end
                    continue
        elif c == "&" and references is not None:
            reference = references.match(stripped, i)
            if reference:
                out.append(decoded(reference).translate(AS_TEXT))
                i = reference.end()
                continue
        out.append(c)
        i += 1
    if elements:
        del out[hidden_from:]
    return "".join(out), not reading or unmatched


def name_form(stripped, raw_html=RAW_HTML, spans=True, labels=None, references=None,
              hide_elements=False):
    """`stripped` as a name in it reads, by the three steps the module description states:
    `step_one`, which removes the raw HTML `raw_html` matches, `RAW_HTML` unless another is
    given, keeps as text the character each backslash escapes and the text of each code
    span, read unless `spans` is false, and removes each "]" directly followed by a link
    label that is blank or in `labels`, the labels the page holding the line defines, with
    that label, and none with `labels` None, and with `hide_elements` true the text of each
    style, script and template element, and with `references`, `HTML_BLOCK_REFERENCE`
    in the HTML block reading, decodes each numeric character reference it matches where it
    stands as written and keeps what it stands for as text; then each "](...)" span
    `PAREN_SPAN` matches removed, whether or not it makes a link, then each "!" `IMAGE`
    matches, and the Markdown characters in `MARKUP`; then the character references decoded,
    less the characters `hiding_kind` names, and the text brought to NFKC, which brings back
    what the first step kept as text, with each character in `CONFUSABLES` read as the
    letters it resembles. The HTML is removed before the "](...)" spans, as HTML can start
    inside a link destination or title and end after the ")" that closes them, while a link
    label is read as written, as CommonMark reads one; and the markup is removed before the
    references are decoded, as a reference to "*" shows a star, while a reference decoded
    in the first step is kept as text, which shows a star too."""
    text = step_one(stripped, raw_html, spans, labels, references, hide_elements)[0]
    text = IMAGE.sub("", PAREN_SPAN.sub("", text)).translate(MARKUP)
    text = REFERENCE.sub(decoded, text)
    return nfkc(text).translate(CONFUSABLES)


def holds(text, name):
    """Whether `text` holds `name` at some place where NFKC does not join the combining
    marks directly after it to its last letter. "DVAA" U+0301 does not hold DVAA, as NFKC
    gives "DVA" U+00C1, and neither does "DVAA" U+0332 U+0301, where NFKC joins U+0301 to
    the A past U+0332; "DVAA" U+0332 COMBINING LOW LINE, "DVAA" U+20DD and "DVAA" U+0301
    " DVAA" do. Only a character after `name` outside ASCII has its category looked up; no
    ASCII character is a mark."""
    start = text.find(name)
    while start >= 0:
        end = run = start + len(name)
        while run < len(text) and not text[run].isascii() and is_mark(ord(text[run])):
            run += 1
        if run == end or nfkc(name[-1] + text[end:run])[0] == name[-1]:
            return True
        start = text.find(name, start + 1)
    return False


def detached(stripped, references=None):
    """`stripped` with `BREAK` put before each combining mark that does not stand directly
    after a letter or another combining mark, and before each character reference to a
    combining mark, one `REFERENCE` matches or, with `references`, one that pattern matches
    first, as written. In "DV**AA**" U+20DD the mark stands after "*" and in "DVAA&#x20dd;"
    it is written as a reference, so each is put apart from the name, while in "DVAA" U+20DD
    it stays directly after it. With `HTML_BLOCK_REFERENCE`, "DVA&#65&#x301" puts U+0301
    apart too. A `BREAK` goes only before a mark or an "&", neither of which a reference
    reads on over, so each reference written before one reads as far as in `stripped`."""
    out = []
    i = 0
    while i < len(stripped):
        reference = None
        if stripped[i] == "&":
            reference = ((references.match(stripped, i) if references is not None else None)
                         or REFERENCE.match(stripped, i))
        piece = reference.group() if reference else stripped[i]
        shown = reference_text(piece)[:1] if reference else piece
        if i and not shown.isascii() and is_mark(ord(shown)):
            if reference or not unicodedata.category(stripped[i - 1]).startswith(("L", "M")):
                out.append(BREAK)
        out.append(piece)
        i += len(piece)
    return "".join(out)


def names(stripped, name, hiding=False, spans=True, labels=None, unsure=frozenset()):
    """Whether a line that is `stripped` once the characters `hiding_kind` names are
    removed names `name`: it `holds` `name` as it stands or in its `name_form`, read with
    `RAW_HTML` and, where a tag name is followed by white space other than a space or
    tab, with `SPACE_OR_TAB_HTML` too, and where a tag name is followed by a character
    other than an ASCII letter, digit, hyphen, tab, line feed, form feed, space, "/" or ">",
    or by a tab, line feed, form feed, space or "/" and then by a "<" before any ">", as a
    browser reads a tag in an HTML block too, with `HtmlBlockHtml`: "DV<x\\>AA",
    "D<D\\\\</b>VAA", "DV<x" U+00A0 "<y>AA", "DV<a <b>AA" and "D<a <b" U+00A0 "D<x\\>VAA"
    name DVAA; and where "/" or white space
    after a tag name is followed by a quote before any "<" or ">", with `QUOTED_HTML` too,
    which passes over a quoted attribute value whole: 'DV<b x="<">AA' and
    "DV<b title='>'>AA" name DVAA. Where "&" stands directly before "#", it is also read as
    a browser reads an HTML block, with `HtmlBlockHtml` and each numeric character reference
    `HTML_BLOCK_REFERENCE` matches decoded where it stands as written: "DVA&#65", "DVA&#x41"
    and "&#x30<b>D<x\\>VAA" name DVAA, the last as "0DVAA". Each name form removes a "]"
    directly followed by a link label that is blank or in `labels`, the labels the page
    holding the line defines, with that label; where a "]" stands directly before a "[",
    the line is also read with no label removed, as it is with `labels` None, and with the
    other removals `label_removals` gives, `unsure` being the labels the page defines only
    in definition-like texts CommonMark may not read as definitions (`unsure_labels`), in
    each of those readings, one `HtmlBlockHtml` serving every label reading: on a page that
    defines DV,
    "[x][DV](url)A<y\\>A <q\\" names DVAA only read with no label removed and as a browser
    reads "<y\\>" in an HTML block, after the reading that removes DV has held "<q\\", a tag
    that finds no ">". `defined_labels` also counts a text that
    only looks like a definition, so "[x][DV](url)AA", which shows "[x]DVAA" unless the page
    defines DV, names DVAA by the reading that removes no label even with DV in `labels`,
    "[x][DV](u)[A][t]A" names DVAA by the reading that removes t alone with dv and t in
    `labels`, "[x][DV](u)[A][t]A [y][a] [z][b]" by the reading that removes t, a and b with
    dv, t, a and b in `labels` and dv in `unsure`, while "[DV][dvaa]AA" names DVAA only
    with dvaa in `labels`. Where
    `HIDDEN_ELEMENT_START` finds a "<" and the name of a style, script or template element,
    each of those readings is also made with the text of each such element removed,
    `name_form` with `hide_elements` true, the one `HtmlBlockHtml` serving those readings
    too: "DV<style>x</style>AA" names DVAA, as a browser shows no text of a style element.
    The name form reads no code span with `spans` false, as `span_lines` gives for a line
    after one that can leave a code span, HTML or a link span open, nor with `hiding` true.
    Where a name form holds `name` only with combining marks directly after it that NFKC
    joins to its last letter, or only once its letters are decomposed, the name form of the
    line `detached` is read too, so a mark counts only where it is written as itself
    directly after a letter or another mark: "DVAA" U+0301 does not name DVAA, while
    "DV**AA**" U+0301 and
    "DV**AA&#x301;**" do, and "DVAA" U+0332, which NFKC leaves apart from the A, names DVAA.
    "DV" U+200B "AA", "DV&#8203;AA", "**DV**AA", "DV<!-- -->AA", "DVA" U+0410 and the
    fullwidth letters each name DVAA; "DVAA" U+0301 does not. On a line that carried such a
    character, `hiding` true, a combining mark after `name` does not keep the line from
    naming it: removing the character can put a mark directly after the name, so "DVAA"
    U+200B U+0301 names DVAA."""
    def found(text):
        return name in text if hiding else holds(text, name)

    if found(stripped):
        return True
    spans = spans and not hiding
    readings = [(RAW_HTML, None)]
    if OTHER_SPACE_AFTER_TAG_NAME.search(stripped):
        readings.append((SPACE_OR_TAB_HTML, None))
    # One instance reads the line in both HTML block readings, with each removal below and
    # its `detached` form: it gives what HTML_BLOCK_HTML gives in every reading, whichever
    # "<" a reading passes over.
    block_html = HtmlBlockHtml()
    if (OTHER_CHARACTER_IN_TAG_NAME.search(stripped)
            or LESS_THAN_AFTER_TAG_NAME.search(stripped)):
        readings.append((block_html, None))
    if QUOTE_AFTER_TAG_NAME.search(stripped):
        readings.append((QUOTED_HTML, None))
    # A numeric character reference stands as written only where "&" is directly followed
    # by "#", and on any other line the reading with HTML_BLOCK_REFERENCE reads the line as
    # the HTML block reading above does. That reading stays: it leaves a reference with no
    # ";" as written and decodes the others once the HTML is removed, as the first does, so
    # "&#x3DV<x\>AA" names DVAA there, where this one decodes "&#x3D".
    if "&#" in stripped:
        readings.append((block_html, HTML_BLOCK_REFERENCE))
    # Only a "]" directly before a "[" can be removed with a label, so a line without one
    # reads alike either way.
    removals = ([None] if labels is None or "][" not in stripped
                else label_removals(stripped, labels, unsure))
    # Only a line holding a start tag of a style, script or template element has text of
    # one to remove, so a line without one reads alike either way.
    hides = [False, True] if HIDDEN_ELEMENT_START.search(stripped) else [False]
    for raw_html, references in readings:
        for removal in removals:
            for hide in hides:
                form = name_form(stripped, raw_html, spans, removal, references, hide)
                if found(form):
                    return True
                decomposed = unicodedata.normalize("NFKD", form).translate(CONFUSABLES)
                if name in decomposed and found(name_form(detached(stripped, references),
                                                          raw_html, spans, removal,
                                                          references, hide)):
                    return True
    return False


def hiding_kind(c):
    """What `c` is when it fails a line that names DVAA, states a count or states the matrix
    version, else None: a character that can keep a wording from being read."""
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


def percent(count, total):
    """`count` as a whole percentage of `total`, rounded half up."""
    return (200 * count + total) // (2 * total)


def release_month(changelog, version):
    """(month name, year) of the first release heading in `changelog` whose version is
    `version`, a version that differs only by trailing ".0" parts being the same (v1.2.0
    for 1.2); None when no heading releases it."""
    def plain(v):
        return re.sub(r"(?:\.0)+$", "", v)

    for m in RELEASE_HEADING.finditer(changelog):
        month = int(m.group(3))
        if plain(m.group(1)) == plain(version) and 1 <= month <= 12:
            return MONTHS[month - 1], m.group(2)
    return None


def read_matrix():
    """(matrix.json parsed, None), or (None, the reason it could not be read or parsed).

    The reasons are the ones scripts/validate_matrix.py gives for the same file: "no such
    file", "a directory, not a file", the system's reason for another OSError, its strerror,
    as in "Permission denied", the message of a ValueError, raised for a syntax error, an
    integer longer than Python's int string conversion limit and bytes that are not UTF-8,
    among others, and the message of the RecursionError, which is not a ValueError, that
    json.loads raises for arrays or objects nested deeper than it parses.
    """
    try:
        return json.loads(MATRIX.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "no such file"
    except IsADirectoryError:
        return None, "a directory, not a file"
    except OSError as exc:
        return None, exc.strerror or str(exc)
    except (ValueError, RecursionError) as exc:
        return None, str(exc)


# What ``wrong_shape`` asks of a key it reads from an object: present, with any value;
# present, as a string; absent, null or a string; absent, null or an array of strings. Each
# but the first is worded as the reason line words it.
ANY, STRING = "any value", "a string"
STRING_OR_NULL, STRINGS_OR_NULL = "a string or null", "an array of strings or null"

# What this check needs from matrix.json, in the order ``wrong_shape`` checks it: each array,
# whether the top level must hold it (an absent attackClasses is read as no classes), and the
# keys of its objects, with what each must hold. An id is a string, as
# scripts/check_canonical_classes.py asks, and so is a name, category or description, which
# the check uses as text. A technique's tactic, attackClass and evidenceTier, which the check
# groups techniques by, are each absent, null or a string, and a class's techniques, which it
# sorts beside technique ids, are absent, null or an array of strings. ``order`` is only
# compared and written as text, so it may hold any value, and so may the top-level
# ``version``, which may also be absent; a key the check only tests for emptiness, as it does
# ``hmaChecks``, is not listed.
SHAPE = (
    ("techniques", True, (("id", STRING), ("name", STRING), ("tactic", STRING_OR_NULL),
                          ("attackClass", STRING_OR_NULL), ("evidenceTier", STRING_OR_NULL))),
    ("tactics", True, (("id", STRING), ("name", STRING), ("order", ANY))),
    ("attackClasses", False, (("id", STRING), ("category", STRING), ("description", STRING),
                              ("techniques", STRINGS_OR_NULL))),
)


def json_type(value):
    """The JSON type of a parsed value, with its article, as in "an array" or "null"."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


def wrong_value(item, field, kind, where):
    """None when the object ``item`` holds ``field`` as ``kind`` asks, or the reason it does
    not; ``where`` names the object, as in "techniques[0]"."""
    if field not in item:
        return None if kind in (STRING_OR_NULL, STRINGS_OR_NULL) else f"{where} has no {field}"
    value = item[field]
    if kind == ANY or (value is None and kind != STRING):
        return None
    if kind == STRINGS_OR_NULL:
        if not isinstance(value, list):
            return f"{where}.{field} is {json_type(value)}, not {kind}"
        for n, entry in enumerate(value):
            if not isinstance(entry, str):
                return f"{where}.{field}[{n}] is {json_type(entry)}, not a string"
        return None
    if not isinstance(value, str):
        return f"{where}.{field} is {json_type(value)}, not {kind}"
    return None


def wrong_shape(matrix):
    """None when the parsed matrix.json holds what ``SHAPE`` says this check needs from it,
    or the reason it does not, naming the first place that fails in the words
    scripts/check_canonical_classes.py uses, as in "techniques[0] has no id"."""
    if not isinstance(matrix, dict):
        return f"the top level is {json_type(matrix)}, not an object"
    for key, required, fields in SHAPE:
        if key not in matrix:
            if required:
                return f"the top level has no {key} key"
            continue
        items = matrix[key]
        if not isinstance(items, list):
            return f"{key} is {json_type(items)}, not an array"
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                return f"{key}[{index}] is {json_type(item)}, not an object"
            for field, kind in fields:
                cause = wrong_value(item, field, kind, f"{key}[{index}]")
                if cause is not None:
                    return cause
    return None


def main(argv):
    # An argument this script does not know ends the run with exit 2 before anything is
    # read or written: a mistyped --fix must not report the README as checked. argparse
    # acts on --help or -h where it stands and names the arguments it does not know only
    # once it has read them all, so help beside such an argument prints the usage and
    # exits 0; that run reads and writes nothing either.
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("--fix", action="store_true",
                        help="rewrite the attack-class tables from matrix.json, on the page "
                             "that holds them")
    args = parser.parse_args(argv)

    matrix, cause = read_matrix()
    if cause is not None:
        print(f"matrix.json is missing or does not parse: {cause}", file=sys.stderr)
        return 1
    cause = wrong_shape(matrix)
    if cause is not None:
        print(f"matrix.json parses but has the wrong shape: {cause}", file=sys.stderr)
        return 1
    pages = Pages(ROOT)

    if args.fix:
        fixed = fix_class_tables(matrix, pages)
        # Without the markers there is no block to rewrite, so nothing is written and the
        # tables are not reported current; the marker failure below ends the run with 1.
        if fixed is None:
            print("NOT FIXED: wrote nothing, as the attack-class tables could not be found; "
                  "see the marker failure below", file=sys.stderr)
        elif fixed[1] != pages.texts[pages.names.index(fixed[0])]:
            (ROOT / fixed[0]).write_text(fixed[1], encoding="utf-8")
            pages = Pages(ROOT)
            print("FIXED: rewrote the attack-class tables from matrix.json")
        else:
            print("OK: attack-class tables already current")
    readme = pages.text

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
    failures = [f"{name}: missing; README.md hands this page text that the check reads"
                for name in pages.missing]

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
        # The line breaks are counted on from the previous occurrence: counting them from
        # the start of the text for each one made many differing occurrences take time in
        # proportion to their number times the size of the README.
        line, counted = 1, 0
        for m in found:
            if m.groups() != want:
                line += text.count("\n", counted, m.start())
                counted = m.start()
                failures.append(
                    f"{pages.where(line)}: \"{m.group(0)}\" does not match {source} "
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
    count(r"(?m)^## Attack Classes \((\d+)\)$", [len(classes)], "attack classes")

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

    # The offset of every line break, found once: a row's line number is then a bisection,
    # where counting the breaks before each row made many rows take time in proportion to
    # their number times the size of the README.
    breaks = [m.start() for m in re.finditer("\n", readme)]

    def line_of(pos):
        return bisect.bisect_left(breaks, pos) + 1

    # Matrix overview: one row per tactic, stating its name, kill chain stage (`order`)
    # and technique count. The name and the link target stop at a line break: a row is one
    # line, and a class that crosses line breaks scanned from every line that starts "| ["
    # to the end of the README and back.
    per_tactic = {}
    for t in techniques:
        per_tactic[t.get("tactic")] = per_tactic.get(t.get("tactic"), 0) + 1
    tactic_by_id = {t["id"]: t for t in tactics}
    tactic_rows = {}
    for m in re.finditer(
            r"(?m)^\| \[([^\]\n]+)\]\(tactics/([^)\n]+)\.md\) \| (\d+) \| (\d+) \|", readme):
        name, tid, stage, stated = m.groups()
        line = pages.where(line_of(m.start()))
        tactic = tactic_by_id.get(tid)
        if tactic is None:
            failures.append(f"{line}: tactic row links tactics/{tid}.md, "
                            f"which is not a tactic in matrix.json")
            continue
        if tid in tactic_rows:
            failures.append(f"{line}: second row for tactic {tid} "
                            f"(first at {tactic_rows[tid]})")
            continue
        tactic_rows[tid] = line
        want = (tactic["name"], str(tactic["order"]), str(per_tactic.get(tid, 0)))
        if (name, stage, stated) != want:
            failures.append(
                f"{line}: tactic row \"{name} | {stage} | {stated}\" does not match "
                f"matrix.json ({tid} name, kill chain stage, techniques: {' | '.join(want)})"
            )
    for tid in tactic_by_id:
        if tid not in tactic_rows:
            failures.append(f"README per-tactic table has no row for tactic {tid}")

    # Evidence Standard: one row per tier, stating its count and its share of all
    # techniques as a whole percentage.
    tier_rows = {}
    for m in re.finditer(r"(?m)^\| \*\*(\w+)\*\* \|.*\| (\d+) \((\d+)%\) \|$", readme):
        tier, stated, pct = m.group(1).lower(), m.group(2), m.group(3)
        line = pages.where(line_of(m.start()))
        if tier not in TIERS:
            failures.append(f"{line}: \"{m.group(1)}\" is not an evidence tier "
                            f"({', '.join(TIERS)})")
            continue
        if tier in tier_rows:
            failures.append(f"{line}: second row for tier {tier} "
                            f"(first at {tier_rows[tier]})")
            continue
        tier_rows[tier] = line
        n = tiers.get(tier, 0)
        want = (str(n), str(percent(n, total)))
        if (stated, pct) != want:
            failures.append(
                f"{line}: \"{stated} ({pct}%)\" does not match matrix.json "
                f"({tier}: {want[0]} of {total}, {want[1]}%)"
            )
    for tier in TIERS:
        if tier not in tier_rows:
            failures.append(f"README evidence tier table has no row for {tier}")

    failures.extend(check_class_tables(matrix, pages))

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
    naming = [names(stripped, "DVAA", bool(hidden), spans, labels, unsure)
              for (_, stripped, hidden), spans, (labels, unsure)
              in zip(lines, span_lines(lines), page_labels(pages, lines))]
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

    # The HackMyAgent and OASB figures, read on every README line.
    figures = []
    for project, field, pattern in RELATED_WORDINGS:
        entry = related.get(project)
        value = entry.get(field) if isinstance(entry, dict) else None
        if type(value) is not int:
            failures.append(f"{pinned}: {project}.{field} is not a whole number")
            continue
        require(pattern, [value],
                f"{project}.{field}, read from release {entry.get('sourceVersion')}",
                source=pinned)
        figures.append(f"{project}.{field}={value}")

    # The matrix version where the README states it, and each month and year on a line
    # stating it, which is when CHANGELOG.md says that version was released.
    version = str(matrix.get("version"))
    for pattern, stated in VERSION_WORDINGS:
        require(pattern, [version], "matrix version", stated=stated)
    released = None
    if CHANGELOG.is_file():
        released = release_month(CHANGELOG.read_text(encoding="utf-8"), version)
    version_lines = set()
    for number, (line, stripped, _) in enumerate(lines, 1):
        if not any(re.search(pattern, stripped) for pattern, _ in VERSION_WORDINGS):
            continue
        version_lines.add(number)
        for m in MONTH_YEAR.finditer(line):
            if released is None:
                failures.append(
                    f"{pages.where(number)}: \"{m.group(0)}\" is read against the CHANGELOG.md "
                    f"release heading of version {version}, and there is none"
                )
            elif m.groups() != released:
                failures.append(
                    f"{pages.where(number)}: \"{m.group(0)}\" does not match CHANGELOG.md "
                    f"(version {version} released {' '.join(released)})"
                )

    # Each technique id where the README writes one, the name, tactic and evidence tier
    # written beside it, and the technique citation with its link and its year, which is
    # the year CHANGELOG.md gives the release of the matrix version.
    technique_by_id = {t["id"]: t for t in techniques}
    tactic_by_name = {t["name"].lower(): t for t in tactics}
    technique_lines = set()
    cited = False
    for number, (_, stripped, _) in enumerate(lines, 1):
        ids = list(TECHNIQUE_ID.finditer(stripped))
        if not ids:
            continue
        technique_lines.add(number)
        where = pages.where(number)
        for m in ids:
            tid = m.group(0)
            technique = technique_by_id.get(tid)
            if technique is None:
                failures.append(f"{where}: \"{tid}\" is not a technique id in matrix.json")
                continue
            name = technique["name"]
            after = NAME_AFTER.match(stripped, m.end())
            if after and after.group(1) != name:
                failures.append(f"{where}: \"{tid} ({after.group(1)})\" does not match "
                                f"matrix.json ({tid} name: {name})")
            if not stripped.endswith(" (", 0, m.start()):
                continue
            before = stripped[:m.start() - 2]
            if not before.endswith(name) or re.search(r"[\w-]$", before[:-len(name)]):
                failures.append(f"{where}: the text before \"({tid}\" does not end with its "
                                f"name in matrix.json ({tid} name: {name})")
            items = ITEMS_AFTER.match(stripped, m.end())
            for item in (items.group(1).split(", ")[1:] if items else ()):
                tactic = tactic_by_name.get(item.lower())
                if tactic is not None and tactic["id"] != technique.get("tactic"):
                    want = tactic_by_id.get(technique.get("tactic"), {}).get("name")
                    failures.append(f"{where}: \"{item}\" does not match matrix.json "
                                    f"({tid} tactic: {want})")
                tier = item.split(" ", 1)[0].lower()
                if tier in TIERS and tier != technique.get("evidenceTier"):
                    failures.append(f"{where}: \"{item}\" does not match matrix.json "
                                    f"({tid} evidence tier: {technique.get('evidenceTier')})")
        cites = [c.group(1) for c in TECHNIQUE_CITATION.finditer(stripped)]
        if cites:
            cited = True
            for m in ids:
                if m.group(0) not in cites:
                    failures.append(f"{where}: \"{m.group(0)}\" on the citation of "
                                    f"{' and '.join(cites)} names another technique")
            for m in YEAR.finditer(stripped):
                if released is None:
                    failures.append(
                        f"{where}: \"{m.group(0)}\" is read against the CHANGELOG.md release "
                        f"heading of version {version}, and there is none"
                    )
                elif m.group(0) != released[1]:
                    failures.append(
                        f"{where}: \"{m.group(0)}\" does not match CHANGELOG.md "
                        f"(version {version} released {released[1]})"
                    )
    if not cited:
        failures.append("README does not state a technique citation (\"Threat Matrix T-N\")")

    # The STIX version where the README states it, which is the spec_version the objects of
    # the committed bundle carry; a bundle whose objects disagree gives nothing to read.
    stix_source = STIX_BUNDLE.relative_to(ROOT).as_posix()
    stix_lines = {number for number, (_, stripped, _) in enumerate(lines, 1)
                  if STIX_VERSION.search(stripped)}
    if not STIX_BUNDLE.is_file():
        failures.append(f"{stix_source}: missing; the STIX version the README states is "
                        f"read from its objects' spec_version")
    else:
        bundle = json.loads(STIX_BUNDLE.read_text(encoding="utf-8"))
        spec_versions = sorted({str(o.get("spec_version"))
                                for o in bundle.get("objects", ())})
        if len(spec_versions) != 1:
            failures.append(f"{stix_source}: its objects carry {len(spec_versions)} "
                            f"spec_version values ({', '.join(spec_versions)}), and the "
                            f"STIX version the README states is read from the one they share")
        else:
            require(STIX_VERSION.pattern, spec_versions, "STIX version", source=stix_source,
                    stated=False)

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
        if number in version_lines:
            readers.append(("stating the matrix version", "version"))
        if number in technique_lines:
            readers.append(("stating a technique id", "technique id"))
        if number in stix_lines:
            readers.append(("stating the STIX version", "STIX version"))
        if not readers:
            continue
        where = " and ".join(phrase for phrase, _ in readers)
        wordings = " and ".join(name for _, name in readers)
        for column, c in hidden:
            label = " ".join(filter(None, (f"U+{ord(c):04X}", unicodedata.name(c, ""))))
            failures.append(
                f"{pages.where(number)}:{column}: a line {where} carries {label}, "
                f"{hiding_kind(c)}, which can hide a figure from the {wordings} wordings; "
                f"remove it"
            )

    related_summary = (
        f"DVAA {dvaa['sourceVersion']}: {dvaa['agents']} agents "
        f"({', '.join(f'{k}={v}' for k, v in kinds.items())}), "
        f"{dvaa['vulnerabilityCategories']} vulnerability categories; {', '.join(figures)}"
    )

    tier_total = sum(tiers.values())
    if tier_total != total:
        failures.append(
            f"evidence tiers sum to {tier_total}, expected {total} "
            f"(every technique needs exactly one tier; got {tiers})"
        )

    if failures:
        print("README claims do not match matrix.json, related-projects.json, "
              "CHANGELOG.md and stix/agent-threat-matrix-bundle.json:\n",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\nmeasured: {len(tactics)} tactics, {total} techniques, "
            f"{len(classes)} attack classes, tiers={tiers}, "
            f"detection={with_detection}/{total}, control={with_control}/{total}, "
            f"lab={with_lab}/{total}\npinned: {related_summary}",
            file=sys.stderr,
        )
        return 1

    print(
        f"README claims match matrix.json: {len(tactics)} tactics, {total} techniques, "
        f"{len(classes)} attack classes, tiers={tiers}, "
        f"detection={with_detection}/{total}, control={with_control}/{total}, "
        f"lab={with_lab}/{total}; and related-projects.json: {related_summary}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
