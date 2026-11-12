"""wildPrevalence and wildSampleCount: the schema requires them and scripts/sync_wild_prevalence.py writes them.

The validator cases run scripts/validate_matrix.py against a scratch copy of the tree, as
tests/test_validate_matrix.py does. The generator cases run scripts/sync_wild_prevalence.py
on a scratch copy, from a saved response (``--payload``) or with the fetch replaced in
process, so no case reads the network and the committed files are never written.
"""

import difflib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import urllib.error
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
API_URL = "https://api.oa2a.org/api/v1/threat-matrix"
FILES = ("matrix.json", "technique-ids.json", "schema/threat-matrix-v1.2.schema.json",
         "schema/consumer-readiness.json", "schema/evidence-sources.schema.json",
         "scripts/validate_matrix.py", "scripts/generate_stix.py", "scripts/sync_wild_prevalence.py",
         "scripts/check_technique_pages.py", "related-projects.json", "docs/data-sources.md",
         "stix/agent-threat-matrix-bundle.json", "evidence-gaps.json", "evidence-sources.json")
# The technique and tactic pages, which scripts/check_technique_pages.py checks against
# matrix.json, as the sync runs it; that check also reads related-projects.json and
# docs/data-sources.md, listed above.
DIRS = ("techniques", "tactics")
STIX = "stix/agent-threat-matrix-bundle.json"
TELEMETRY = "honeypot-telemetry"


def today() -> str:
    return date.today().isoformat()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for rel in FILES:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    for rel in DIRS:
        shutil.copytree(ROOT / rel, tmp_path / rel)
    return tmp_path


def load(root: Path, rel: str = "matrix.json"):
    return json.loads((root / rel).read_text(encoding="utf-8"))


def dump(root: Path, data, rel: str = "matrix.json") -> None:
    (root / rel).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run_validator(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "scripts" / "validate_matrix.py")],
                          capture_output=True, text=True, timeout=120)


def run_sync(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "scripts" / "sync_wild_prevalence.py"), *args],
                          capture_output=True, text=True, timeout=120)


def write_payload(root: Path, payload, name: str = "response.json") -> Path:
    path = root / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def technique(matrix: dict, tid: str) -> dict:
    return next(t for t in matrix["techniques"] if t["id"] == tid)


# --------------------------------------------------------------------------- the shipped file

def test_shipped_matrix_carries_both_fields_on_every_technique():
    matrix = load(ROOT)
    for t in matrix["techniques"]:
        assert isinstance(t["wildPrevalence"], (int, float)) and 0 <= t["wildPrevalence"] <= 100, t["id"]
        assert isinstance(t["wildSampleCount"], int) and t["wildSampleCount"] >= 0, t["id"]
    source = matrix["wildPrevalenceSource"]
    assert source["url"] == API_URL
    assert date.fromisoformat(source["read"]).isoformat() == source["read"]
    assert source["read"] <= matrix["updated"]


# --------------------------------------------------------------------------- the schema requires them

def _drop(key):
    def fn(m):
        del m["techniques"][0][key]
    return fn


def _set(key, value):
    def fn(m):
        m["techniques"][0][key] = value
    return fn


def _source(**changes):
    def fn(m):
        for key, value in changes.items():
            if value is None:
                del m["wildPrevalenceSource"][key]
            else:
                m["wildPrevalenceSource"][key] = value
    return fn


def _drop_source(m):
    del m["wildPrevalenceSource"]


# 10 ** 400 has 401 digits: JSON allows an integer that long, and it is too large to convert
# to a 64-bit float.
HUGE = 10 ** 400
TOO_LARGE = "an integer of 401 digits is too large for a 64-bit float, so it is not a finite number"
# The largest finite 64-bit float, a whole number of 309 digits.
LARGEST = int(sys.float_info.max)


RED = [
    ("technique without wildPrevalence", _drop("wildPrevalence"),
     "matrix.techniques[0]: missing required property 'wildPrevalence'"),
    ("technique without wildSampleCount", _drop("wildSampleCount"),
     "matrix.techniques[0]: missing required property 'wildSampleCount'"),
    ("file without wildPrevalenceSource", _drop_source,
     "matrix: missing required property 'wildPrevalenceSource'"),
    ("prevalence above 100", _set("wildPrevalence", 100.5),
     "matrix.techniques[0].wildPrevalence: 100.5 is above the maximum 100"),
    ("negative prevalence", _set("wildPrevalence", -1),
     "matrix.techniques[0].wildPrevalence: -1 is below the minimum 0"),
    ("prevalence as a string", _set("wildPrevalence", "98.44"),
     "matrix.techniques[0].wildPrevalence: expected type number, got str"),
    ("prevalence as a boolean", _set("wildPrevalence", True),
     "matrix.techniques[0].wildPrevalence: expected type number, got bool"),
    ("prevalence NaN", _set("wildPrevalence", float("nan")),
     "matrix.techniques[0].wildPrevalence: expected type number, got float"),
    ("prevalence Infinity", _set("wildPrevalence", float("inf")),
     "matrix.techniques[0].wildPrevalence: expected type number, got float"),
    ("prevalence too large for a float", _set("wildPrevalence", HUGE),
     f"matrix.techniques[0].wildPrevalence: {TOO_LARGE}"),
    ("negative prevalence too large for a float", _set("wildPrevalence", -HUGE),
     f"matrix.techniques[0].wildPrevalence: {TOO_LARGE}"),
    ("sample count too large for a float", _set("wildSampleCount", HUGE),
     f"matrix.techniques[0].wildSampleCount: {TOO_LARGE}"),
    ("fractional sample count", _set("wildSampleCount", 1.5),
     "matrix.techniques[0].wildSampleCount: expected type integer, got float"),
    ("negative sample count", _set("wildSampleCount", -1),
     "matrix.techniques[0].wildSampleCount: -1 is below the minimum 0"),
    ("read date in another format", _source(read="19 October 2026"),
     "matrix.wildPrevalenceSource.read: '19 October 2026' does not match"),
    ("source without a read date", _source(read=None),
     "matrix.wildPrevalenceSource: missing required property 'read'"),
    ("source url over plain http", _source(url="http://api.oa2a.org/api/v1/threat-matrix"),
     "matrix.wildPrevalenceSource.url: 'http://api.oa2a.org/api/v1/threat-matrix' does not match"),
    ("source with an unknown field", _source(note="hand typed"),
     "matrix.wildPrevalenceSource: unexpected property 'note'"),
    ("period without an end", _source(period={"start": "2026-09-01"}),
     "matrix.wildPrevalenceSource.period: missing required property 'end'"),
    ("period end in another format", _source(period={"start": "2026-09-01", "end": "30 September 2026"}),
     "matrix.wildPrevalenceSource.period.end: '30 September 2026' does not match"),
    ("period with an unknown field", _source(period={"start": "2026-09-01", "end": "2026-09-30", "closed": True}),
     "matrix.wildPrevalenceSource.period: unexpected property 'closed'"),
    ("period end that is no calendar date", _source(period={"start": "2026-09-01", "end": "2026-09-31"}),
     "S19 wildPrevalenceSource.period: end '2026-09-31' is not a calendar date"),
    ("period start that is no calendar date", _source(period={"start": "2026-02-29", "end": "2026-03-31"}),
     "S19 wildPrevalenceSource.period: start '2026-02-29' is not a calendar date"),
]


@pytest.mark.parametrize("fn,needle", [pytest.param(fn, needle, id=name) for name, fn, needle in RED])
def test_validator_refuses(tree, fn, needle):
    matrix = load(tree)
    fn(matrix)
    dump(tree, matrix)
    proc = run_validator(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert needle in proc.stderr, proc.stderr


def test_validator_reports_an_integer_too_large_for_a_float_as_one_finding(tree):
    matrix = load(tree)
    matrix["techniques"][0]["wildSampleCount"] = HUGE
    dump(tree, matrix)
    proc = run_validator(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.splitlines() == [
        "FAIL: matrix.json does not validate (2 finding(s)):",
        f"  - matrix.techniques[0].wildSampleCount: {TOO_LARGE}",
        "  - semantic checks skipped until the schema violations above are fixed",
    ], proc.stderr


def test_s14_prevalence_above_zero_with_no_samples_is_red(tree):
    matrix = load(tree)
    first = matrix["techniques"][0]
    first["wildPrevalence"], first["wildSampleCount"] = 50, 0
    dump(tree, matrix)
    proc = run_validator(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"S14 {first['id']}: wildPrevalence is 50 but wildSampleCount is 0" in proc.stderr, proc.stderr


def _period(start: int, end: int):
    """Give wildPrevalenceSource a period from start to end days after its read date."""
    def fn(m):
        read = date.fromisoformat(m["wildPrevalenceSource"]["read"])
        m["wildPrevalenceSource"]["period"] = {"start": (read + timedelta(days=start)).isoformat(),
                                               "end": (read + timedelta(days=end)).isoformat()}
    return fn


S19_RED = [
    ("period that starts after it ends", -10, -20, "start {start} is later than end {end}"),
    ("period that ends on the read date", -30, 0, "end {end} is not earlier than read {read}"),
    ("period that ends after the read date", -30, 12, "end {end} is not earlier than read {read}"),
]


@pytest.mark.parametrize("start,end,needle", [pytest.param(s, e, n, id=name) for name, s, e, n in S19_RED])
def test_s19_refuses_a_period_that_had_not_ended_when_it_was_read(tree, start, end, needle):
    matrix = load(tree)
    _period(start, end)(matrix)
    dump(tree, matrix)
    proc = run_validator(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    source = matrix["wildPrevalenceSource"]
    expected = "S19 wildPrevalenceSource.period: " + needle.format(read=source["read"], **source["period"])
    assert expected in proc.stderr, proc.stderr


@pytest.mark.parametrize("start,end", [pytest.param(-30, -1, id="ended the day before the read"),
                                       pytest.param(-1, -1, id="one day, the day before the read")])
def test_validator_accepts_a_period_that_ended_before_the_read_date(tree, start, end):
    matrix = load(tree)
    _period(start, end)(matrix)
    dump(tree, matrix)
    proc = run_validator(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


GREEN = [
    ("no data: both 0", 0, 0),
    ("samples with no prevalence", 0, 10),
    ("prevalence at the maximum", 100, 2566),
    ("fractional prevalence", 98.44, 7610),
    ("prevalence as a float zero", 0.0, 0),
    ("sample count at the largest finite float", 100, LARGEST),
]


@pytest.mark.parametrize("prevalence,samples", [pytest.param(p, s, id=name) for name, p, s in GREEN])
def test_validator_accepts(tree, prevalence, samples):
    matrix = load(tree)
    matrix["techniques"][0]["wildPrevalence"] = prevalence
    matrix["techniques"][0]["wildSampleCount"] = samples
    dump(tree, matrix)
    proc = run_validator(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- the generator

def days_ago(days: int) -> str:
    return (date.today() - timedelta(days=days)).isoformat()


def closed_period() -> dict:
    """A period that ended before every read date the generator cases give."""
    return {"start": days_ago(40), "end": days_ago(10)}


def served(matrix: dict, period=None) -> dict:
    """A response shaped like the endpoint's, for a closed period: every technique but the
    last, with values on three."""
    entries = []
    for t in matrix["techniques"][:-1]:
        entries.append({"id": t["id"], "name": t["name"], "threatStatus": "active",
                        "wildPrevalence": 0, "wildSampleCount": 0})
    entries[0]["wildPrevalence"] = None
    entries[0]["wildSampleCount"] = None
    entries[1].update(wildPrevalence=98.44, wildSampleCount=7610)
    entries[2].update(wildPrevalence=100, wildSampleCount=11306)
    entries.append({"id": "T-9999", "wildPrevalence": 12.5, "wildSampleCount": 40})
    return {"version": "1.1", "wildPeriod": period or closed_period(), "techniques": entries}


def test_sync_writes_both_fields_on_every_technique_and_zero_where_none_is_served(tree):
    original = load(tree)
    original["updated"] = "2026-06-03"
    for t in original["techniques"]:
        t["wildPrevalence"], t["wildSampleCount"] = 7, 7
    dump(tree, original)
    ids = [t["id"] for t in original["techniques"]]
    payload = write_payload(tree, served(original))

    proc = run_sync(tree, "--payload", str(payload), "--read-date", today())
    assert proc.returncode == 0, proc.stdout + proc.stderr

    matrix = load(tree)
    assert [t["id"] for t in matrix["techniques"]] == ids
    assert (technique(matrix, ids[0])["wildPrevalence"], technique(matrix, ids[0])["wildSampleCount"]) == (0, 0)
    assert (technique(matrix, ids[1])["wildPrevalence"], technique(matrix, ids[1])["wildSampleCount"]) == (98.44, 7610)
    assert (technique(matrix, ids[2])["wildPrevalence"], technique(matrix, ids[2])["wildSampleCount"]) == (100, 11306)
    assert (technique(matrix, ids[-1])["wildPrevalence"], technique(matrix, ids[-1])["wildSampleCount"]) == (0, 0)
    assert all((t["wildPrevalence"], t["wildSampleCount"]) == (0, 0) for t in matrix["techniques"][3:])
    assert matrix["wildPrevalenceSource"] == {"url": API_URL, "read": today(), "period": closed_period()}
    assert matrix["updated"] == today()
    assert f"from {API_URL}, read {today()}: 2 above 0" in proc.stdout, proc.stdout
    assert f"Not listed by the endpoint, written as 0: {ids[-1]}" in proc.stdout, proc.stdout
    assert "Listed by the endpoint but not in matrix.json, left out: T-9999" in proc.stdout, proc.stdout

    # The two techniques served samples carry one honeypot-telemetry entry citing this read,
    # and the others carry none: the entries the shipped file holds for the earlier read go.
    for t in matrix["techniques"]:
        expected = [(API_URL, today())] if t["id"] in ids[1:3] else []
        assert [(e["reference"], e["date"]) for e in t.get("evidence", []) if e["type"] == TELEMETRY] \
            == expected, t["id"]

    # No other field moves: every technique keeps the rest of its record, and the file
    # keeps every other top-level value.
    strip = ("wildPrevalence", "wildSampleCount", "evidence")
    for old, new in zip(original["techniques"], matrix["techniques"]):
        assert {k: v for k, v in new.items() if k not in strip} == {k: v for k, v in old.items() if k not in strip}
    skip = ("updated", "techniques", "wildPrevalenceSource")
    assert {k: v for k, v in matrix.items() if k not in skip} == {k: v for k, v in original.items() if k not in skip}

    # The STIX bundle is rendered again with the new updated date, so the tree validates.
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_sync_with_the_same_response_again_writes_nothing(tree):
    payload = write_payload(tree, served(load(tree)))
    first = run_sync(tree, "--payload", str(payload), "--read-date", today())
    assert first.returncode == 0, first.stdout + first.stderr
    matrix_bytes, stix_bytes = (tree / "matrix.json").read_bytes(), (tree / STIX).read_bytes()

    again = run_sync(tree, "--payload", str(payload), "--read-date", today())
    assert again.returncode == 0, again.stdout + again.stderr
    assert "nothing written" in again.stdout, again.stdout
    assert (tree / "matrix.json").read_bytes() == matrix_bytes
    assert (tree / STIX).read_bytes() == stix_bytes


def test_sync_keeps_a_read_date_older_than_today_and_still_moves_updated(tree):
    original = load(tree)
    original["updated"] = "2026-06-03"
    dump(tree, original)
    read = (date.today() - timedelta(days=3)).isoformat()
    payload = write_payload(tree, served(original))
    proc = run_sync(tree, "--payload", str(payload), "--read-date", read)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    matrix = load(tree)
    assert matrix["wildPrevalenceSource"]["read"] == read
    assert matrix["updated"] == today()


def kept(t: dict) -> list:
    """The entries of a technique that do not cite the endpoint, which the sync keeps."""
    return [e for e in t.get("evidence", []) if e["type"] != TELEMETRY]


def test_sync_dates_each_telemetry_entry_with_the_read_and_the_tree_validates(tree):
    original = load(tree)
    read = (date.today() - timedelta(days=3)).isoformat()
    payload = write_payload(tree, served(original))
    proc = run_sync(tree, "--payload", str(payload), "--read-date", read)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (f"and a {TELEMETRY} evidence entry dated {read} on the 2 with a wildSampleCount above 0"
            in proc.stdout), proc.stdout
    matrix = load(tree)
    ids = [t["id"] for t in matrix["techniques"]]
    for tid in ids[1:3]:
        # The entries that do not cite the endpoint stay first, as they were; the one
        # telemetry entry follows them.
        *others, entry = technique(matrix, tid)["evidence"]
        assert others == kept(technique(original, tid)), tid
        assert (entry["type"], entry["reference"], entry["date"]) == (TELEMETRY, API_URL, read), tid
    backed = {t["id"] for t in original["techniques"] if kept(t)}
    assert load(tree, "evidence-gaps.json")["ids"] == sorted(set(ids) - set(ids[1:3]) - backed)
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_sync_keeps_evidence_entries_that_do_not_cite_the_endpoint(tree):
    matrix = load(tree)
    ids = [t["id"] for t in matrix["techniques"]]
    other = {"type": "publication", "reference": "https://example.org/paper", "date": "2026-01-01"}
    for tid in (ids[1], ids[5]):
        technique(matrix, tid)["evidence"] = [dict(other)] + technique(matrix, tid).get("evidence", [])
    dump(tree, matrix)
    payload = write_payload(tree, served(matrix))
    proc = run_sync(tree, "--payload", str(payload), "--read-date", today())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    shipped = load(ROOT)
    matrix = load(tree)
    # Served samples: the other entries stay first, in their order, and the telemetry entry
    # follows them.
    assert [(e["type"], e["reference"]) for e in technique(matrix, ids[1])["evidence"]] == [
        ("publication", other["reference"])] + [
        (e["type"], e["reference"]) for e in kept(technique(shipped, ids[1]))] + [(TELEMETRY, API_URL)]
    # Served none: the other entries stay and no telemetry entry is written.
    assert technique(matrix, ids[5])["evidence"] == [other] + kept(technique(shipped, ids[5]))


def test_sync_drops_an_evidence_array_it_leaves_empty(tree):
    # T-2002 carries only the telemetry entry: its dvaaValidation names no DVAA challenge or
    # scenario, and no pinned page names it.
    shipped = technique(load(tree), "T-2002")
    assert [e["type"] for e in shipped["evidence"]] == [TELEMETRY]
    payload = served(load(tree))
    assert all(e["id"] != "T-2002" or e["wildSampleCount"] == 0 for e in payload["techniques"])
    proc = run_sync(tree, "--payload", str(write_payload(tree, payload)), "--read-date", today())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "evidence" not in technique(load(tree), "T-2002")
    assert "T-2002" in load(tree, "evidence-gaps.json")["ids"]


def test_sync_refuses_evidence_that_is_not_an_array_and_writes_nothing(tree):
    matrix = load(tree)
    matrix["techniques"][0]["evidence"] = "see the audit"
    dump(tree, matrix)
    before = (tree / "matrix.json").read_bytes()
    proc = run_sync(tree, "--payload", str(write_payload(tree, served(matrix))), "--read-date", today())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (f"FAIL: {matrix['techniques'][0]['id']}: evidence in matrix.json is not an array; "
            f"matrix.json is unchanged") in proc.stderr, proc.stderr
    assert (tree / "matrix.json").read_bytes() == before


def _entry(**values):
    def fn(payload):
        payload["techniques"][1].update(values)
    return fn


def _replace(new):
    def fn(payload):
        payload.clear()
        payload.update(new)
    return fn


def _duplicate(payload):
    payload["techniques"].append(dict(payload["techniques"][1]))


def _no_id(payload):
    del payload["techniques"][1]["id"]


def _foreign_ids(payload):
    payload["techniques"] = [{"id": "T-9998", "wildPrevalence": 1, "wildSampleCount": 1}]


REFUSED = [
    ("no techniques list", _replace({"version": "1.1"}), "the response holds no techniques list"),
    ("an empty techniques list", _replace({"techniques": []}), "the response holds no techniques list"),
    ("an entry without an id", _no_id, "techniques[1] in the response has no string id"),
    ("an id listed twice", _duplicate, "is listed twice in the response"),
    ("none of the ids", _foreign_ids, "the response lists none of the technique ids in matrix.json"),
    ("prevalence above 100", _entry(wildPrevalence=101), "wildPrevalence 101 is not a number from 0 to 100"),
    ("negative prevalence", _entry(wildPrevalence=-0.5), "wildPrevalence -0.5 is not a number from 0 to 100"),
    ("prevalence as a string", _entry(wildPrevalence="98.44"),
     "wildPrevalence '98.44' is not a number from 0 to 100"),
    ("prevalence as a boolean", _entry(wildPrevalence=True), "wildPrevalence True is not a number from 0 to 100"),
    ("prevalence NaN", _entry(wildPrevalence=float("nan")), "wildPrevalence nan is not a number from 0 to 100"),
    ("fractional sample count", _entry(wildSampleCount=1.5),
     "wildSampleCount 1.5 is not a whole number of 0 or more"),
    ("negative sample count", _entry(wildSampleCount=-3),
     "wildSampleCount -3 is not a whole number of 0 or more"),
    ("prevalence with no samples", _entry(wildPrevalence=50, wildSampleCount=0),
     "wildPrevalence 50 is served with a wildSampleCount of 0"),
]


@pytest.mark.parametrize("fn,needle", [pytest.param(fn, needle, id=name) for name, fn, needle in REFUSED])
def test_sync_refuses_and_leaves_the_tree_as_it_was(tree, fn, needle):
    payload = served(load(tree))
    fn(payload)
    path = write_payload(tree, payload)
    before = (tree / "matrix.json").read_bytes(), (tree / STIX).read_bytes()
    proc = run_sync(tree, "--payload", str(path), "--read-date", today())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert needle in proc.stderr, proc.stderr
    assert "matrix.json is unchanged" in proc.stderr, proc.stderr
    assert ((tree / "matrix.json").read_bytes(), (tree / STIX).read_bytes()) == before


@pytest.mark.parametrize("key", ["wildPrevalence", "wildSampleCount"])
def test_sync_refuses_an_integer_too_large_for_a_float_and_writes_nothing(tree, key):
    payload = {"techniques": [{"id": "T-1001", "wildPrevalence": 5, "wildSampleCount": 5}]}
    payload["techniques"][0][key] = HUGE
    path = write_payload(tree, payload)
    before = (tree / "matrix.json").read_bytes(), (tree / STIX).read_bytes()
    proc = run_sync(tree, "--payload", str(path), "--read-date", today())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr == (f"FAIL: T-1001: {key} is an integer of 401 digits, too large for a 64-bit "
                           f"float, so it is not a finite number; matrix.json is unchanged\n"), proc.stderr
    assert ((tree / "matrix.json").read_bytes(), (tree / STIX).read_bytes()) == before


def test_sync_writes_the_largest_sample_count_a_float_holds_and_the_tree_validates(tree):
    payload = served(load(tree))
    entry = payload["techniques"][1]
    entry["wildSampleCount"] = LARGEST
    path = write_payload(tree, payload)
    proc = run_sync(tree, "--payload", str(path), "--read-date", today())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert technique(load(tree), entry["id"])["wildSampleCount"] == LARGEST
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_sync_refuses_a_response_that_does_not_parse(tree):
    path = write_payload(tree, "<html>502 Bad Gateway</html>")
    before = (tree / "matrix.json").read_bytes()
    proc = run_sync(tree, "--payload", str(path), "--read-date", today())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"could not read {path}" in proc.stderr, proc.stderr
    assert (tree / "matrix.json").read_bytes() == before


def test_sync_refuses_a_matrix_that_does_not_parse(tree):
    path = write_payload(tree, served(load(tree)))
    (tree / "matrix.json").write_text("{not json", encoding="utf-8")
    proc = run_sync(tree, "--payload", str(path), "--read-date", today())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "could not read matrix.json" in proc.stderr, proc.stderr
    assert (tree / "matrix.json").read_text(encoding="utf-8") == "{not json"


USAGE = [
    ("payload without a read date", lambda p: ["--payload", p], "--payload needs --read-date"),
    ("read date without a payload", lambda p: ["--read-date", today()], "--read-date is the date of a --payload"),
    ("read date that is no date", lambda p: ["--payload", p, "--read-date", "2026-13-01"],
     "--read-date '2026-13-01' is not a YYYY-MM-DD date"),
    ("read date in the basic format", lambda p: ["--payload", p, "--read-date", "20261019"],
     "--read-date '20261019' is not a YYYY-MM-DD date"),
    ("read date after today", lambda p: ["--payload", p, "--read-date",
                                         (date.today() + timedelta(days=1)).isoformat()],
     "is later than today"),
]


@pytest.mark.parametrize("argv,needle", [pytest.param(a, n, id=name) for name, a, n in USAGE])
def test_sync_usage_errors_write_nothing(tree, argv, needle):
    path = write_payload(tree, served(load(tree)))
    before = (tree / "matrix.json").read_bytes()
    proc = run_sync(tree, *argv(str(path)))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert needle in proc.stderr, proc.stderr
    assert (tree / "matrix.json").read_bytes() == before


def load_module(root: Path):
    spec = importlib.util.spec_from_file_location("sync_wild_prevalence_under_test",
                                                  root / "scripts" / "sync_wild_prevalence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sync_fetches_the_endpoint_once_and_dates_the_read_today(tree, monkeypatch):
    module = load_module(tree)
    assert module.MATRIX == (tree / "matrix.json").resolve()
    body = json.dumps(served(load(tree))).encode("utf-8")
    calls = []

    def fake_urlopen(url, timeout=None):
        calls.append((url, timeout))
        return io.BytesIO(body)

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    assert module.main([]) == 0
    assert calls == [(API_URL, 30)]
    assert load(tree)["wildPrevalenceSource"] == {"url": API_URL, "read": today(), "period": closed_period()}


def test_sync_reports_a_failed_fetch_and_writes_nothing(tree, monkeypatch, capsys):
    module = load_module(tree)
    before = (tree / "matrix.json").read_bytes()

    def fake_urlopen(url, timeout=None):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    assert module.main([]) == 1
    assert f"could not fetch {API_URL}" in capsys.readouterr().err
    assert (tree / "matrix.json").read_bytes() == before


def test_sync_description_is_its_docstring_summary():
    module = load_module(ROOT)
    assert module.DESCRIPTION == module.__doc__.strip().splitlines()[0]


# --------------------------------------------------------------------------- closed periods only

def files(root: Path):
    """matrix.json, the STIX bundle and the technique pages, which the sync writes, as bytes."""
    return ((root / "matrix.json").read_bytes(), (root / STIX).read_bytes(),
            tuple(path.read_bytes() for path in sorted((root / "techniques").glob("*.md"))))


def sync(root: Path, payload, read: str = None) -> subprocess.CompletedProcess:
    return run_sync(root, "--payload", str(write_payload(root, payload)), "--read-date", read or today())


def bounds(period: dict) -> str:
    return f"{period['start']} to {period['end']}"


def test_sync_refuses_a_response_that_names_no_closed_period(tree):
    # The endpoint serves its values with no period: the file keeps the values it holds.
    payload = served(load(tree))
    del payload["wildPeriod"]
    before = files(tree)
    proc = sync(tree, payload)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr == ("FAIL: the response names no closed period in wildPeriod, so its values are "
                           "not copied until the registry serves one; matrix.json is unchanged\n"), proc.stderr
    assert files(tree) == before


def test_sync_fetch_of_a_response_that_names_no_closed_period_writes_nothing(tree, monkeypatch, capsys):
    module = load_module(tree)
    payload = served(load(tree))
    del payload["wildPeriod"]
    body = json.dumps(payload).encode("utf-8")
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout=None: io.BytesIO(body))
    before = files(tree)
    assert module.main([]) == 1
    assert "the response names no closed period in wildPeriod" in capsys.readouterr().err
    assert files(tree) == before


PERIOD_REFUSED = [
    ("a period that is not an object", lambda: "2026-10",
     "wildPeriod in the response is not an object with a start and an end"),
    ("a period without a start", lambda: {"end": days_ago(10)},
     "wildPeriod.start None in the response is not a YYYY-MM-DD date"),
    ("a period end that is no calendar date", lambda: {"start": "2026-02-01", "end": "2026-02-30"},
     "wildPeriod.end '2026-02-30' in the response is not a YYYY-MM-DD date"),
    ("a period end in the basic format", lambda: {"start": "2026-02-01", "end": "20260228"},
     "wildPeriod.end '20260228' in the response is not a YYYY-MM-DD date"),
    ("a period that starts after it ends", lambda: {"start": days_ago(10), "end": days_ago(40)},
     "after it ends on"),
    ("a period that ends on the read date", lambda: {"start": days_ago(30), "end": today()},
     "is not closed: it ends on or after the read date"),
    ("a period that ends after the read date",
     lambda: {"start": days_ago(30), "end": (date.today() + timedelta(days=5)).isoformat()},
     "is not closed: it ends on or after the read date"),
]


@pytest.mark.parametrize("period,needle", [pytest.param(p, n, id=name) for name, p, n in PERIOD_REFUSED])
def test_sync_refuses_a_period_that_is_not_closed_and_writes_nothing(tree, period, needle):
    payload = served(load(tree))
    payload["wildPeriod"] = period()
    before = files(tree)
    proc = sync(tree, payload)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert needle in proc.stderr, proc.stderr
    assert "matrix.json is unchanged" in proc.stderr, proc.stderr
    assert files(tree) == before


def test_sync_records_the_period_bounds_and_names_them_in_each_telemetry_note(tree):
    period = closed_period()
    proc = sync(tree, served(load(tree)))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    matrix = load(tree)
    assert f"for the closed period {bounds(period)} on {len(matrix['techniques'])} techniques" in proc.stdout
    assert matrix["wildPrevalenceSource"]["period"] == period
    notes = [e["note"] for t in matrix["techniques"] for e in t.get("evidence", []) if e["type"] == TELEMETRY]
    assert len(notes) == 2, notes
    for note in notes:
        assert f"served for the technique over the closed period {bounds(period)}, read on this date" in note
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_sync_writes_nothing_for_the_held_period_served_again_with_its_values(tree):
    payload = served(load(tree))
    held_read = days_ago(3)
    assert sync(tree, payload, held_read).returncode == 0
    before = files(tree)
    proc = sync(tree, payload)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout == (f"matrix.json already holds the values {API_URL} served for the closed period "
                           f"{bounds(closed_period())}, read {held_read}; nothing written\n"), proc.stdout
    assert files(tree) == before


def _more_samples(payload):
    payload["techniques"][1]["wildSampleCount"] += 1
    return payload["techniques"][1]["id"]


def _other_prevalence(payload):
    payload["techniques"][2]["wildPrevalence"] = 99.5
    return payload["techniques"][2]["id"]


def _unlisted(payload):
    return payload["techniques"].pop(2)["id"]


@pytest.mark.parametrize("change", [pytest.param(_more_samples, id="another sample count"),
                                    pytest.param(_other_prevalence, id="another prevalence"),
                                    pytest.param(_unlisted, id="a technique no longer listed")])
def test_sync_never_rewrites_a_value_held_for_a_period(tree, change):
    payload = served(load(tree))
    assert sync(tree, payload).returncode == 0
    before = files(tree)
    tid = change(payload)
    proc = sync(tree, payload)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr == (f"FAIL: matrix.json holds the values for the period {bounds(closed_period())}, "
                           f"and the response serves other values for it on {tid}; a value held for a "
                           f"period is never rewritten; matrix.json is unchanged\n"), proc.stderr
    assert files(tree) == before


OVERLAPPING = [
    ("a period that starts on the day the held one ends", lambda: {"start": days_ago(10), "end": days_ago(1)}),
    ("a period inside the held one", lambda: {"start": days_ago(30), "end": days_ago(20)}),
    ("a period that ends before the held one starts", lambda: {"start": days_ago(70), "end": days_ago(41)}),
]


@pytest.mark.parametrize("period", [pytest.param(p, id=name) for name, p in OVERLAPPING])
def test_sync_refuses_a_period_that_does_not_start_after_the_held_one(tree, period):
    assert sync(tree, served(load(tree))).returncode == 0
    before = files(tree)
    served_period = period()
    proc = sync(tree, served(load(tree), served_period))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr == (f"FAIL: the period {bounds(served_period)} does not start after "
                           f"{bounds(closed_period())}, the period matrix.json holds values for; a value "
                           f"held for a period is never rewritten; matrix.json is unchanged\n"), proc.stderr
    assert files(tree) == before


def test_sync_writes_the_next_closed_period_in_place_of_the_held_one(tree):
    assert sync(tree, served(load(tree))).returncode == 0
    following = {"start": days_ago(9), "end": days_ago(1)}
    payload = served(load(tree), following)
    payload["techniques"][1].update(wildPrevalence=50, wildSampleCount=12)
    proc = sync(tree, payload)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    matrix = load(tree)
    assert matrix["wildPrevalenceSource"] == {"url": API_URL, "read": today(), "period": following}
    entry = technique(matrix, payload["techniques"][1]["id"])
    assert (entry["wildPrevalence"], entry["wildSampleCount"]) == (50, 12)
    assert bounds(following) in entry["evidence"][-1]["note"]
    validated = run_validator(tree)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_sync_refuses_a_held_period_without_a_start_and_an_end(tree):
    matrix = load(tree)
    matrix["wildPrevalenceSource"]["period"] = {"start": "2026-09-01"}
    dump(tree, matrix)
    before = files(tree)
    proc = sync(tree, served(matrix))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr == ("FAIL: wildPrevalenceSource.period in matrix.json is not a YYYY-MM-DD start "
                           "and end; matrix.json is unchanged\n"), proc.stderr
    assert files(tree) == before


# --------------------------------------------------------------------------- the technique pages

def page_lines(root: Path) -> dict:
    """The lines of each technique page under root, by its file name."""
    return {path.name: path.read_text(encoding="utf-8").splitlines()
            for path in sorted((root / "techniques").glob("*.md"))}


def run_page_check(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "scripts" / "check_technique_pages.py")],
                          capture_output=True, text=True, timeout=120)


def test_sync_writes_the_evidence_lines_of_the_technique_pages_and_the_page_check_passes(tree):
    # The References section of a technique page lists the technique's evidence entries, one
    # Evidence line each, and scripts/check_technique_pages.py fails on a page whose lines
    # differ from them. A write dates each telemetry entry with its read and names its period
    # in the note, and drops the entry of each technique served no samples.
    assert run_page_check(tree).returncode == 0
    shipped = load(tree)
    before = page_lines(tree)
    listed_before = {t["id"] for t in shipped["techniques"]
                     if any(e["type"] == TELEMETRY for e in t.get("evidence", []))}
    period, read = closed_period(), days_ago(3)

    proc = sync(tree, served(shipped), read)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    checked = run_page_check(tree)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert "the technique pages list the evidence entries matrix.json now carries" in proc.stdout, proc.stdout

    matrix = load(tree)
    ids = [t["id"] for t in matrix["techniques"]]
    after = page_lines(tree)
    for tid in ids:
        name = f"{tid}.md"
        listed = [line for line in after[name] if line.startswith(f"- Evidence: {TELEMETRY} ")]
        if tid in ids[1:3]:
            # The two techniques served samples list the entry of this read.
            note = technique(matrix, tid)["evidence"][-1]["note"]
            assert bounds(period) in note, tid
            assert listed == [f"- Evidence: {TELEMETRY} dated {read}, [{API_URL}]({API_URL}). {note}"], tid
        else:
            assert listed == [], tid
        # Every line the write adds to a page or removes from it is an Evidence line.
        moved = [line[2:] for line in difflib.ndiff(before[name], after[name]) if line[:2] in ("- ", "+ ")]
        assert all(line.startswith("- Evidence: ") for line in moved), (tid, moved)
    # The pages that change are those of the techniques whose telemetry entry the write
    # replaced or dropped, and of those it gave one; the shipped file holds the earlier
    # read's entry on techniques beyond the two served samples, so some pages drop it.
    assert listed_before - set(ids[1:3])
    assert sorted(name for name in after if after[name] != before[name]) == \
        sorted(f"{tid}.md" for tid in listed_before | set(ids[1:3]))


def test_sync_exits_1_when_a_page_has_no_place_for_its_evidence_lines(tree):
    # Evidence lines sit directly under the Tactic link, so a page without one has no place
    # for them: scripts/check_technique_pages.py --fix reports the page and exits 1, after
    # matrix.json and the STIX bundle are written.
    tid = load(tree)["techniques"][1]["id"]
    page = tree / "techniques" / f"{tid}.md"
    text = page.read_text(encoding="utf-8")
    page.write_text("".join(line for line in text.splitlines(keepends=True)
                            if not line.startswith("- Tactic: [")), encoding="utf-8")
    proc = sync(tree, served(load(tree)))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stderr.startswith("FAIL: matrix.json, the STIX bundle and evidence-gaps.json are written, but "
                                  "scripts/check_technique_pages.py --fix failed:\n"), proc.stderr
    assert f"  - {tid}: References section does not list the evidence entries" in proc.stderr, proc.stderr
    assert load(tree)["wildPrevalenceSource"]["period"] == closed_period()
