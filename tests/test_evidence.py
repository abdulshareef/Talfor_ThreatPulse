import json

from threatpulse.evidence import EvidenceLedger, verify_ledger


def _ledger(tmp_path, n=5):
    p = tmp_path / "l.jsonl"
    led = EvidenceLedger(str(p))
    for i in range(n):
        led.append({"i": i, "msg": f"alert {i}"})
    led.close()
    return p, led.head


def test_ledger_ok(tmp_path):
    p, head = _ledger(tmp_path)
    ok, n, h, _ = verify_ledger(str(p), head)
    assert ok and n == 5 and h == head


def test_ledger_detects_edit(tmp_path):
    p, head = _ledger(tmp_path)
    lines = p.read_text().splitlines()
    e = json.loads(lines[2]); e["record"]["msg"] = "edited"; lines[2] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    ok, *_ , msg = verify_ledger(str(p), head)
    assert not ok and "altered" in msg


def test_ledger_detects_deletion_and_truncation(tmp_path):
    p, head = _ledger(tmp_path)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not verify_ledger(str(p), head)[0]
    p.write_text("\n".join(lines[:4]) + "\n")
    ok, *_, msg = verify_ledger(str(p), head)
    assert not ok and "head" in msg


def test_ledger_resumes_chain(tmp_path):
    p, _ = _ledger(tmp_path, 2)
    led = EvidenceLedger(str(p)); led.append({"i": 99}); led.close()
    assert verify_ledger(str(p), led.head)[0]
