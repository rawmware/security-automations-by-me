"""Hermetic tests for auth_watch (synthetic log lines, tmp files)."""

from sentinel import auth_watch

FAILED = ("Oct  2 12:00:0{} host sshd[123]: Failed password for invalid user "
          "admin from 203.0.113.7 port 5123 ssh2")
ACCEPTED = ("Oct  2 12:05:00 host sshd[124]: Accepted password for roman "
            "from 198.51.100.9 port 5124 ssh2")
NOISE = "Oct  2 12:06:00 host systemd[1]: Started daily cleanup."


def test_parse_failed():
    e = auth_watch.parse_line(FAILED.format(1))
    assert e["type"] == "failed" and e["user"] == "admin" and e["ip"] == "203.0.113.7"


def test_parse_accepted():
    e = auth_watch.parse_line(ACCEPTED)
    assert e["type"] == "accepted" and e["user"] == "roman"


def test_parse_ignores_noise():
    assert auth_watch.parse_line(NOISE) is None


def _events(n, users=("admin",)):
    return [{"type": "failed", "user": users[i % len(users)],
             "ip": "203.0.113.7", "ts": None} for i in range(n)]


def test_brute_force_classification():
    attacks = auth_watch.detect(_events(12, ("admin", "root")), threshold=10)
    assert len(attacks) == 1
    assert attacks[0]["kind"] == "brute-force"
    assert attacks[0]["over_threshold"] is True


def test_spraying_classification():
    users = tuple(f"user{i}" for i in range(6))
    attacks = auth_watch.detect(_events(12, users), threshold=10)
    assert attacks[0]["kind"] == "password-spraying"


def test_below_threshold_is_watch():
    attacks = auth_watch.detect(_events(4), threshold=10)
    assert attacks[0]["kind"] == "watch"
    assert attacks[0]["over_threshold"] is False


def test_tail_reads_only_new_lines(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("line1\nline2\n")
    state = {}
    assert auth_watch.tail_new_lines(str(p), state) == ["line1\n", "line2\n"]
    assert auth_watch.tail_new_lines(str(p), state) == []  # nothing new
    with p.open("a") as fh:
        fh.write("line3\n")
    assert auth_watch.tail_new_lines(str(p), state) == ["line3\n"]


def test_run_emits_spray_finding(tmp_path, monkeypatch):
    p = tmp_path / "auth.log"
    lines = "".join(FAILED.format(i) + "\n" for i in range(12))
    p.write_text(lines)
    cfg = {"log_path": str(p), "window_minutes": 6000, "threshold": 10}
    findings = auth_watch.run(cfg, {})
    assert any("brute-force" in f.title or "spraying" in f.title for f in findings)


def test_suggest_block_is_text_only():
    cmd = auth_watch.suggest_block("203.0.113.7")
    assert "203.0.113.7" in cmd and "ufw" in cmd
