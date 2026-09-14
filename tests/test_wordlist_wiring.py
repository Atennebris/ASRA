"""Every tool that can consult an operator-assigned wordlist (agent/tools/wordlist_store.py) --
ffuf, Hydra, and web_login_bruteforce's own builders -- must actually use it when the model didn't
supply its own explicit wordlist/list, and must still let an explicit model choice win over it.
arjun_probe's own equivalent test lives in tests/test_arjun_native.py (it's a native tier-1
function, not a build_command()-shaped builder, so it belongs next to arjun_probe's other tests).
"""
import tempfile
from pathlib import Path

from agent.tools import wordlist_store
from agent.tools.builders.ffuf import build_ffuf_command
from agent.tools.builders.hydra import build_hydra_command
from agent.tools.builders.web_login_bruteforce import build_web_login_bruteforce_command


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")


def test_ffuf_uses_the_assigned_wordlist_when_the_model_gives_none(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assigned = tmp_path / "assigned.txt"
    assigned.write_text("a\n", encoding="utf-8")
    wordlist_store.set_assignment("ffuf", str(assigned))

    command = build_ffuf_command({"target": "http://example.com/FUZZ"})

    assert command[command.index("-w") + 1] == str(assigned)


def test_ffuf_explicit_wordlist_wins_over_the_assignment(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assigned = tmp_path / "assigned.txt"
    assigned.write_text("a\n", encoding="utf-8")
    wordlist_store.set_assignment("ffuf", str(assigned))

    command = build_ffuf_command({"target": "http://example.com/FUZZ", "wordlist": "/custom/list.txt"})

    assert command[command.index("-w") + 1] == "/custom/list.txt"


def test_hydra_uses_assigned_usernames_and_passwords_when_the_model_gives_none(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    users_file = tmp_path / "users.txt"
    users_file.write_text("root\nadmin\n", encoding="utf-8")
    passwords_file = tmp_path / "passwords.txt"
    passwords_file.write_text("hunter2\n", encoding="utf-8")
    wordlist_store.set_assignment("hydra_usernames", str(users_file))
    wordlist_store.set_assignment("hydra_passwords", str(passwords_file))

    job_dir = Path(tempfile.mkdtemp())
    command = build_hydra_command({"target": "ssh://1.2.3.4", "protocol": "ssh"}, "job1", job_dir)

    assert command[command.index("-L") + 1] == str(users_file)
    assert command[command.index("-P") + 1] == str(passwords_file)


def test_hydra_explicit_username_list_wins_over_the_assignment(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    users_file = tmp_path / "users.txt"
    users_file.write_text("root\n", encoding="utf-8")
    wordlist_store.set_assignment("hydra_usernames", str(users_file))

    job_dir = Path(tempfile.mkdtemp())
    command = build_hydra_command(
        {"target": "ssh://1.2.3.4", "protocol": "ssh", "username_list": ["custom1", "custom2"]}, "job1", job_dir,
    )

    users_path = Path(command[command.index("-L") + 1])
    assert users_path.read_text(encoding="utf-8").splitlines() == ["custom1", "custom2"]


def test_web_login_bruteforce_uses_assigned_passwords_when_the_model_gives_none(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    passwords_file = tmp_path / "web_passwords.txt"
    passwords_file.write_text("pw1\npw2\npw3\n", encoding="utf-8")
    wordlist_store.set_assignment("web_login_bruteforce_passwords", str(passwords_file))

    job_dir = Path(tempfile.mkdtemp())
    build_web_login_bruteforce_command(
        {"target": "http://example.com", "login_path": "/login", "failure_string": "bad"}, "job1", job_dir,
    )

    import json
    config = json.loads((job_dir / "job1_config.json").read_text(encoding="utf-8"))
    assert config["passwords"] == ["pw1", "pw2", "pw3"]


def test_web_login_bruteforce_caps_an_assigned_wordlist_at_the_line_limit(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    from agent.tools.builders import web_login_bruteforce as wlb

    monkeypatch.setattr(wlb, "_MAX_ASSIGNED_WORDLIST_LINES", 3)
    passwords_file = tmp_path / "huge.txt"
    passwords_file.write_text("\n".join(f"pw{i}" for i in range(100)), encoding="utf-8")
    wordlist_store.set_assignment("web_login_bruteforce_passwords", str(passwords_file))

    job_dir = Path(tempfile.mkdtemp())
    wlb.build_web_login_bruteforce_command(
        {"target": "http://example.com", "login_path": "/login", "failure_string": "bad"}, "job1", job_dir,
    )

    import json
    config = json.loads((job_dir / "job1_config.json").read_text(encoding="utf-8"))
    assert config["passwords"] == ["pw0", "pw1", "pw2"]


def test_web_login_bruteforce_explicit_password_list_wins_over_the_assignment(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    passwords_file = tmp_path / "web_passwords.txt"
    passwords_file.write_text("pw1\n", encoding="utf-8")
    wordlist_store.set_assignment("web_login_bruteforce_passwords", str(passwords_file))

    job_dir = Path(tempfile.mkdtemp())
    build_web_login_bruteforce_command(
        {
            "target": "http://example.com", "login_path": "/login", "failure_string": "bad",
            "password_list": ["custom_pw"],
        },
        "job1", job_dir,
    )

    import json
    config = json.loads((job_dir / "job1_config.json").read_text(encoding="utf-8"))
    assert config["passwords"] == ["custom_pw"]
