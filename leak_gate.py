#!/usr/bin/env python3
"""Block unpublished research from leaving the machine."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unicodedata
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MAX_BODY = 2_000_000
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
SKIP_JSON_KEYS = {"authorization", "api_key", "api-key", "token", "password", "secret"}
REDACTABLE = {"SECRET", "PII", "HIDDEN-TEXT"}
PROOF_ENV = re.compile(r"\\begin\{pr" r"oof\}", re.I)
THEOREM_ENV = re.compile(r"\\begin\{(?:the" r"orem|lem" r"ma)\}", re.I)
HIDDEN_TEXT = re.compile(
    r"[\u00AD\u034F\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF"
    r"\U000E0001-\U000E007F]"
)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HEX_ESCAPE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
HEX_STRING = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40,}(?![0-9A-Fa-f])")
CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

SECRET_SPECS = (
    ("aws-access-key", re.compile(r"AKI" r"A[0-9A-Z]{16}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("openai-key", re.compile(r"sk-(?:proj|ant)-[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("pem-key", PEM),
)


def builtin_watchwords() -> tuple[str, ...]:
    return (
        "nav" "ier-sto" "kes",
        "nav" "ier sto" "kes",
        "yan" "g-mil" "ls",
        "yan" "g mil" "ls",
        "rie" "mann hypo" "thesis",
        "bir" "ch and swinner" "ton-dyer",
        "hod" "ge conjec" "ture",
        "p ver" "sus np",
        "p v" "s np",
        "millenn" "ium pri" "ze",
        "unpub" "lished pr" "oof",
        "do not circ" "ulate",
        "do not dist" "ribute",
    )


@dataclass(frozen=True)
class Hit:
    rule: str
    detail: str


@dataclass(frozen=True)
class Result:
    verdict: str
    sha256: str
    nbytes: int
    hits: tuple[Hit, ...]
    redacted: str | None = None


@dataclass
class Policy:
    watchwords: list[str] = field(default_factory=list)
    regexes: list[tuple[str, re.Pattern[str]]] = field(default_factory=list)
    secrets: bool = True
    pii: bool = False


class Vault:
    """In-memory original <-> placeholder map. Never written to disk."""

    def __init__(self) -> None:
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.n = 0

    def token(self, original: str) -> str:
        existing = self.forward.get(original)
        if existing is not None:
            return existing
        self.n += 1
        placeholder = f"<<LG:{self.n}>>"
        self.forward[original] = placeholder
        self.reverse[placeholder] = original
        return placeholder


def normalize(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = re.sub(r"[\u2010-\u2015\u2212_-]+", " ", folded)
    folded = re.sub(r"\s+", " ", folded)
    return folded.strip()


def watchword_regex(word: str) -> re.Pattern[str]:
    tokens = [re.escape(token) for token in word.split() if token]
    gap = r"[\s\u2010-\u2015\u2212_-]+"
    return re.compile(gap.join(tokens), re.I)


def luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    alt = False
    for char in reversed(digits):
        n = ord(char) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def try_utf8(data: bytes) -> str | None:
    if len(data) < 8:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    if printable / len(text) < 0.9:
        return None
    if not re.search(r"[A-Za-z]{3,}", text):
        return None
    return text


def try_b64(raw: str) -> str | None:
    pad = (-len(raw)) % 4
    if pad == 3:
        return None
    try:
        data = base64.b64decode(raw + "=" * pad, validate=True)
    except (ValueError, binascii.Error):
        return None
    return try_utf8(data)


def try_hex(raw: str) -> str | None:
    hex_chars = re.sub(r"^\\x|\\x", "", raw, flags=re.I)
    if len(hex_chars) % 2:
        return None
    try:
        data = bytes.fromhex(hex_chars)
    except ValueError:
        return None
    return try_utf8(data)


def decode_blobs(text: str, depth: int = 2, limit: int = 16) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    frontier = [text]
    extractors = (
        (BASE64_BLOB, try_b64),
        (HEX_ESCAPE, try_hex),
        (HEX_STRING, try_hex),
    )
    for _ in range(depth):
        nxt: list[str] = []
        for src in frontier:
            for regex, decoder in extractors:
                for match in regex.finditer(src):
                    decoded = decoder(match.group(0))
                    if not decoded or decoded in seen:
                        continue
                    seen.add(decoded)
                    found.append(decoded)
                    nxt.append(decoded)
                    if len(found) >= limit:
                        return found
        frontier = nxt
        if not frontier:
            break
    return found


def load_policy(
    paths: list[Path],
    *,
    use_builtin: bool,
    secrets: bool,
    pii: bool,
) -> Policy:
    policy = Policy(secrets=secrets, pii=pii)
    seen: set[str] = set()

    def add_word(raw: str) -> None:
        item = normalize(raw)
        if item and item not in seen:
            seen.add(item)
            policy.watchwords.append(item)

    if use_builtin:
        for word in builtin_watchwords():
            add_word(word)
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for index, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("re:"):
                pattern = stripped[3:]
                try:
                    policy.regexes.append((f"{path.name}:{index}", re.compile(pattern)))
                except re.error as error:
                    raise SystemExit(f"invalid regex in {path}:{index}: {error}") from error
            else:
                add_word(stripped)
    return policy


def collect_hits(text: str, policy: Policy, *, scan_encoded: bool = True) -> list[Hit]:
    hits: list[Hit] = []
    if HIDDEN_TEXT.search(text):
        hits.append(Hit("HIDDEN-TEXT", "hidden or bidirectional characters"))
    if policy.secrets:
        for name, regex in SECRET_SPECS:
            if regex.search(text):
                hits.append(Hit("SECRET", name))
        for match in CARD_CANDIDATE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if luhn_ok(digits):
                hits.append(Hit("PII", "credit-card"))
                break
        if SSN.search(text):
            hits.append(Hit("PII", "ssn"))
    if policy.pii and EMAIL.search(text):
        hits.append(Hit("PII", "email"))
    for name, regex in policy.regexes:
        if regex.search(text):
            hits.append(Hit("USER-REGEX", name))
    normalized = normalize(text)
    for word in policy.watchwords:
        if word and word in normalized:
            hits.append(Hit("WATCHWORD", word))
    if PROOF_ENV.search(text):
        hits.append(Hit("PROOF-ENV", "latex proof environment"))
    if THEOREM_ENV.search(text) and len(text) >= 4_000:
        hits.append(Hit("THEOREM-DUMP", "large latex theorem or lemma dump"))
    if len(text) >= 20_000 and text.count("$") >= 40:
        hits.append(Hit("LATEX-DUMP", "large latex payload"))
    if scan_encoded:
        for blob in decode_blobs(text):
            for item in collect_hits(blob, policy, scan_encoded=False):
                if item.rule != "HIDDEN-TEXT":
                    hits.append(Hit("ENCODED", f"{item.rule}:{item.detail}"))
    return hits


def check_text(text: str, policy: Policy) -> Result:
    hits = tuple(collect_hits(text, policy))
    return Result(
        "BLOCK" if hits else "PASS",
        hashlib.sha256(text.encode("utf-8")).hexdigest(),
        len(text.encode("utf-8")),
        hits,
    )


def redact_text(text: str, policy: Policy, vault: Vault) -> str:
    stripped = HIDDEN_TEXT.sub("", text)
    replacements: list[tuple[int, int, str]] = []

    def mark(match: re.Match[str]) -> None:
        replacements.append((match.start(), match.end(), vault.token(match.group(0))))

    if policy.secrets:
        for _, regex in SECRET_SPECS:
            for match in regex.finditer(stripped):
                mark(match)
        for match in CARD_CANDIDATE.finditer(stripped):
            digits = re.sub(r"\D", "", match.group(0))
            if luhn_ok(digits):
                mark(match)
        for match in SSN.finditer(stripped):
            mark(match)
    if policy.pii:
        for match in EMAIL.finditer(stripped):
            mark(match)
    replacements.sort(key=lambda item: (item[0], -item[1]))
    merged: list[tuple[int, int, str]] = []
    last = -1
    for start, end, token in replacements:
        if start < last:
            continue
        merged.append((start, end, token))
        last = end
    if not merged:
        return stripped
    out: list[str] = []
    cursor = 0
    for start, end, token in merged:
        out.append(stripped[cursor:start])
        out.append(token)
        cursor = end
    out.append(stripped[cursor:])
    return "".join(out)


def restore_text(text: str, vault: Vault) -> str:
    out = text
    for placeholder, original in sorted(vault.reverse.items(), key=lambda item: -len(item[0])):
        out = out.replace(placeholder, original)
    return out


def extract_text(payload: object) -> str:
    chunks: list[str] = []

    def walk(value: object, key: str | None = None) -> None:
        if key is not None and key.casefold() in SKIP_JSON_KEYS:
            return
        if isinstance(value, str):
            chunks.append(value)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, str(child_key))

    walk(payload)
    return "\n".join(chunks)


def map_strings(payload: object, transform) -> object:
    if isinstance(payload, str):
        return transform(payload)
    if isinstance(payload, list):
        return [map_strings(item, transform) for item in payload]
    if isinstance(payload, dict):
        out = {}
        for key, value in payload.items():
            if str(key).casefold() in SKIP_JSON_KEYS:
                out[key] = value
            else:
                out[key] = map_strings(value, transform)
        return out
    return payload


def blocking_hits(hits: tuple[Hit, ...]) -> list[Hit]:
    return [item for item in hits if item.rule not in REDACTABLE]


def default_config_dir() -> Path:
    return Path.home() / ".leak-gate"


def default_watchword_path() -> Path:
    return default_config_dir() / "watchwords.txt"


def default_ledger_path() -> Path:
    return default_config_dir() / "ledger.jsonl"


def gate_sha256() -> str:
    digest = hashlib.sha256()
    with Path(__file__).resolve().open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_ledger(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def ledger_record(kind: str, result: Result, extra: dict[str, object] | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        "bytes": result.nbytes,
        "gate_sha256": gate_sha256(),
        "hits": [asdict(item) for item in result.hits],
        "kind": kind,
        "sha256": result.sha256,
        "ts": datetime.now(timezone.utc).isoformat(),
        "verdict": result.verdict,
    }
    if extra:
        record.update(extra)
    return record


def read_input(paths: list[Path]) -> str:
    if not paths:
        return sys.stdin.read()
    parts: list[str] = []
    for path in paths:
        if str(path) == "-":
            parts.append(sys.stdin.read())
        else:
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def print_result(result: Result, *, as_json: bool) -> None:
    payload = {
        "verdict": result.verdict,
        "sha256": result.sha256,
        "bytes": result.nbytes,
        "hits": [asdict(item) for item in result.hits],
        "gate_sha256": gate_sha256(),
    }
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    print(f"Verdict: {result.verdict}")
    print(f"SHA-256: {result.sha256}")
    for item in result.hits:
        print(f"{item.rule:12} {item.detail}")
    if not result.hits:
        print("No watchword or dump pattern matched. That is not proof the text is safe to send.")


def confirm_send() -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input("BLOCK: send anyway? [y/N] ").strip().casefold()
    return answer in {"y", "yes"}


def join_url(upstream: str, path: str) -> str:
    base = upstream.rstrip("/")
    route = path if path.startswith("/") else f"/{path}"
    if base.endswith("/v1") and route.startswith("/v1/"):
        return base + route[3:]
    return base + route


class GateHandler(BaseHTTPRequestHandler):
    server: "GateServer"

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] in {"/health", "/v1/health"}:
            self._send_json(200, {"status": "ok", "bind": "localhost", "mode": self.server.mode})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except Exception as error:
            self._send_json(403, {
                "error": {
                    "message": "leak-gate failed closed",
                    "type": "leak_gate_error",
                    "detail": error.__class__.__name__,
                }
            })

    def _handle_post(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        if length > MAX_BODY:
            self._send_json(413, {"error": "payload too large"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
            text = extract_text(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(403, {
                "error": {
                    "message": "leak-gate failed closed: body is not JSON",
                    "type": "leak_gate_error",
                }
            })
            return
        result = check_text(text, self.server.policy)
        blocked = blocking_hits(result.hits)
        append_ledger(
            self.server.ledger,
            ledger_record("proxy", result, {"mode": self.server.mode, "path": self.path.split("?", 1)[0]}),
        )
        if blocked or (result.verdict == "BLOCK" and self.server.mode == "block"):
            self._send_json(403, {
                "error": {
                    "message": "leak-gate blocked this request",
                    "type": "leak_gate_blocked",
                    "hits": [asdict(item) for item in result.hits],
                    "sha256": result.sha256,
                }
            })
            return
        vault = Vault()
        outbound: bytes = raw
        if self.server.mode == "redact" and result.hits:
            redacted_payload = map_strings(payload, lambda value: redact_text(value, self.server.policy, vault))
            outbound = json.dumps(redacted_payload, ensure_ascii=False).encode("utf-8")
        url = join_url(self.server.upstream, self.path)
        headers = {}
        for key, value in self.headers.items():
            if key.lower() in {"host", "content-length"}:
                continue
            headers[key] = value
        request = urllib.request.Request(url, data=outbound, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                body = response.read()
                if vault.reverse:
                    body = restore_text(body.decode("utf-8", "replace"), vault).encode("utf-8")
                self.send_response(response.status)
                for key, value in response.headers.items():
                    if key.lower() in {"transfer-encoding", "connection", "content-length"}:
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as error:
            payload_bytes = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(payload_bytes)))
            self.end_headers()
            self.wfile.write(payload_bytes)
        except urllib.error.URLError as error:
            self._send_json(502, {"error": f"upstream unreachable: {error.reason}"})


class GateServer(ThreadingHTTPServer):
    def __init__(self, bind: tuple[str, int], policy: Policy, ledger: Path, upstream: str, mode: str) -> None:
        super().__init__(bind, GateHandler)
        self.policy = policy
        self.ledger = ledger
        self.upstream = upstream
        self.mode = mode


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        watch_path = root / "watchwords.txt"
        watch_path.write_text("codename-orion\nre:project[- ]hydra\n", encoding="utf-8")
        policy = load_policy([watch_path], use_builtin=True, secrets=True, pii=True)
        clean = check_text("rewrite this paragraph in spanish.\n", policy)
        assert clean.verdict == "PASS", clean
        phrase = "nav" + "ier-sto" + "kes"
        blocked = check_text(f"consider finite-time blowup for {phrase} with smooth data.\n", policy)
        assert blocked.verdict == "BLOCK"
        assert any(item.rule == "WATCHWORD" for item in blocked.hits)
        assert check_text("draft notes on codename-orion stay on this laptop.\n", policy).verdict == "BLOCK"
        assert any(item.rule == "USER-REGEX" for item in check_text("see project-hydra notes.\n", policy).hits)
        proof = check_text("\\begin{pr" + "oof}\nlet epsilon > 0.\n\\end{pr" + "oof}\n", policy)
        assert any(item.rule == "PROOF-ENV" for item in proof.hits)
        aws = "AKI" + "A" + "IOSFODNN7EXAMPLE"
        secret = check_text(f"deploy with {aws}\n", policy)
        assert any(item.rule == "SECRET" for item in secret.hits)
        card = "4111" + "1111" + "1111" + "1111"
        assert any(item.detail == "credit-card" for item in check_text(f"card {card}\n", policy).hits)
        packed = base64.b64encode(f"help with {phrase}\n".encode()).decode("ascii")
        encoded = check_text(f"payload={packed}\n", policy)
        assert any(item.rule == "ENCODED" for item in encoded.hits)
        hidden = check_text("ok\u200bsecret\n", policy)
        assert any(item.rule == "HIDDEN-TEXT" for item in hidden.hits)
        payload = {"messages": [{"role": "user", "content": f"help me with {phrase}"}]}
        assert check_text(extract_text(payload), policy).verdict == "BLOCK"
        tools = {"tool_calls": [{"function": {"arguments": json.dumps({"key": aws})}}]}
        assert any(item.rule == "SECRET" for item in check_text(extract_text(tools), policy).hits)
        vault = Vault()
        redacted = redact_text(f"deploy with {aws} please\n", policy, vault)
        assert aws not in redacted
        assert aws in restore_text(redacted, vault)
        assert "<<LG:" in redacted
        stamp_path = root / "notes.lean"
        stamp_path.write_text("def id (x : Nat) := x\n", encoding="utf-8")
        stamped = check_text(stamp_path.read_text(encoding="utf-8"), policy)
        ledger = root / "ledger.jsonl"
        append_ledger(ledger, ledger_record("stamp", stamped, {"path": str(stamp_path)}))
        raw_ledger = ledger.read_text(encoding="utf-8")
        assert "id (x : Nat)" not in raw_ledger
        assert aws not in raw_ledger
        line = json.loads(raw_ledger)
        assert line["sha256"] == stamped.sha256
        assert "gate_sha256" in line
        assert join_url("https://api.example.com/v1", "/v1/chat/completions") == "https://api.example.com/v1/chat/completions"
        assert blocking_hits(secret.hits) == []
        assert blocking_hits(blocked.hits)
    print("self-test: ok")


def add_policy_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--watchwords", action="append", type=Path, default=[], help="extra watchword files")
    parser.add_argument("--no-builtin", action="store_true", help="do not load the built-in prize-name list")
    parser.add_argument("--no-secrets", action="store_true", help="do not flag API keys, PEM, or cards")
    parser.add_argument("--pii", action="store_true", help="also flag email addresses")
    parser.add_argument("--ledger", type=Path, help="hash-only ledger (default: ~/.leak-gate/ledger.jsonl)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Block unpublished research from leaving the machine")
    parser.add_argument("--self-test", action="store_true", help="run the built-in regression check")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="inspect a prompt, file, or stdin")
    check.add_argument("paths", nargs="*", type=Path, help="files to inspect; stdin when omitted")
    add_policy_flags(check)
    check.add_argument("--json", action="store_true")
    check.add_argument("--confirm", action="store_true")

    stamp = sub.add_parser("stamp", help="hash a local file for priority without sending it")
    stamp.add_argument("path", type=Path)
    add_policy_flags(stamp)
    stamp.add_argument("--json", action="store_true")

    serve = sub.add_parser("serve", help="localhost proxy that checks or redacts before forwarding")
    serve.add_argument("--upstream", required=True, help="base URL, for example https://api.x.ai/v1")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--mode", choices=("block", "redact"), default="block",
                       help="block = refuse hits; redact = strip secrets/PII, still block research watchwords")
    add_policy_flags(serve)

    wrap = sub.add_parser("wrap", help="run a command with OpenAI/Anthropic base URLs pointed at the gate")
    wrap.add_argument("--upstream", required=True)
    wrap.add_argument("--host", default="127.0.0.1")
    wrap.add_argument("--port", type=int, default=8787)
    wrap.add_argument("--mode", choices=("block", "redact"), default="block")
    add_policy_flags(wrap)
    wrap.add_argument("cmd", nargs=argparse.REMAINDER, help="command after --")
    return parser.parse_args()


def resolve_watchword_paths(extra: list[Path]) -> list[Path]:
    paths: list[Path] = []
    default = default_watchword_path()
    if default.exists():
        paths.append(default)
    paths.extend(extra)
    return paths


def policy_from_args(args: argparse.Namespace) -> Policy:
    return load_policy(
        resolve_watchword_paths(args.watchwords),
        use_builtin=not args.no_builtin,
        secrets=not args.no_secrets,
        pii=args.pii,
    )


def run_server(args: argparse.Namespace) -> GateServer:
    if args.host not in LOCAL_HOSTS:
        raise SystemExit("serve only binds to localhost")
    if args.port < 1:
        raise SystemExit("--port must be positive")
    policy = policy_from_args(args)
    ledger = args.ledger or default_ledger_path()
    server = GateServer((args.host, args.port), policy, ledger, args.upstream, args.mode)
    return server


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.command:
        raise SystemExit("pass check, stamp, serve, wrap, or --self-test")

    if args.command in {"serve", "wrap"}:
        server = run_server(args)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        if args.command == "serve":
            print(f"leak-gate listening on http://{args.host}:{args.port} -> {args.upstream} ({args.mode})", file=sys.stderr)
            print("prompts are hashed, not stored. secrets can be redacted in --mode redact.", file=sys.stderr)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\nstopped", file=sys.stderr)
            return 0
        command = list(args.cmd)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise SystemExit("wrap needs a command after --")
        thread.start()
        env = os.environ.copy()
        root = f"http://{args.host}:{args.port}"
        env["OPENAI_BASE_URL"] = f"{root}/v1"
        env["OPENAI_API_BASE"] = f"{root}/v1"
        env["ANTHROPIC_BASE_URL"] = root
        try:
            return subprocess.call(command, env=env)
        finally:
            server.shutdown()

    policy = policy_from_args(args)
    ledger = args.ledger or default_ledger_path()

    if args.command == "stamp":
        text = args.path.read_text(encoding="utf-8")
        result = check_text(text, policy)
        append_ledger(ledger, ledger_record("stamp", result, {"path": str(args.path)}))
        if args.json:
            print(json.dumps({
                "kind": "stamp",
                "path": str(args.path),
                "sha256": result.sha256,
                "bytes": result.nbytes,
                "verdict": result.verdict,
                "hits": [asdict(item) for item in result.hits],
                "gate_sha256": gate_sha256(),
            }, indent=2))
        else:
            print(f"STAMP {args.path}")
            print(f"SHA-256: {result.sha256}")
            print("Keep this hash somewhere that is not a frontier chat.")
        return 0

    text = read_input(args.paths)
    result = check_text(text, policy)
    if result.verdict == "BLOCK" and args.confirm and confirm_send():
        result = Result("PASS", result.sha256, result.nbytes, result.hits)
    append_ledger(ledger, ledger_record("check", result))
    print_result(result, as_json=args.json)
    return 2 if result.verdict == "BLOCK" else 0


if __name__ == "__main__":
    raise SystemExit(main())
