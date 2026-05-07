from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AdapterResult:
    ok: bool
    error: str | None
    response_len: int
    frames_accepted: int
    output_bytes: int
    progress: int
    latency_us: float


class TCGAdapter:
    def __init__(self, probe_path: str | None = None) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        self.probe_module_dir = repo_root / "integrations/go-tcg-storage"
        self.probe_path = Path(probe_path) if probe_path else (
            self.probe_module_dir / "cmd/wb_tcg_probe"
        )

    def reset(self) -> None:
        return None

    def feed(self, data: bytes) -> AdapterResult:
        payload = {
            "response_hex": data.hex(),
            "proto": 1,
            "sps": 1,
            "com_id": 1,
        }

        proc = subprocess.run(
            ["go", "run", "./cmd/wb_tcg_probe"],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            cwd=self.probe_module_dir,
        )

        if not proc.stdout:
            return AdapterResult(
                ok=False,
                error=proc.stderr.decode("utf-8", errors="replace") or "probe produced no stdout",
                response_len=0,
                frames_accepted=0,
                output_bytes=0,
                progress=0,
                latency_us=0.0,
            )

        raw = json.loads(proc.stdout.decode("utf-8"))

        ok = bool(raw.get("ok", False))
        parsed_hex = raw.get("parsed_hex") or ""
        output_bytes = len(parsed_hex) // 2

        return AdapterResult(
            ok=ok,
            error=raw.get("error"),
            response_len=int(raw.get("response_len", 0)),
            frames_accepted=1 if ok and output_bytes > 0 else 0,
            output_bytes=output_bytes,
            progress=int(raw.get("if_recv_calls", 0)),
            latency_us=float(raw.get("latency_us", 0.0)),
        )

    def inject_heartbeat(self) -> bool:
        result = self.feed(b"\xaa\x00")
        return result.ok

    def teardown(self) -> None:
        return None
