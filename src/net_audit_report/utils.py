from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
import json
import csv
from typing import Any, Iterable


def ensure_outdir(outdir: str | Path) -> Path:
    p = Path(outdir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    return obj


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(to_jsonable(data), indent=2, sort_keys=False))


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
