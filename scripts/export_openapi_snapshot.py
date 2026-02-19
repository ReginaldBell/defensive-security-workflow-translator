from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import app


def main() -> int:
    snapshot_path = Path("openapi") / "openapi.snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)

    spec = app.openapi()
    snapshot_path.write_text(
        json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote OpenAPI snapshot to {snapshot_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
