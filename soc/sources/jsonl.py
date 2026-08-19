import json
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ..schema import Alert
from .base import Source
from .wazuh import parse as parse_wazuh


class JsonlSource(Source):
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def fetch(self, since: datetime | None = None, limit: int = 500) -> Iterator[Alert]:
        count = 0
        with self.path.open(encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                doc = record if "_source" in record else {"_id": record.get("id", f"a{i}"), "_source": record}
                alert = parse_wazuh(doc)
                if since and alert.timestamp <= since:
                    continue
                yield alert
                count += 1
                if count >= limit:
                    return
