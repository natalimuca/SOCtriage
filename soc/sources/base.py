from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator

from ..schema import Alert


class Source(ABC):
    @abstractmethod
    def fetch(self, since: datetime | None = None, limit: int = 500) -> Iterator[Alert]:
        ...
