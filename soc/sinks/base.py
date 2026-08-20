from abc import ABC, abstractmethod

from ..schema import Result


class Sink(ABC):
    name: str

    @abstractmethod
    def emit(self, result: Result) -> bool:
        """Deliver one triage result. Return True if it was sent, False if skipped."""

    def close(self) -> None:
        pass
