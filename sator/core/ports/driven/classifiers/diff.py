from abc import ABC, abstractmethod
from sator.core.models.oss.diff import Diff
from sator.core.models.patch.descriptor import DiffDescriptor


class DiffClassifierPort(ABC):
    @abstractmethod
    def classify_diff(self, diff: Diff) -> DiffDescriptor:
        raise NotImplementedError

    @abstractmethod
    def is_security_diff_message(self, message: str) -> bool | None:
        raise NotImplementedError
