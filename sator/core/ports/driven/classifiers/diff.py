from abc import ABC, abstractmethod
from sator.core.models.oss.diff import Diff
from sator.core.models.oss.annotation import DiffAnnotation


class DiffClassifierPort(ABC):
    @abstractmethod
    def classify_diff(self, diff: Diff) -> DiffAnnotation:
        raise NotImplementedError

