from abc import ABC, abstractmethod

from sator.core.models.oss.annotation import DiffAnnotation


class DiffAnnotationPort(ABC):

    @abstractmethod
    def annotate_diff(self, vulnerability_id: str) -> DiffAnnotation | None:
        raise NotImplementedError
