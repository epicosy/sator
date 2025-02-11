from abc import ABC, abstractmethod

from sator.core.models.enums import DiffHunkType


class DiffAnnotationPort(ABC):

    @abstractmethod
    def annotate_diff(self, vulnerability_id: str) -> DiffHunkType | None:
        raise NotImplementedError
