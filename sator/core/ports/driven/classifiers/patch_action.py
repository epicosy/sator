
from abc import ABC, abstractmethod

from sator.core.models.enums import PatchActionType


class PatchActionClassifierPort(ABC):
    @abstractmethod
    def classify_patch_action(self, action: str) -> PatchActionType | None:
        raise NotImplementedError
