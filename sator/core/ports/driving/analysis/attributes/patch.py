from abc import ABC, abstractmethod

from sator.core.models.patch.locator import PatchLocator


class PatchAttributesAnalysisPort(ABC):
    @abstractmethod
    def analyze_patch_attributes(self, vulnerability_id: str) -> PatchLocator | None:
        raise NotImplementedError
