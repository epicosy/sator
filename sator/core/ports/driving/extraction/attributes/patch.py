from abc import ABC, abstractmethod

from sator.core.models.patch.attributes import PatchAttributes


class PatchAttributesExtractionPort(ABC):
    @abstractmethod
    def extract_patch_attributes(self, vulnerability_id: str) -> PatchAttributes | None:
        raise NotImplementedError
