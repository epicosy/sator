from abc import ABC, abstractmethod

from sator.core.models.patch.references import PatchReferences


class PatchReferencesResolutionPort(ABC):

    @abstractmethod
    def search_patch_references(self, vulnerability_id: str) -> PatchReferences | None:
        raise NotImplementedError
