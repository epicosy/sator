from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff
from sator.core.models.patch.attributes import PatchAttributes


class PatchAttributesExtractorPort(ABC):
    @abstractmethod
    def extract_patch_attributes(self, diff_message: str, diff: Diff) -> PatchAttributes | None:
        """
            Method for extracting attributes from a vulnerability description.
        """
        raise NotImplementedError
