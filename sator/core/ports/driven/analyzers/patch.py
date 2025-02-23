from typing import Tuple
from abc import ABC, abstractmethod

from sator.core.models.patch import PatchAttributes, PatchDescriptor


class PatchAttributesAnalyzerPort(ABC):
    @abstractmethod
    def analyze_patch_attributes(self, patch_attributes: PatchAttributes, patch_descriptor: PatchDescriptor) \
            -> Tuple[str, int, int] | None:
        raise NotImplementedError
