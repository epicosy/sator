from abc import ABC, abstractmethod

from sator.core.models.patch.descriptor import PatchDescriptor


class PatchAttributesAnnotationPort(ABC):

    @abstractmethod
    def annotate_patch_attributes(self, vulnerability_id: str) -> PatchDescriptor | None:
        raise NotImplementedError
