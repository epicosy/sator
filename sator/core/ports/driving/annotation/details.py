from abc import ABC, abstractmethod

from sator.core.models.vulnerability.descriptor import VulnerabilityDescriptor


class DetailsAnnotationPort(ABC):

    @abstractmethod
    def annotate_details(self, vulnerability_id: str) -> VulnerabilityDescriptor | None:
        raise NotImplementedError
