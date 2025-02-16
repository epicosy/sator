from abc import ABC, abstractmethod

from sator.core.models.vulnerability.details import VulnerabilityDetails
from sator.core.models.vulnerability.description import VulnerabilityDescription


class DetailsExtractorPort(ABC):
    @abstractmethod
    def extract_details(self, vulnerability_description: VulnerabilityDescription) -> VulnerabilityDetails | None:
        """
            Method for extracting details in a vulnerability description.
        """
        raise NotImplementedError
