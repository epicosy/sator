from abc import ABC, abstractmethod

from sator.core.models.vulnerability.details import VulnerabilityDetails


class DetailsExtractionPort(ABC):
    @abstractmethod
    def extract_details(self, vulnerability_id: str) -> VulnerabilityDetails | None:
        """Method for extracting details in a vulnerability description by its ID."""
        raise NotImplementedError
