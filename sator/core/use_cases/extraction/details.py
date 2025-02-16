
from sator.core.models.vulnerability.details import VulnerabilityDetails
from sator.core.models.vulnerability.description import VulnerabilityDescription

from sator.core.ports.driven.extraction.details import DetailsExtractorPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driving.extraction.details import DetailsExtractionPort


class DetailsExtraction(DetailsExtractionPort):
    def __init__(self, details_extractor: DetailsExtractorPort, storage_port: StoragePersistencePort):
        self.storage_port = storage_port
        self.details_extractor = details_extractor

    def extract_details(self, vulnerability_id: str) -> VulnerabilityDetails | None:
        details = self.storage_port.load(VulnerabilityDetails, vulnerability_id)

        if details:
            return details

        description = self.storage_port.load(VulnerabilityDescription, vulnerability_id)

        if description:
            details = self.details_extractor.extract_details(description)

            if details and details.any():
                self.storage_port.save(details, vulnerability_id)
                return details

        return None
