from abc import ABC, abstractmethod

from sator.core.models.enums import WeaknessType
from sator.core.models.vulnerability.details import VulnerabilityDetails


class WeaknessClassifierPort(ABC):
    @abstractmethod
    def classify_weakness(self, vulnerability_details: VulnerabilityDetails) -> WeaknessType | None:
        """
            Classify the weakness of a vulnerability based on its details.
        """
        raise NotImplementedError
