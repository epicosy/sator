from typing import List
from abc import ABC, abstractmethod

from sator.core.models.enums import ImpactType
from sator.core.models.vulnerability.details import VulnerabilityDetails


class ImpactClassifierPort(ABC):
    @abstractmethod
    def classify_impact(self, vulnerability_details: VulnerabilityDetails) -> List[ImpactType]:
        """
            Classify the impact of a vulnerability based on its details.
        """
        raise NotImplementedError
