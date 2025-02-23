from abc import ABC, abstractmethod

from sator.core.models.enums import WeaknessType


class WeaknessClassifierPort(ABC):
    @abstractmethod
    def classify_weakness(self, weakness_keywords: str | list) -> WeaknessType | None:
        """
            Classify the weakness of a vulnerability based on its details.
        """
        raise NotImplementedError
