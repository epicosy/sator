from abc import ABC, abstractmethod

from sator.core.models.bug import BugLocator


class DiffAnalysisPort(ABC):
    @abstractmethod
    def analyze_diff(self, vulnerability_id: str) -> BugLocator | None:
        """
            Analyze the diff of the given vulnerability.

            Args:
                vulnerability_id: The id of the vulnerability.

            Returns:
                The location of the bug in the diff.
        """
        raise NotImplementedError
