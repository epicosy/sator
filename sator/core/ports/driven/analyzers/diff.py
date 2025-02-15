from typing import Tuple
from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff
from sator.core.models.oss.annotation import DiffAnnotation


class DiffAnalyzerPort(ABC):
    @abstractmethod
    def analyze_diff(self, diff: Diff, annotation: DiffAnnotation) -> Tuple[str, int] | None:
        """
            Analyze the diff and annotate it.

            Args:
                diff: The diff to analyze.
                annotation: The annotation to update.

            Returns:
                The file and line number where the bug is located.
        """
        raise NotImplementedError
