from sator.core.models.bug import BugLocator
from sator.core.models.oss.diff import Diff
from sator.core.models.oss.annotation import DiffAnnotation

from sator.core.ports.driving.analysis.diff import DiffAnalysisPort
from sator.core.ports.driven.analyzers.diff import DiffAnalyzerPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort


class DiffAnalysis(DiffAnalysisPort):
    def __init__(self, diff_analyzer: DiffAnalyzerPort, storage_port: StoragePersistencePort):
        self.diff_analyzer = diff_analyzer
        self.storage_port = storage_port

    def analyze_diff(self, vulnerability_id: str) -> BugLocator | None:
        diff = self.storage_port.load(Diff, vulnerability_id)

        if diff:
            diff_annotation = self.storage_port.load(DiffAnnotation, vulnerability_id)

            if diff_annotation:
                analysis = self.diff_analyzer.analyze_diff(diff, diff_annotation)

                if analysis:
                    file, line = analysis
                    bug_locator = BugLocator(commit=diff.parent_commit_sha, file=file, line=line)
                    self.storage_port.save(bug_locator, vulnerability_id)
                    return bug_locator

        return None
