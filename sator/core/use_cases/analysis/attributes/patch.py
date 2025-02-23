from sator.core.models.patch import PatchLocator, PatchAttributes, PatchDescriptor

from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driven.analyzers.patch import PatchAttributesAnalyzerPort
from sator.core.ports.driving.analysis.attributes.patch import PatchAttributesAnalysisPort


class PatchAttributesAnalysis(PatchAttributesAnalysisPort):
    def __init__(self, patch_analyzer: PatchAttributesAnalyzerPort, storage_port: StoragePersistencePort):
        self.patch_analyzer = patch_analyzer
        self.storage_port = storage_port

    def analyze_patch_attributes(self, vulnerability_id: str) -> PatchLocator | None:
        patch_locator = self.storage_port.load(PatchLocator, vulnerability_id)

        if patch_locator:
            return patch_locator

        patch_attributes = self.storage_port.load(PatchAttributes, vulnerability_id)

        if patch_attributes:
            patch_descriptor = self.storage_port.load(PatchDescriptor, vulnerability_id)

            if patch_descriptor:
                analysis = self.patch_analyzer.analyze_patch_attributes(patch_attributes, patch_descriptor)

                if analysis:
                    file_path, start_lineno, end_lineno = analysis
                    patch_locator = PatchLocator(
                        repository_id=patch_attributes.diff.repository_id, diff_id=patch_attributes.diff.commit_sha,
                        file_path=file_path, start_lineno=start_lineno, end_lineno=end_lineno
                    )

                    self.storage_port.save(patch_locator, vulnerability_id)
                    return patch_locator

        return None
