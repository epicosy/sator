from sator.app.bootstrap.base import BaseBuilder

from sator.core.ports.driven.classifiers.diff import DiffClassifierPort
from sator.core.ports.driven.analyzers.patch import PatchAttributesAnalyzerPort


from sator.core.use_cases.analysis.attributes import (
    PatchAttributesAnalysis, ProductAttributesAnalysis, VulnerabilityAttributesAnalysis
)


class AnalysisBuilder(BaseBuilder):
    def __init__(
            self, diff_classifier: DiffClassifierPort, patch_attrs_analyzer: PatchAttributesAnalyzerPort, **kwargs
    ):
        super().__init__(**kwargs)
        self.patch_attributes_analyzer = patch_attrs_analyzer
        self.diff_classifier = diff_classifier

    def create_patch_attributes_analysis(self) -> PatchAttributesAnalysis:
        return PatchAttributesAnalysis(
            patch_analyzer=self.patch_attributes_analyzer,
            storage_port=self.storage_port
        )

    def create_product_attributes_analysis(self) -> ProductAttributesAnalysis:
        return ProductAttributesAnalysis(
            oss_gateway=self.oss_gateway,
            storage_port=self.storage_port
        )

    def create_vulnerability_attributes_analysis(self) -> VulnerabilityAttributesAnalysis:
        return VulnerabilityAttributesAnalysis(
            storage_port=self.storage_port
        )
