
from sator.app.bootstrap.base import BaseBuilder

from sator.core.ports.driven.extraction.attributes.patch import PatchAttributesExtractorPort
from sator.core.ports.driven.extraction.attributes.vulnerability import VulnerabilityAttributesExtractorPort


from sator.core.use_cases.extraction.attributes import (
    ProductAttributesExtraction, VulnerabilityAttributesExtraction, PatchAttributesExtraction
)


class ExtractionBuilder(BaseBuilder):
    def __init__(
            self, patch_attrs_extractor: PatchAttributesExtractorPort,
            vuln_attrs_extractor: VulnerabilityAttributesExtractorPort, **kwargs
    ):
        super().__init__(**kwargs)

        self.patch_attributes_extractor = patch_attrs_extractor
        self.vulnerability_attributes_extractor = vuln_attrs_extractor

    def create_product_attributes_extraction(self) -> ProductAttributesExtraction:
        return ProductAttributesExtraction(
            storage_port=self.storage_port
        )

    def create_vulnerability_attributes_extraction(self) -> VulnerabilityAttributesExtraction:
        return VulnerabilityAttributesExtraction(
            attributes_extractor=self.vulnerability_attributes_extractor,
            storage_port=self.storage_port
        )

    def create_patch_attributes_extraction(self) -> PatchAttributesExtraction:
        return PatchAttributesExtraction(
            oss_gateway=self.oss_gateway,
            attributes_extractor=self.patch_attributes_extractor,
            storage_port=self.storage_port
        )
