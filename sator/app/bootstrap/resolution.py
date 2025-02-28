from typing import List

from sator.app.bootstrap.base import BaseBuilder

from sator.core.ports.driven.repositories.product import ProductRepositoryPort
from sator.core.ports.driven.repositories.vulnerability import VulnerabilityRepositoryPort

from sator.core.use_cases.resolution.metadata import VulnerabilityMetadataResolution, ProductMetadataResolution
from sator.core.use_cases.resolution.references import (
    ProductReferencesResolution, VulnerabilityReferencesResolution, PatchReferencesResolution
)


class ResolutionBuilder(BaseBuilder):
    def __init__(
            self, vuln_repos: List[VulnerabilityRepositoryPort], prod_repos: List[ProductRepositoryPort], **kwargs
    ):
        super().__init__(**kwargs)
        self.vulnerability_repositories = vuln_repos
        self.product_repositories = prod_repos

    def create_vulnerability_metadata_resolution(self) -> VulnerabilityMetadataResolution:
        return VulnerabilityMetadataResolution(
            vuln_repositories=self.vulnerability_repositories,
            storage_port=self.storage_port
        )

    def create_vulnerability_references_resolution(self) -> VulnerabilityReferencesResolution:
        return VulnerabilityReferencesResolution(
            vulnerability_repositories=self.vulnerability_repositories,
            storage_port=self.storage_port
        )

    def create_product_metadata_resolution(self) -> ProductMetadataResolution:
        return ProductMetadataResolution(
            product_repositories=self.product_repositories,
            storage_port=self.storage_port
        )

    def create_product_references_resolution(self) -> ProductReferencesResolution:
        return ProductReferencesResolution(
            product_repositories=self.product_repositories,
            storage_port=self.storage_port
        )

    def create_patch_references_resolution(self) -> PatchReferencesResolution:
        return PatchReferencesResolution(
            oss_gateway=self.oss_gateway,
            storage_port=self.storage_port
        )
