
from cement.core.config import ConfigHandler

# app/bootstrap.py
from sator.core.use_cases.annotation.product import ProductAnnotation
from sator.core.use_cases.resolution.product import ProductResolution
from sator.core.use_cases.resolution.vulnerability import VulnerabilityResolutionUseCase

from sator.adapters.driven.persistence.json import JsonPersistence
from sator.adapters.driven.gateways.oss.github import GithubGateway
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.repositories.vulnerability.nvd import NVDVulnerabilityRepository
from sator.adapters.driven.classifiers.product.keyword_based import KeywordBasedProductClassifier


VULN_REPOS_MAPPING = {
    "nvd": NVDVulnerabilityRepository
}


def create_product_resolution(config: ConfigHandler) -> ProductResolution:
    repositories = config.get('sator', 'repositories')
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    return ProductResolution(
        product_reference_port=CPEDictionary(repositories['nvd']['path']),
        oss_port=GithubGateway(gateways['github']["login"]),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_vulnerability_resolution(config: ConfigHandler) -> VulnerabilityResolutionUseCase:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    return VulnerabilityResolutionUseCase(
        repository_ports=[
            VULN_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in VULN_REPOS_MAPPING
        ],
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_product_annotation(config: ConfigHandler) -> ProductAnnotation:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    return ProductAnnotation(
        product_reference_port=CPEDictionary(repositories['nvd']['path']),
        product_classifier_port=KeywordBasedProductClassifier(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )
