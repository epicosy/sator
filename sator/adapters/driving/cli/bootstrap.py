
from cement.core.config import ConfigHandler

# app/bootstrap.py
from sator.core.use_cases.analysis.diff import DiffAnalysis
from sator.core.use_cases.annotation.diff import DiffAnnotator
from sator.core.use_cases.resolution.diff import DiffResolution
from sator.core.use_cases.annotation.product import ProductAnnotation
from sator.core.use_cases.resolution.product import ProductResolution
from sator.core.use_cases.resolution.vulnerability import VulnerabilityResolutionUseCase

from sator.adapters.driven.analyzers.diff.score_based import ScoreBasedDiffAnalyzer
from sator.adapters.driven.persistence.json import JsonPersistence
from sator.adapters.driven.gateways.oss.github import GithubGateway
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.repositories.vulnerability.nvd import NVDVulnerabilityRepository
from sator.adapters.driven.classifiers.product.keyword_based import KeywordBasedProductClassifier
from sator.adapters.driven.classifiers.diff.rule_based import RuleBasedDiffClassifier


VULN_REPOS_MAPPING = {
    "nvd": NVDVulnerabilityRepository
}


def create_product_resolution(config: ConfigHandler) -> ProductResolution:
    repositories = config.get('sator', 'repositories')
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    return ProductResolution(
        product_reference_port=CPEDictionary(repositories['cpe']['path']),
        oss_port=GithubGateway(gateways['github']["login"]),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_vulnerability_resolution(config: ConfigHandler) -> VulnerabilityResolutionUseCase:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')
    gateways = config.get('sator', 'gateways')

    return VulnerabilityResolutionUseCase(
        repository_ports=[
            VULN_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in VULN_REPOS_MAPPING
        ],
        storage_port=JsonPersistence(persistence['json']['path']),
        oss_port=GithubGateway(gateways['github']["login"])
    )


def create_diff_resolution(config: ConfigHandler) -> DiffResolution:
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    return DiffResolution(
        oss_port=GithubGateway(gateways['github']["login"]),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_product_annotation(config: ConfigHandler) -> ProductAnnotation:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    # TODO: product_classifier_port hardcoded as temporary solution
    return ProductAnnotation(
        product_reference_port=CPEDictionary(repositories['nvd']['path']),
        product_classifier_port=KeywordBasedProductClassifier(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_diff_annotation(config: ConfigHandler) -> DiffAnnotator:
    persistence = config.get('sator', 'persistence')

    # TODO: diff_classifier hardcoded as temporary solution
    return DiffAnnotator(
        diff_classifier_port=RuleBasedDiffClassifier(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_diff_analysis(config: ConfigHandler) -> DiffAnalysis:
    persistence = config.get('sator', 'persistence')

    # TODO: diff_classifier hardcoded as temporary solution
    return DiffAnalysis(
        diff_analyzer=ScoreBasedDiffAnalyzer(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )
