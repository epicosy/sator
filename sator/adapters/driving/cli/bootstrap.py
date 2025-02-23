
from cement.core.config import ConfigHandler

from sator.core.use_cases.resolution.vulnerability import VulnerabilityResolutionUseCase

from sator.core.use_cases.extraction.attributes import (ProductAttributesExtraction, VulnerabilityAttributesExtraction,
                                                        PatchAttributesExtraction)

from sator.core.use_cases.resolution.references import (ProductReferencesResolution, VulnerabilityReferencesResolution,
                                                        PatchReferencesResolution)

from sator.core.use_cases.analysis.attributes import (PatchAttributesAnalysis, ProductAttributesAnalysis,
                                                      VulnerabilityAttributesAnalysis)

from sator.core.use_cases.annotation.attributes import (PatchAttributesAnnotation, ProductAttributesAnnotation,
                                                        VulnerabilityAttributesAnnotation)

from sator.adapters.driven.analyzers.diff.score_based import ScorePatchAttributesAnalyzer
from sator.adapters.driven.persistence.json import JsonPersistence
from sator.adapters.driven.gateways.oss.github import GithubGateway
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.repositories.vulnerability.nvd import NVDVulnerabilityRepository
from sator.adapters.driven.classifiers.impact.regex_based import RegexBasedImpactClassifier
from sator.adapters.driven.classifiers.weakness.keyword_based import KeywordWeaknessClassifier
from sator.adapters.driven.classifiers.product.keyword_based import KeywordBasedProductClassifier
from sator.adapters.driven.classifiers.patch.action.keyword_based import KeywordPatchActionClassifier
from sator.adapters.driven.classifiers.diff.rule_based import RuleBasedDiffClassifier
from sator.adapters.driven.extractors.attributes.patch.regex_based import RegexPatchAttributesExtractor
from sator.adapters.driven.extractors.attributes.vulnerability.regex_based import RegexVulnerabilityAttributesExtractor


VULN_REPOS_MAPPING = {
    "nvd": NVDVulnerabilityRepository
}

PROD_REPOS_MAPPING = {
    "cpe": CPEDictionary
}


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


def create_vulnerability_references_resolution(config: ConfigHandler) -> VulnerabilityReferencesResolution:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    return VulnerabilityReferencesResolution(
        vulnerability_repositories=[
            VULN_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in VULN_REPOS_MAPPING
        ],
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_product_references_resolution(config: ConfigHandler) -> ProductReferencesResolution:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    return ProductReferencesResolution(
        product_repositories=[
            PROD_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in PROD_REPOS_MAPPING
        ],
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_patch_references_resolution(config: ConfigHandler) -> PatchReferencesResolution:
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    # TODO: oss_gateway hardcoded as temporary solution
    return PatchReferencesResolution(
        diff_classifier=RuleBasedDiffClassifier(),
        oss_gateway=GithubGateway(gateways['github']["login"]),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_product_attributes_annotation(config: ConfigHandler) -> ProductAttributesAnnotation:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    # TODO: product_classifier_port hardcoded as temporary solution
    return ProductAttributesAnnotation(
        product_reference_port=CPEDictionary(repositories['nvd']['path']),
        product_classifier_port=KeywordBasedProductClassifier(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_patch_attributes_annotation(config: ConfigHandler) -> PatchAttributesAnnotation:
    persistence = config.get('sator', 'persistence')

    # TODO: patch_action_classifier, weakness_classifier, and diff_classifier hardcoded as temporary solution
    return PatchAttributesAnnotation(
        patch_action_classifier=KeywordPatchActionClassifier(),
        weakness_classifier=KeywordWeaknessClassifier(),
        diff_classifier_port=RuleBasedDiffClassifier(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_patch_attributes_analysis(config: ConfigHandler) -> PatchAttributesAnalysis:
    persistence = config.get('sator', 'persistence')

    # TODO: patch_analyzer hardcoded as temporary solution
    return PatchAttributesAnalysis(
        patch_analyzer=ScorePatchAttributesAnalyzer(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_product_attributes_extraction(config: ConfigHandler) -> ProductAttributesExtraction:
    persistence = config.get('sator', 'persistence')
    repositories = config.get('sator', 'repositories')

    # TODO: vulnerability_extractor hardcoded as temporary solution
    return ProductAttributesExtraction(
        product_repositories=[
            PROD_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in PROD_REPOS_MAPPING
        ],
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_vulnerability_attributes_extraction(config: ConfigHandler) -> VulnerabilityAttributesExtraction:
    persistence = config.get('sator', 'persistence')

    # TODO: vulnerability_extractor hardcoded as temporary solution
    return VulnerabilityAttributesExtraction(
        attributes_extractor=RegexVulnerabilityAttributesExtractor(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_patch_attributes_extraction(config: ConfigHandler) -> PatchAttributesExtraction:
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    # TODO: oss_gateway and attributes_extractor and storage_port hardcoded as temporary solution
    return PatchAttributesExtraction(
        oss_gateway=GithubGateway(gateways['github']["login"]),
        attributes_extractor=RegexPatchAttributesExtractor(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_vulnerability_attributes_annotation(config: ConfigHandler) -> VulnerabilityAttributesAnnotation:
    persistence = config.get('sator', 'persistence')

    # TODO: weakness_classifier and impact_classifier hardcoded as temporary solution
    return VulnerabilityAttributesAnnotation(
        weakness_classifier=KeywordWeaknessClassifier(),
        impact_classifier=RegexBasedImpactClassifier(),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_product_attributes_analysis(config: ConfigHandler) -> ProductAttributesAnalysis:
    persistence = config.get('sator', 'persistence')
    gateways = config.get('sator', 'gateways')

    return ProductAttributesAnalysis(
        oss_gateway=GithubGateway(gateways['github']["login"]),
        storage_port=JsonPersistence(persistence['json']['path'])
    )


def create_vulnerability_attributes_analysis(config: ConfigHandler) -> VulnerabilityAttributesAnalysis:
    persistence = config.get('sator', 'persistence')
    repositories = config.get('sator', 'repositories')

    return VulnerabilityAttributesAnalysis(
        product_repository=CPEDictionary(repositories['cpe']['path']),
        storage_port=JsonPersistence(persistence['json']['path'])
    )
