
from cement.core.config import ConfigHandler

from sator_app.bootstrap import ResolutionBuilder, ExtractionBuilder, AnnotationBuilder, AnalysisBuilder

from sator.adapters.driven.persistence.json import JsonPersistence

from sator.adapters.driven.gateways.oss.github import GithubGateway
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.repositories.vulnerability.nvd import NVDVulnerabilityRepository

from sator.adapters.driven.extractors.attributes.patch.regex_based import RegexPatchAttributesExtractor
from sator.adapters.driven.extractors.attributes.product.keyword_based import KeywordBasedProductAttributesExtractor
from sator.adapters.driven.extractors.attributes.vulnerability.regex_based import RegexVulnerabilityAttributesExtractor

from sator.adapters.driven.classifiers.diff.rule_based import RuleBasedDiffClassifier
from sator.adapters.driven.classifiers.impact.regex_based import RegexBasedImpactClassifier
from sator.adapters.driven.classifiers.weakness.keyword_based import KeywordWeaknessClassifier
from sator.adapters.driven.classifiers.product.keyword_based import KeywordBasedProductClassifier
from sator.adapters.driven.classifiers.patch.action.keyword_based import KeywordPatchActionClassifier

from sator.adapters.driven.analyzers.diff.score_based import ScorePatchAttributesAnalyzer


VULN_REPOS_MAPPING = {
    "nvd": NVDVulnerabilityRepository
}

PROD_REPOS_MAPPING = {
    "cpe": CPEDictionary
}


def create_resolution_builder(config: ConfigHandler) -> ResolutionBuilder:
    gateways = config.get('sator', 'gateways')
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')

    # TODO: storage_port and oss_gateway hardcoded as temporary solution
    return ResolutionBuilder(
        vuln_repos=[
            VULN_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in VULN_REPOS_MAPPING
        ],
        prod_repos=[
            PROD_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in PROD_REPOS_MAPPING
        ],
        storage_port=JsonPersistence(persistence['json']['path']),
        oss_gateway=GithubGateway(gateways['github']["login"])
    )


def create_extraction_builder(config: ConfigHandler) -> ExtractionBuilder:
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    # TODO: patch_attrs_extractor, vuln_attrs_extractor, storage_port, and oss_gateway hardcoded as temporary solution
    return ExtractionBuilder(
        patch_attrs_extractor=RegexPatchAttributesExtractor(),
        vuln_attrs_extractor=RegexVulnerabilityAttributesExtractor(),
        product_attrs_extractor=KeywordBasedProductAttributesExtractor(),
        storage_port=JsonPersistence(persistence['json']['path']),
        oss_gateway=GithubGateway(gateways['github']["login"])
    )


def create_annotation_builder(config: ConfigHandler) -> AnnotationBuilder:
    gateways = config.get('sator', 'gateways')
    persistence = config.get('sator', 'persistence')

    # TODO: classifiers and storage_port and oss_gateway hardcoded as temporary solution
    return AnnotationBuilder(
        product_classifier=KeywordBasedProductClassifier(),
        weakness_classifier=KeywordWeaknessClassifier(),
        patch_action_classifier=KeywordPatchActionClassifier(),
        impact_classifier=RegexBasedImpactClassifier(),
        diff_classifier=RuleBasedDiffClassifier(),
        storage_port=JsonPersistence(persistence['json']['path']),
        oss_gateway=GithubGateway(gateways['github']["login"])
    )


def create_analysis_builder(config: ConfigHandler) -> AnalysisBuilder:
    repositories = config.get('sator', 'repositories')
    persistence = config.get('sator', 'persistence')
    gateways = config.get('sator', 'gateways')

    # TODO: ports hardcoded as temporary solution
    return AnalysisBuilder(
        prod_repos=[
            PROD_REPOS_MAPPING[name](**values) for name, values in repositories.items() if name in PROD_REPOS_MAPPING
        ],
        diff_classifier=RuleBasedDiffClassifier(),
        patch_attrs_analyzer=ScorePatchAttributesAnalyzer(),
        storage_port=JsonPersistence(persistence['json']['path']),
        oss_gateway=GithubGateway(gateways['github']["login"])
    )
