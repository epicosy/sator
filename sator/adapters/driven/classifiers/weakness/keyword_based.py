
from sator.core.ports.driven.classifiers.weakness import WeaknessClassifierPort

from sator.core.models.enums import WeaknessType
from sator.core.models.vulnerability.details import VulnerabilityDetails


# TODO: Improve the list of keywords for each weakness type based on the CWE documentation.
KEYWORD_WEAKNESS_MAPPING = {
    WeaknessType.MEMORY_SAFETY: ("buffer", "overflow", "underflow", "stack", "heap", "use-after-free", "double-free"),
    WeaknessType.INPUT_SAFETY: ("injection", "sql", "code", "command", "xml", "injection", "command", "injection"),
    WeaknessType.TYPE_SAFETY: ("type", "confusion", "type", "confusion", "type", "confusion", "type", "confusion"),
}


class KeywordBasedWeaknessClassifier(WeaknessClassifierPort):
    def classify_weakness(self, vulnerability_details: VulnerabilityDetails) -> WeaknessType | None:
        """
            Classify the weakness of a vulnerability based on its details.
        """

        if not vulnerability_details.weakness:
            return None

        weakness = {
            "type": None,
            "count": 0
        }

        weakness_keywords = vulnerability_details.weakness.lower().split(" ")

        for weakness_type, keywords in KEYWORD_WEAKNESS_MAPPING.items():
            keywords_count = len(set(weakness_keywords) & set(keywords))

            if keywords_count > weakness["count"]:
                weakness["type"] = weakness_type
                weakness["count"] = keywords_count

        return weakness["type"]
