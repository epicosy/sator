import re

from sator.core.ports.driven.extraction.details import DetailsExtractorPort

from sator.core.models.enums import DescriptionType
from sator.core.models.vulnerability.details import VulnerabilityDetails
from sator.core.models.vulnerability.description import VulnerabilityDescription


# ------------------- 8 Key Phrasing Details -------------
# weakness function file product version attacker impact vector
DETAILS_8_1 = (r'(?P<weakness>.+?) in (the |)(?P<function>.+?) function in (?P<file>.+?) in (?P<product>.+?) '
               r'(?P<version>.+?) allow(s|ed|ing|) (?P<attacker>.+?) to (?P<impact>.+?) (via|by) (vector[s]? |)'
               r'(?P<vector>.+)')

# TODO: add more regex templates


class RegexDetailsExtractor(DetailsExtractorPort):
    def extract_details(self, vulnerability_description: VulnerabilityDescription) -> VulnerabilityDetails | None:
        if vulnerability_description.description_type == DescriptionType.CVE:
            match = re.compile(DETAILS_8_1).match(vulnerability_description.content)

            if match:
                return VulnerabilityDetails(**match.groupdict())

        return None
