import re
import string

from typing import List

from sator.core.models.enums import ImpactType
from sator.core.models.vulnerability.attributes import VulnerabilityAttributes
from sator.core.ports.driven.classifiers.impact import ImpactClassifierPort

# Create a translation table
translator = str.maketrans('', '', string.punctuation)


EXECUTION_TERMS_1 = r'((code|process[es])|(command|shell|payload|script|binary|exploit|function)[s]?)'
EXECUTION_TERMS_2 = r'execut(e|ed|ion|ing)'
INFO_DISCLOSURE_TERMS_1 = r'(read(|ing)|disclos(e|ure)|leak(|age)|expos(e|ure)|cleartext transmission|gain|inclusion)'
INFO_DISCLOSURE_TERMS_2 = r'(?:sensitive |)(information|memory|data|knowledge)'

BASIC_EXECUTION_GROUP = EXECUTION_TERMS_1 + r'(?: [\w\s]+)? ' + EXECUTION_TERMS_2
BASIC_DENIAL_GROUP = r'den(y|ies|ial)(?: [\w\s]+)? (service|access)'
BASIC_DISCLOSURE_GROUP = INFO_DISCLOSURE_TERMS_2 + r'(?: [\w\s]+)?(?:\s|-)' + INFO_DISCLOSURE_TERMS_1
BASIC_ESCALATION_GROUP = r'(privilege|permission|access|right)[s]?(?: [\w\s]+)? (?:escalat(e|ed|ion)|elevat(e|ed|ion))'

MIXED_EXECUTION_GROUP = EXECUTION_TERMS_2 + r'(?: [\w\s]+)? ' + EXECUTION_TERMS_1
MIXED_DISCLOSURE_GROUP_1 = INFO_DISCLOSURE_TERMS_1 + r'\s(?:of |)' + INFO_DISCLOSURE_TERMS_2
MIXED_DISCLOSURE_GROUP_2 = (r'\battacker[s]?(?: [\w\s]+)? to(?: [\w\s]+)? ' + INFO_DISCLOSURE_TERMS_1 +
                            r'(?: [\w\s]+)? ' + INFO_DISCLOSURE_TERMS_2)

# privelege is misspelled in the following pattern because it is a common typo
MIXED_ESCALATION_GROUP = r'\bescalat(e|ed|ion|ing)(?: [\w\s]+)? (privelege|privilege|permission|root|access)[s]?\b'

EXECUTION_ACRONYMS_GROUP = r'\s(rce|)\s'
DOS_ACRONYMS_GROUP = r'\s(dos|ddos)\s'

EXECUTION_VARIATIONS_GROUP = r'\b(lead|allow)[s]?(?: [\w\s]+)? execut(e|ion)\b'
DENIAL_VARIATIONS_GROUP_1 = r'\battacker[s]?(?: [\w\s]+)? to(?: [\w\s]+)? (crash)\b'
DENIAL_VARIATIONS_GROUP_2 = r'(result(|ing) in|could|possibly|cause[s]?)(?: [\w\s]+)? (crash)'
DISCLOSURE_VARIATIONS_GROUP_1 = r'\b(lead|allow)[s]?(?: [\w\s]+)? ' + INFO_DISCLOSURE_TERMS_1 + '\b'
DISCLOSURE_VARIATIONS_GROUP_2 = r'\bexpose[s]?(?: [\w\s]+)? ' + INFO_DISCLOSURE_TERMS_2 + '\b'


IMPACT_PATTERNS = {
    ImpactType.CODE_EXECUTION: r'(' + BASIC_EXECUTION_GROUP + r'|' + MIXED_EXECUTION_GROUP + r'|' +
                               EXECUTION_ACRONYMS_GROUP + r'|' + EXECUTION_VARIATIONS_GROUP + r')',
    ImpactType.DENIAL_OF_SERVICE: r'(' + BASIC_DENIAL_GROUP + r'|' + DOS_ACRONYMS_GROUP + r'|' +
                                  DENIAL_VARIATIONS_GROUP_1 + r'|' + DENIAL_VARIATIONS_GROUP_2 + r')',
    ImpactType.INFORMATION_DISCLOSURE: r'(' + BASIC_DISCLOSURE_GROUP + r'|' + MIXED_DISCLOSURE_GROUP_1 + r'|' +
                                       MIXED_DISCLOSURE_GROUP_2 + r'|' + DISCLOSURE_VARIATIONS_GROUP_1 + r'|' +
                                       DISCLOSURE_VARIATIONS_GROUP_2 + r')',
    ImpactType.PRIVILEGE_ESCALATION: r'(' + BASIC_ESCALATION_GROUP + r'|' + MIXED_ESCALATION_GROUP + r')'
}


def clean_text(text):
    # TODO: find a proper way to do this cleaning
    return (text.translate(translator).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').replace('/', ' ').
            replace('"', '').replace('-', ' ').replace(':', '').replace('(', '').replace(')', ''))


class RegexBasedImpactClassifier(ImpactClassifierPort):
    def classify_impact(self, vulnerability_details: VulnerabilityAttributes) -> List[ImpactType]:
        """
            Classify the impact of a vulnerability based on its details.
        """

        impact_types = []

        if vulnerability_details.impact:

            no_punctuation = clean_text(vulnerability_details.impact)

            for impact_type, pattern in IMPACT_PATTERNS.items():
                if re.search(pattern, no_punctuation.strip(), re.IGNORECASE):
                    impact_types.append(impact_type)

        return impact_types
