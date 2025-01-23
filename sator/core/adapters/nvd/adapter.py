from typing import Dict, List, Any, Union, Iterator

from nvdutils.models.cve import CVE

from sator.core.adapters.nvd.vulnerability import VulnerabilityAdapter, VulnerabilityCWEAdapter
from sator.core.adapters.nvd.reference import ReferenceAdapter
from sator.core.adapters.nvd.configuration import ConfigurationAdapter
from sator.core.adapters.nvd.metrics import MetricsAdapter


class CVEToDBAdapter:
    def __init__(self, cve: CVE, tag_ids: Dict[str, int], cwe_ids: Dict[str, int]):
        # TODO: find a better way to handle tags
        self.tag_ids = tag_ids
        # TODO: find a better way to handle CWEs
        self.cwe_ids = cwe_ids

        self.vulnerability_adapter = VulnerabilityAdapter(cve)
        self.vulnerability_cwe_adapter = VulnerabilityCWEAdapter(cve.id, cve.weaknesses, self.cwe_ids)
        self.reference_adapter = ReferenceAdapter(cve.id, cve.references, self.tag_ids)
        self.configuration_adapter = ConfigurationAdapter(cve.id, cve.configurations)
        self.metrics_adapter = MetricsAdapter(cve.id, cve.metrics)

    def __call__(self) -> List[Union[Dict[str, Any], Iterator[Dict[str, Any]]]]:
        return [
            self.vulnerability_adapter(),
            *self.vulnerability_cwe_adapter(),
            *self.reference_adapter(),
            *self.configuration_adapter(),
            *self.metrics_adapter()
        ]
