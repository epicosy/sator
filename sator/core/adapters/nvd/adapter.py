from typing import Dict, List, Any, Union, Iterator

from nvdutils.types.cve import CVE

from sator.core.adapters.nvd.vulnerability import VulnerabilityAdapter, VulnerabilityCWEAdapter
from sator.core.adapters.nvd.reference import ReferenceAdapter
from sator.core.adapters.nvd.commit import CommitAdapter
from sator.core.adapters.nvd.configuration import ConfigurationAdapter
from sator.core.adapters.nvd.metrics import MetricsAdapter


class CVEToDBAdapter:
    def __init__(self, cve: CVE, tag_ids: Dict[str, int], cwe_ids: Dict[str, int]):
        self.cve = cve
        # TODO: find a better way to handle tags
        self.tag_ids = tag_ids
        # TODO: find a better way to handle CWEs
        self.cwe_ids = cwe_ids

        self.commits, self.references = cve.get_separated_references(vcs='github')

        self.vulnerability_adapter = VulnerabilityAdapter(self.cve)
        self.vulnerability_cwe_adapter = VulnerabilityCWEAdapter(self.cve, self.cwe_ids)
        self.reference_adapter = ReferenceAdapter(self.cve.id, self.references, self.tag_ids)
        self.commit_adapter = CommitAdapter(self.cve.id, self.commits)
        self.configuration_adapter = ConfigurationAdapter(self.cve.id, self.cve.configurations)
        self.metrics_adapter = MetricsAdapter(self.cve)

    def __call__(self) -> List[Union[Dict[str, Any], Iterator[Dict[str, Any]]]]:
        return [
            self.vulnerability_adapter(),
            *self.vulnerability_cwe_adapter(),
            *self.reference_adapter(),
            *self.commit_adapter(),
            *self.configuration_adapter(),
            *self.metrics_adapter()
        ]
