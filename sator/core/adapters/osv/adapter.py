from typing import Dict, List, Any, Union, Iterator

from osvutils.types.osv import OSV

from sator.core.adapters.osv.reference import ReferenceAdapter
from sator.core.adapters.osv.commit import CommitAdapter
from sator.core.adapters.osv.metrics import MetricsAdapter


class OSVToDBAdapter:
    def __init__(self, osv: OSV, tag_ids: Dict[str, int], source_ids: Dict[str, str]):
        self.osv = osv
        cve_id = osv.get_cve_id()
        # TODO: find a better way to handle tags
        self.tag_ids = tag_ids
        self.source_ids = source_ids

        # self.commits, self.references = osv.get_separated_references(vcs='github')
        self.reference_adapter = ReferenceAdapter(cve_id, osv.references, self.tag_ids)
        self.commit_adapter = CommitAdapter(cve_id, osv.get_git_ranges())
        self.metrics_adapter = MetricsAdapter(cve_id, osv.get_scores())

        # TODO: need to update the database ORM in order to handle the rest of data fields

    def __call__(self) -> List[Union[Dict[str, Any], Iterator[Dict[str, Any]]]]:
        results = []
        results.extend(self.reference_adapter())
        results.extend(self.commit_adapter())
        results.extend(self.metrics_adapter())

        return results
