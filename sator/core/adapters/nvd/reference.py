from typing import Dict, Iterator, Union

from sator.core.adapters.base import BaseAdapter

from nvdutils.models.references import References
from arepo.models.common.reference import ReferenceModel
from sator.utils.misc import get_digest


class ReferenceAdapter(BaseAdapter):
    def __init__(self, cve_id: str, references: References, tag_ids: Dict[str, int]):
        super().__init__()
        self.cve_id = cve_id
        self.tag_ids = tag_ids
        self.references = references

    def __call__(self) -> Iterator[Dict[str, Union[ReferenceModel]]]:
        # TODO: fix the source ids
        for reference in self.references:
            self._ids[ReferenceModel.__tablename__].add(get_digest(str(reference.url)))
            ref_digest = get_digest(str(reference.url))
            # TODO: there should be a ReferenceVulnerability table, and the vulnerability_id should not be part of the
            #  ReferenceModel
            yield {
                ref_digest: ReferenceModel(
                    id=ref_digest,
                    url=reference.url,
                    vulnerability_id=self.cve_id
                )
            }
