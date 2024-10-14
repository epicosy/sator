from typing import List, Dict, Iterator, Union

from sator.core.adapters.base import BaseAdapter
from osvutils.types.reference import Reference
from arepo.models.common.vulnerability import ReferenceModel, ReferenceTagModel
from sator.utils.misc import get_digest


# TODO: should decide which one is the standard format
OSV_TO_NVD_TAG_MAP = {
    'ADVISORY': 'Vendor Advisory',
    'ARTICLE': 'Third Party Advisory',  # (close enough)
    'DETECTION': 'Tool Signature',
    'DISCUSSION': 'Press/Media Coverage',
    'REPORT': 'Technical Description',
    'FIX': 'Patch',
    'INTRODUCED': 'Issue Tracking',  # this should actually be a type of tag
    'PACKAGE': 'Product',
    'EVIDENCE': 'Exploit',
    'WEB': 'Other'
}


class ReferenceAdapter(BaseAdapter):
    def __init__(self, cve_id: str, references: List[Reference], tag_ids: Dict[str, int]):
        super().__init__()
        self.cve_id = cve_id
        self.tag_ids = tag_ids
        self.references = references if references is not None else []

    def __call__(self) -> Iterator[Dict[str, Union[ReferenceModel, ReferenceTagModel]]]:
        for reference in self.references:
            # TODO: Reference model should provide a function for this
            reference_url = reference.url if reference.is_full_url() else str(reference.url)
            ref_digest = get_digest(reference_url)
            self._ids[ReferenceModel.__tablename__].add(ref_digest)
            # TODO: there should be a ReferenceVulnerability table, and the vulnerability_id should not be part of the
            #  ReferenceModel
            yield {
                ref_digest: ReferenceModel(
                    id=ref_digest,
                    url=reference_url,
                    vulnerability_id=self.cve_id
                )
            }

            # Map reference type to tag id
            tag = OSV_TO_NVD_TAG_MAP[reference.type]
            _id = f"{ref_digest}_{self.tag_ids[tag]}"
            self._ids[ReferenceTagModel.__tablename__].add(_id)

            yield {
                _id: ReferenceTagModel(
                    reference_id=ref_digest,
                    tag_id=self.tag_ids[tag]
                )
            }
