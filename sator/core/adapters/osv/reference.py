from typing import List, Dict, Iterator, Union

from sator.core.adapters.base import BaseAdapter
from osvutils.types.reference import Reference
from arepo.models.common.reference import ReferenceModel, ReferenceAssociationModel
from arepo.models.common.tag import TagAssociationModel


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

    def __call__(self) -> Iterator[Dict[str, Union[ReferenceModel, ReferenceAssociationModel]]]:
        for reference in self.references:
            # TODO: Reference model should provide a function for this
            ref_model = ReferenceModel(
                url=reference.url if reference.is_full_url() else str(reference.url)
            )

            yield from self.yield_if_new(ref_model, ReferenceModel.__tablename__)

            ref_assoc = ReferenceAssociationModel(
                vulnerability_id=self.cve_id,
                reference_id=ref_model.id,
                source_id="osv_id"
            )

            yield from self.yield_if_new(ref_assoc, ReferenceAssociationModel.__tablename__)

            # Map reference type to tag id
            tag = OSV_TO_NVD_TAG_MAP[reference.type]

            tag_assoc = TagAssociationModel(
                reference_id=ref_model.id,
                tag_id=self.tag_ids[tag],
                source_id="osv_id"
            )

            yield from self.yield_if_new(tag_assoc, TagAssociationModel.__tablename__)
