from typing import List, Dict, Iterator, Union

from sator.core.adapters.base import BaseAdapter
from nvdutils.types.reference import Reference
from arepo.models.common.reference import ReferenceModel, ReferenceAssociationModel
from arepo.models.common.tag import TagAssociationModel


class ReferenceAdapter(BaseAdapter):
    def __init__(self, cve_id: str, references: List[Reference], tag_ids: Dict[str, int], source_ids: Dict[str, str]):
        super().__init__()
        self.cve_id = cve_id
        self.tag_ids = tag_ids
        self.source_ids = source_ids
        self.references = references

    def __call__(self) -> Iterator[Dict[str, Union[ReferenceModel, ReferenceAssociationModel, TagAssociationModel]]]:
        # TODO: fix the source ids
        for reference in self.references:
            ref_model = ReferenceModel(url=reference.url)

            yield from self.yield_if_new(ref_model, ReferenceModel.__tablename__)

            ref_assoc = ReferenceAssociationModel(
                vulnerability_id=self.cve_id,
                reference_id=ref_model.id,
                source_id="nvd_id"
            )

            yield from self.yield_if_new(ref_assoc, ReferenceAssociationModel.__tablename__)
            # TODO: fix the source ids
            yield from self.convert_tags(reference.tags, ref_model.id, "nvd_id")

    def convert_tags(self, tags: List[str], reference_id: str, source_id: str) -> List[int]:
        for tag in tags:
            tag_assoc = TagAssociationModel(
                reference_id=reference_id,
                tag_id=self.tag_ids[tag],
                source_id=source_id
            )

            yield from self.yield_if_new(tag_assoc, TagAssociationModel.__tablename__)
