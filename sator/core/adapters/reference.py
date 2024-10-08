from typing import List, Dict, Iterator, Union

from sator.core.adapters.base import BaseAdapter
from nvdutils.types.reference import Reference
from arepo.models.common.vulnerability import (ReferenceModel, ReferenceTagModel)
from sator.utils.misc import get_digest


class ReferenceAdapter(BaseAdapter):
    def __init__(self, cve_id: str, references: List[Reference], tag_ids: Dict[str, int]):
        super().__init__()
        self.cve_id = cve_id
        self.tag_ids = tag_ids
        self.references = references

    def __call__(self) -> Iterator[Dict[str, Union[ReferenceModel, ReferenceTagModel]]]:
        for reference in self.references:
            self._ids[ReferenceModel.__tablename__].add(get_digest(reference.url))
            ref_digest = get_digest(reference.url)
            # TODO: there should be a ReferenceVulnerability table, and the vulnerability_id should not be part of the
            #  ReferenceModel
            yield {
                ref_digest: ReferenceModel(
                    id=ref_digest,
                    url=reference.url,
                    vulnerability_id=self.cve_id
                )
            }

            for tag in reference.tags:
                _id = f"{ref_digest}_{self.tag_ids[tag]}"
                self._ids[ReferenceTagModel.__tablename__].add(_id)

                yield {
                    _id: ReferenceTagModel(
                        reference_id=ref_digest,
                        tag_id=self.tag_ids[tag]
                    )
                }
