from typing import Union, Iterator, Dict
from nvdutils.types.cve import CVE
from nvdutils.types.cvss import CVSSv2, CVSSv3, CVSSType
from sator.core.adapters.base import BaseAdapter

from arepo.models.common.scoring.cvss2 import CVSS2Model, CVSS2AssociationModel
from arepo.models.common.scoring.cvss3 import CVSS3Model, CVSS3AssociationModel


class MetricsAdapter(BaseAdapter):
    def __init__(self, cve: CVE, source_ids: Dict[str, str]):
        super().__init__()
        self.cve = cve
        self.metrics = []
        self.source_ids = source_ids

        for metric_type in ['cvssMetricV2', 'cvssMetricV31', 'cvssMetricV30']:
            self.metrics.extend(cve.get_metrics(metric_type, CVSSType.Primary))

    def convert_cvss2(self, cvss: CVSSv2) -> Iterator[Dict[str, Union[CVSS2Model, CVSS2AssociationModel]]]:
        cvss_model = CVSS2Model(
            vector_string=cvss.vector,
            access_vector=cvss.access_vector,
            access_complexity=cvss.access_complexity,
            authentication=cvss.authentication,
            confidentiality_impact=cvss.impact.confidentiality,
            integrity_impact=cvss.impact.integrity,
            availability_impact=cvss.impact.availability,
            base_severity=cvss.base_severity,
            base_score=cvss.scores.base,
            exploitability_score=cvss.scores.exploitability,
            impact_score=cvss.scores.impact,
            ac_insuf_info=cvss.ac_insuf_info,
            obtain_all_privilege=cvss.obtain_all_privilege,
            obtain_user_privilege=cvss.obtain_user_privilege,
            obtain_other_privilege=cvss.obtain_other_privilege,
            user_interaction_required=cvss.user_interaction_required
        )

        yield from self.yield_if_new(cvss_model, CVSS2Model.__tablename__)
        # TODO: fix the source ids

        cvss_assoc = CVSS2AssociationModel(
            cvss_id=cvss_model.id,
            vulnerability_id=self.cve.id,
            source_id="nvd_id"
        )

        yield from self.yield_if_new(cvss_assoc, CVSS2AssociationModel.__tablename__)

    def convert_cvss3(self, cvss: CVSSv3) -> Iterator[Dict[str, Union[CVSS3Model, CVSS3AssociationModel]]]:
        cvss_model = CVSS3Model(
            version=cvss.version,
            vector_string=cvss.vector,
            attack_vector=cvss.attack_vector,
            attack_complexity=cvss.attack_complexity,
            privileges_required=cvss.privileges_required,
            user_interaction=cvss.user_interaction,
            scope=cvss.scope,
            confidentiality_impact=cvss.impact.confidentiality,
            integrity_impact=cvss.impact.integrity,
            availability_impact=cvss.impact.availability,
            base_severity=cvss.base_severity,
            base_score=cvss.scores.base,
            exploitability_score=cvss.scores.exploitability,
            impact_score=cvss.scores.impact
        )

        yield from self.yield_if_new(cvss_model, CVSS3Model.__tablename__)
        # TODO: fix the source ids

        cvss_assoc = CVSS3AssociationModel(
            cvss_id=cvss_model.id,
            vulnerability_id=self.cve.id,
            source_id="nvd_id"
        )

        yield from self.yield_if_new(cvss_assoc, CVSS3AssociationModel.__tablename__)

    def __call__(self) \
            -> Iterator[Dict[str, Union[CVSS2Model, CVSS3Model, CVSS3AssociationModel, CVSS2AssociationModel]]]:
        for cvss in self.metrics:
            if isinstance(cvss, CVSSv2):
                yield from self.convert_cvss2(cvss)
            elif isinstance(cvss, CVSSv3):
                yield from self.convert_cvss3(cvss)
