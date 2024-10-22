from typing import Union, Iterator, Dict, List
from cvss import CVSS2, CVSS3, CVSS4
from sator.core.adapters.base import BaseAdapter

from arepo.models.common.scoring.cvss2 import CVSS2Model, CVSS2AssociationModel
from arepo.models.common.scoring.cvss3 import CVSS3Model, CVSS3AssociationModel


class MetricsAdapter(BaseAdapter):
    def __init__(self, cve_id: str, metrics: List[Union[CVSS2, CVSS3, CVSS4]]):
        super().__init__()
        self.cve_id = cve_id
        self.metrics = metrics

    def convert_cvss2(self, cvss: CVSS2) -> Iterator[Dict[str, Union[CVSS2Model, CVSS2AssociationModel]]]:
        cvss_dict = cvss.as_json()

        cvss_model = CVSS2Model(
                vector_string=cvss.vector,
                access_vector=cvss_dict['accessVector'],
                access_complexity=cvss_dict['accessComplexity'],
                authentication=cvss_dict['authentication'],
                confidentiality_impact=cvss_dict['confidentialityImpact'],
                integrity_impact=cvss_dict['integrityImpact'],
                availability_impact=cvss_dict['availabilityImpact'],
                base_severity=cvss_dict['baseSeverity'],
                base_score=cvss.base_score,
                exploitability_score=None,  # TODO: to be computed
                impact_score=None,  # TODO: to be computed
                ac_onsuf_info=cvss_dict['acInsufInfo'],
                obtain_all_privilege=cvss_dict['obtainAllPrivilege'],
                obtain_user_privilege=cvss_dict['obtainUserPrivilege'],
                obtain_other_privilege=cvss_dict['obtainOtherPrivilege'],
                user_interaction_required=cvss_dict['userInteractionRequired']
            )

        yield from self.yield_if_new(cvss_model, CVSS2Model.__tablename__)
        # TODO: fix hardcoded source ids
        cvss_assoc = CVSS2AssociationModel(
            cvss_id=cvss_model.id,
            vulnerability_id=self.cve_id,
            source_id="osv_id"
        )

        yield from self.yield_if_new(cvss_assoc, CVSS2AssociationModel.__tablename__)

    def convert_cvss3(self, cvss: CVSS3) -> Iterator[Dict[str, Union[CVSS3Model, CVSS3AssociationModel]]]:
        cvss_dict = cvss.as_json()

        cvss_model =  CVSS3Model(
            version=cvss_dict['version'],
            vector_string=cvss.vector,
            attack_vector=cvss_dict['attackVector'],
            attack_complexity=cvss_dict['attackComplexity'],
            privileges_required=cvss_dict['privilegesRequired'],
            user_interaction=cvss_dict['userInteraction'],
            scope=cvss.scope,
            confidentiality_impact=cvss_dict['confidentialityImpact'],
            integrity_impact=cvss_dict['integrityImpact'],
            availability_impact=cvss_dict['availabilityImpact'],
            base_severity=cvss_dict['baseSeverity'],
            base_score=cvss.base_score,
            exploitability_score=None,  # TODO: to be computed
            impact_score=None,  # TODO: to be computed
        )

        yield from self.yield_if_new(cvss_model, CVSS3Model.__tablename__)
        # TODO: fix hardcoded source ids
        cvss_assoc = CVSS3AssociationModel(
            cvss_id=cvss_model.id,
            vulnerability_id=self.cve_id,
            source_id="osv_id"
        )

        yield from self.yield_if_new(cvss_assoc, CVSS3AssociationModel.__tablename__)

    def __call__(self) -> Iterator[Dict[str, Union[CVSS2Model, CVSS3Model]]]:
        for cvss in self.metrics:
            if isinstance(cvss, CVSS3):
                yield from self.convert_cvss3(cvss)

            elif isinstance(cvss, CVSS2):
                yield from self.convert_cvss2(cvss)
