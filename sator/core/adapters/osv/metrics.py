import json

from typing import Union, Iterator, Dict, List
from cvss import CVSS2, CVSS3, CVSS4
from sator.utils.misc import get_digest
from sator.core.adapters.base import BaseAdapter

from arepo.models.common.scoring import CVSS2Model, CVSS3Model


class MetricsAdapter(BaseAdapter):
    def __init__(self, cve_id: str, metrics: List[Union[CVSS2, CVSS3, CVSS4]]):
        super().__init__()
        self.cve_id = cve_id
        self.metrics = metrics

    def get_model(self, cvss: Union[CVSS2, CVSS3]):
        cvss_dict = cvss.as_json()
        # TODO: cve_id should not be part of the id
        cvss_dict.update({"cve_id": self.cve_id})
        cvss_id = get_digest(json.dumps(cvss_dict))

        if isinstance(cvss, CVSS2):
            self._ids[CVSS2Model.__tablename__].add(cvss_id)
            return CVSS2Model(
                id=cvss_id,
                vulnerability_id=self.cve_id,
                cvssData_version=cvss_dict['version'],
                cvssData_vectorString=cvss.vector,
                cvssData_accessVector=cvss_dict['accessVector'],
                cvssData_accessComplexity=cvss_dict['accessComplexity'],
                cvssData_authentication=cvss_dict['authentication'],
                cvssData_confidentialityImpact=cvss_dict['confidentialityImpact'],
                cvssData_integrityImpact=cvss_dict['integrityImpact'],
                cvssData_availabilityImpact=cvss_dict['availabilityImpact'],
                cvssData_baseScore=cvss.base_score,
                baseSeverity=cvss_dict['baseSeverity'],
                exploitabilityScore=None,  # TODO: to be computed
                impactScore=None,  # TODO: to be computed
                acInsufInfo=cvss_dict['acInsufInfo'],
                obtainAllPrivilege=cvss_dict['obtainAllPrivilege'],
                obtainUserPrivilege=cvss_dict['obtainUserPrivilege'],
                obtainOtherPrivilege=cvss_dict['obtainOtherPrivilege'],
                userInteractionRequired=cvss_dict['userInteractionRequired']
            )
        elif isinstance(cvss, CVSS3):
            self._ids[CVSS3Model.__tablename__].add(cvss_id)
            return CVSS3Model(
                id=cvss_id,
                vulnerability_id=self.cve_id,
                exploitabilityScore=None,  # TODO: to be computed
                impactScore=None,  # TODO: to be computed
                cvssData_version=cvss_dict['version'],
                cvssData_vectorString=cvss.vector,
                cvssData_attackVector=cvss_dict['attackVector'],
                cvssData_attackComplexity=cvss_dict['attackComplexity'],
                cvssData_privilegesRequired=cvss_dict['privilegesRequired'],
                cvssData_userInteraction=cvss_dict['userInteraction'],
                cvssData_scope=cvss.scope,
                cvssData_confidentialityImpact=cvss_dict['confidentialityImpact'],
                cvssData_integrityImpact=cvss_dict['integrityImpact'],
                cvssData_availabilityImpact=cvss_dict['availabilityImpact'],
                cvssData_baseScore=cvss.base_score,
                cvssData_baseSeverity=cvss_dict['baseSeverity']
            )

    def __call__(self) -> Iterator[Dict[str, Union[CVSS2Model, CVSS3Model]]]:
        for cvss in self.metrics:
            if isinstance(cvss, CVSS4):
                # TODO: to be implemented
                continue

            cvss_model = self.get_model(cvss)

            yield {
                cvss_model.id: cvss_model
            }

            # TODO: add instance with cvss_id and vulnerability_id to CVSSVulnerability table
            # TODO: there should be a SourceCVSS table to keep track of the cvss scores
