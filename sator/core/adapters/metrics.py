import json

from typing import Union, Iterator, Dict
from nvdutils.types.cve import CVE
from nvdutils.types.cvss import CVSSv2, CVSSv3, CVSSType
from sator.utils.misc import get_digest
from sator.core.adapters.base import BaseAdapter

from arepo.models.common.scoring import CVSS2Model, CVSS3Model


class MetricsAdapter(BaseAdapter):
    def __init__(self, cve: CVE):
        super().__init__()
        self.cve = cve
        self.metrics = []

        for metric_type in ['cvssMetricV2', 'cvssMetricV31', 'cvssMetricV30']:
            self.metrics.extend(cve.get_metrics(metric_type, CVSSType.Primary))

    def get_model(self, cvss: Union[CVSSv2, CVSSv3]):
        cvss_dict = cvss.to_dict()
        # TODO: cve_id should not be part of the id
        cvss_dict.update({"cve_id": self.cve.id})
        cvss_id = get_digest(json.dumps(cvss_dict))

        if isinstance(cvss, CVSSv2):
            self._ids[CVSS2Model.__tablename__].add(cvss_id)
            return CVSS2Model(
                id=cvss_id,
                vulnerability_id=self.cve.id,
                cvssData_version=cvss.version,
                cvssData_vectorString=cvss.vector,
                cvssData_accessVector=cvss.access_vector,
                cvssData_accessComplexity=cvss.access_complexity,
                cvssData_authentication=cvss.authentication,
                cvssData_confidentialityImpact=cvss.impact.confidentiality,
                cvssData_integrityImpact=cvss.impact.integrity,
                cvssData_availabilityImpact=cvss.impact.availability,
                cvssData_baseScore=cvss.scores.base,
                baseSeverity=cvss.base_severity,
                exploitabilityScore=cvss.scores.exploitability,
                impactScore=cvss.scores.impact,
                acInsufInfo=cvss.ac_insuf_info,
                obtainAllPrivilege=cvss.obtain_all_privilege,
                obtainUserPrivilege=cvss.obtain_user_privilege,
                obtainOtherPrivilege=cvss.obtain_other_privilege,
                userInteractionRequired=cvss.user_interaction_required
            )
        elif isinstance(cvss, CVSSv3):
            self._ids[CVSS3Model.__tablename__].add(cvss_id)
            return CVSS3Model(
                id=cvss_id,
                vulnerability_id=self.cve.id,
                exploitabilityScore=cvss.scores.exploitability,
                impactScore=cvss.scores.impact,
                cvssData_version=cvss.version,
                cvssData_vectorString=cvss.vector,
                cvssData_attackVector=cvss.attack_vector,
                cvssData_attackComplexity=cvss.attack_complexity,
                cvssData_privilegesRequired=cvss.privileges_required,
                cvssData_userInteraction=cvss.user_interaction,
                cvssData_scope=cvss.scope,
                cvssData_confidentialityImpact=cvss.impact.confidentiality,
                cvssData_integrityImpact=cvss.impact.integrity,
                cvssData_availabilityImpact=cvss.impact.availability,
                cvssData_baseScore=cvss.scores.base,
                cvssData_baseSeverity=cvss.base_severity
            )

    def __call__(self) -> Iterator[Dict[str, Union[CVSS2Model, CVSS3Model]]]:
        for cvss in self.metrics:
            cvss_model = self.get_model(cvss)

            yield {
                cvss_model.id: cvss_model
            }

            # TODO: add instance with cvss_id and vulnerability_id to CVSSVulnerability table
