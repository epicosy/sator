import unittest
from unittest.mock import MagicMock

from sator.core.adapters.nvd.metrics import MetricsAdapter

from nvdutils.types.cve import CVE
from nvdutils.types.cvss import CVSSv2, CVSSv3, CVSSType

from arepo.models.common.scoring.cvss2 import CVSS2Model, CVSS2AssociationModel
from arepo.models.common.scoring.cvss3 import CVSS3Model, CVSS3AssociationModel


class TestMetricsAdapter(unittest.TestCase):

    def setUp(self):
        # Sample CVE ID
        self.cve_id = 'CVE-1234'

        # Mock source IDs
        self.source_ids = {
            'source1': 'src-1',
            'source2': 'src-2'
        }

        # Sample CVSSv2 and CVSSv3 metrics
        self.cvss_v2 = CVSSv2(
            vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
            version="2.0",
            type=CVSSType.Primary,
            access_vector="Network",
            access_complexity="Low",
            authentication="None",
            base_severity="Medium",
            scores=MagicMock(base=5.0, exploitability=8.0, impact=4.0),
            source="source1",
            impact=MagicMock(confidentiality="Partial", integrity="Partial", availability="Partial"),
            ac_insuf_info=False,
            obtain_all_privilege=False,
            obtain_user_privilege=False,
            obtain_other_privilege=False,
            user_interaction_required=False
        )

        self.cvss_v3 = CVSSv3(
            version="3.1",
            type=CVSSType.Primary,
            vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            attack_complexity="Low",
            attack_vector="Network",
            privileges_required="None",
            user_interaction="None",
            scope="Unchanged",
            base_severity="High",
            scores=MagicMock(base=9.8, exploitability=3.9, impact=5.9),
            source="source2",
            impact=MagicMock(confidentiality="High", integrity="High", availability="High")
        )

        # Mock CVE object with CVSSv2 and CVSSv3 metrics
        self.cve = CVE(
            id=self.cve_id,
            metrics={
                "cvssMetricV2": {
                    "Primary": self.cvss_v2,
                },
                "cvssMetricV31": {
                    "Primary": self.cvss_v3
                }
            },
            references=[],
            configurations=[],
            descriptions=[],
            last_modified_date="2021-01-01T00:00:00Z",
            published_date="2021-01-01T00:00:00Z",
            source="source1",
            status="Accepted",
            weaknesses={}
        )

    def test_metrics_adapter_yields_correct_cvss_models(self):
        adapter = MetricsAdapter(cve=self.cve, source_ids=self.source_ids)

        # Collect the yielded models for CVSSv2
        yielded_models = list(adapter())
        expected_models = [CVSS2Model, CVSS2AssociationModel, CVSS3Model, CVSS3AssociationModel]

        # Collect the yielded IDs
        for model_dict, expected_model in zip(yielded_models, expected_models):
            for model_id, model in model_dict.items():
                # Assert that the model is one of the expected models
                self.assertTrue(isinstance(model, expected_model))


if __name__ == '__main__':
    unittest.main()
