import unittest

from nvdutils.types.cve import CVE, Description
from nvdutils.types.weakness import Weakness, WeaknessDescription, WeaknessType
from sator.core.adapters.nvd.vulnerability import VulnerabilityCWEAdapter


class TestNVDVulnCWEAdapter(unittest.TestCase):

    def setUp(self):
        # Sample CVE and weaknesses
        self.cve_id = 'CVE-1234'
        self.cwe_ids = [100, 200, 300]

        self.weakness1 = Weakness(
            source="nvd@nist.gov",
            type=WeaknessType.Primary,
            description=[
                WeaknessDescription(lang="en", value="CWE-100"),
                WeaknessDescription(lang="en", value="CWE-200")
            ]
        )
        self.weakness2 = Weakness(
            source="snyk.io",
            type=WeaknessType.Secondary,
            description=[
                WeaknessDescription(lang="en", value="CWE-300"),
                WeaknessDescription(lang="en", value="CWE-400")  # This should be ignored
            ]
        )

        self.cve = CVE(
            id=self.cve_id,
            weaknesses={
                "Primary": self.weakness1,
                "Secondary": self.weakness2
            },
            descriptions=[
                Description(value="A sample vulnerability", lang="en")
            ],
            source="nvd@nist.gov",
            published_date="2023-01-01",
            last_modified_date="2023-01-15",
            metrics={},
            references=[],
            configurations=[],
            status="Draft"
        )

    def test_vulnerability_cwe_adapter_yields_correct_cwe_associations(self):
        adapter = VulnerabilityCWEAdapter(self.cve, self.cwe_ids)

        # Collect the yielded models
        yielded_models = list(adapter())

        # Expected CWE associations (CWEs '100' and '200')
        # '300' and '400' are secondary weaknesses from a different source
        expected_cwe_ids = {100, 200}
        print(yielded_models)
        # Collect yielded CWE IDs
        yielded_cwe_ids = {v.cwe_id for model in yielded_models for v in model.values()}
        print(yielded_cwe_ids)

        self.assertEqual(expected_cwe_ids, yielded_cwe_ids)

    def test_vulnerability_cwe_adapter_ignores_non_existing_cwe_ids(self):
        adapter = VulnerabilityCWEAdapter(self.cve, self.cwe_ids)

        # Collect the yielded models
        yielded_models = list(adapter())

        # '400' is not in self.cwe_ids, so it should not be yielded
        yielded_cwe_ids = {v.cwe_id for model in yielded_models for v in model.values()}
        self.assertNotIn('400', yielded_cwe_ids)


if __name__ == '__main__':
    unittest.main()
