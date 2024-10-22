import unittest


from nvdutils.types.cve import CVE, Description
from sator.core.adapters.nvd.adapter import VulnerabilityAdapter


class TestNVDVulnAdapter(unittest.TestCase):
    def setUp(self):
        # Sample CVE data
        self.cve_id = 'CVE-1234'
        self.source_ids = {'nvd@nist.gov': 'source-id-1'}

        self.cve = CVE(
            id=self.cve_id,
            weaknesses={},
            descriptions=[
                Description(
                    lang="en",
                    value="A sample vulnerability description"
                )
            ],
            source="nvd@nist.gov",
            published_date="2023-01-01",
            last_modified_date="2023-01-15",
            configurations=[],
            metrics={},
            references=[],
            status="Accepted",
        )

    def test_vulnerability_adapter_returns_correct_vulnerability_model(self):
        adapter = VulnerabilityAdapter(self.cve, self.source_ids)

        # Call the adapter and get the resulting model
        result = adapter()

        # Extract the VulnerabilityModel from the result
        vulnerability_model = result[self.cve_id]

        # Assert that the returned model has correct attributes
        self.assertEqual(vulnerability_model.id, self.cve_id)
        self.assertEqual(vulnerability_model.description, "A sample vulnerability description")
        self.assertEqual(vulnerability_model.source_id, 'source-id-1')
        self.assertEqual(vulnerability_model.published_date, "2023-01-01")
        self.assertEqual(vulnerability_model.last_modified_date, "2023-01-15")

    def test_vulnerability_adapter_handles_missing_source_ids(self):
        # If the source_id is missing in the source_ids dict
        missing_source_ids = {}

        adapter = VulnerabilityAdapter(self.cve, missing_source_ids)

        # Calling the adapter should raise a KeyError due to missing source_id
        with self.assertRaises(KeyError):
            adapter()


if __name__ == '__main__':
    unittest.main()
