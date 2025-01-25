import unittest

from nvdutils.types.reference import Reference
from sator.core.adapters.nvd.reference import ReferenceAdapter

from arepo.models.common.reference import ReferenceModel, ReferenceAssociationModel
from arepo.models.common.tag import TagAssociationModel


class TestReferenceAdapter(unittest.TestCase):
    def setUp(self):
        # Sample data
        self.cve_id = 'CVE-1234'

        # Mock tag_ids and source_ids
        self.tag_ids = {
            'Tag1': 1,
            'Tag2': 2
        }

        self.source_ids = {
            'source1': 'src-1',
            'source2': 'src-2'
        }

        # Sample references
        self.references = [
            Reference(url='https://example.com/1', source='source1', tags=['Tag1', 'Tag2']),
            Reference(url='https://example.com/2', source='source2', tags=[])
        ]

    def test_reference_adapter_yields_correct_models(self):
        # Instantiate ReferenceAdapter with test data
        adapter = ReferenceAdapter(cve_id=self.cve_id, references=self.references, tag_ids=self.tag_ids, source_ids=self.source_ids)

        # Collect the yielded models
        yielded_models = list(adapter())

        expected_models = [ReferenceModel, ReferenceAssociationModel, TagAssociationModel, TagAssociationModel,
                           ReferenceModel, ReferenceAssociationModel]

        for model_dict, expected_model in zip(yielded_models, expected_models):
            for model_id, model in model_dict.items():
                # Assert that the model is one of the expected models
                self.assertTrue(isinstance(model, expected_model))

    def test_no_duplicate_yields(self):
        # Test case where the same reference is provided twice to check for duplication
        references = [
            self.references[0],
            self.references[0]
        ]

        adapter = ReferenceAdapter(cve_id=self.cve_id, references=references, tag_ids=self.tag_ids,
                                   source_ids=self.source_ids)

        # Collect the yielded models
        yielded_models = list(adapter())

        # Since the same reference is provided twice, we expect no duplication
        # 1 ReferenceModel, 1 ReferenceAssociationModel, 1 TagAssociationModel, 2 TagAssociationModel
        self.assertEqual(len(yielded_models), 4)

    def test_skips_empty_tag_lists(self):
        # Reference with no tags
        references = [
            self.references[1]
        ]

        adapter = ReferenceAdapter(cve_id=self.cve_id, references=references, tag_ids=self.tag_ids,
                                   source_ids=self.source_ids)

        # Collect the yielded models
        yielded_models = list(adapter())

        # Assert that only ReferenceModel and ReferenceAssociationModel are yielded, no TagAssociationModel
        self.assertEqual(len(yielded_models), 2)  # ReferenceModel and ReferenceAssociationModel


if __name__ == '__main__':
    unittest.main()
