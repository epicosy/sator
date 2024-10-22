import unittest

from nvdutils.types.reference import CommitReference
from sator.core.adapters.nvd.commit import CommitAdapter

from arepo.models.vcs.core.repository import RepositoryModel, RepositoryAssociationModel
from arepo.models.vcs.core.commit import CommitModel, CommitAssociationModel


# Test class for CommitAdapter
class TestCommitAdapter(unittest.TestCase):

    def setUp(self):
        # Sample data
        self.cve_id = 'CVE-1234'

        # Commits with and without the 'Patch' tag
        self.commits = [
            CommitReference(repo='repo1', owner='owner1', sha='sha1', tags=['Patch'], source='source1', url="url1"),
            CommitReference(repo='repo2', owner='owner2', sha='sha2', tags=[], source='source2', url="url2"),
            CommitReference(repo='repo1', owner='owner1', sha='sha3', tags=['Patch'], source='source3', url="url3")
        ]

    def test_commit_adapter_yields_correct_models(self):
        # Instantiate CommitAdapter with test data
        adapter = CommitAdapter(cve_id=self.cve_id, commits=self.commits)

        # Collect the yielded models
        yielded_models = list(adapter())
        expected_models = [RepositoryModel, RepositoryAssociationModel, CommitModel, CommitAssociationModel,
                           RepositoryAssociationModel, CommitModel, CommitAssociationModel]

        # Collect the IDs that were yielded
        for model_dict, expected_model in zip(yielded_models, expected_models):
            for model_id, model in model_dict.items():
                # asser that the model is one of the expected models
                self.assertTrue(isinstance(model, expected_model))

    def test_no_duplicate_yields(self):
        # Duplicate commit references for the same repository and commit to test deduplication
        commits = [
            self.commits[0],
            self.commits[0]
        ]

        adapter = CommitAdapter(cve_id=self.cve_id, commits=commits)

        # Collect the yielded models
        yielded_models = list(adapter())

        # Since both commits are identical, we expect only one set of objects to be yielded
        self.assertEqual(len(yielded_models), 4)  # Repository, RepoAssoc, Commit, CommitAssoc

    def test_skips_non_patch_commits(self):
        # Commits without the 'Patch' tag should not yield any models
        commits = [
            self.commits[1]
        ]

        adapter = CommitAdapter(cve_id=self.cve_id, commits=commits)

        # Collect the yielded models
        yielded_models = list(adapter())

        # Assert that no models are yielded since the commit doesn't have 'Patch' in its tags
        self.assertEqual(len(yielded_models), 0)


if __name__ == '__main__':
    unittest.main()
