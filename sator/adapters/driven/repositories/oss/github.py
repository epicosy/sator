from typing import List

from gitlib.loader import DiffLoader

from sator_core.models.oss.diff import Diff
from sator_core.models.product import ProductLocator
from sator_core.models.patch.references import PatchReferences
from sator_core.models.vulnerability.locator import VulnerabilityLocator

from sator_core.ports.driven.repositories.oss import OSSRepositoryPort
from sator.adapters.driven.repositories.oss.mappers import GithubDiffMapper


class GithubRepository(OSSRepositoryPort):
    def __init__(self, path: str):
        self.loader = DiffLoader(path=path)
        self.diff_dict = self.loader.load()

    def get_diff(self, commit_sha: str) -> Diff | None:
        return self.diff_dict.entries.get(commit_sha, None)

    def get_diffs(self) -> List[Diff]:
        return [GithubDiffMapper.map_diff(sha, diff) for sha, diff in self.diff_dict.entries.items()]

    def get_references(
            self, vulnerability_id: str, vulnerability_locator: VulnerabilityLocator = None,
            product_locator: ProductLocator = None
    ) -> PatchReferences | None:
        """
            Method for getting patch references for a vulnerability.

            :param vulnerability_id: The ID of the vulnerability.
            :param vulnerability_locator: The locator of the vulnerability.
            :param product_locator: The locator of the product.
        """

        # TODO: Implement the logic to retrieve patch references based on the vulnerability ID and locators.

        return None
