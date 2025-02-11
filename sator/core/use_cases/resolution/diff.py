from sator.core.models.oss.diff import Diff
from sator.core.models.vulnerability.locator import VulnerabilityLocator

from sator.core.ports.driven.gateways.oss import OSSGatewayPort
from sator.core.ports.driving.resolution.diff import DiffResolutionPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort


class DiffResolution(DiffResolutionPort):
    def __init__(self, oss_port: OSSGatewayPort, storage_port: StoragePersistencePort):
        self.oss_port = oss_port
        self.storage_port = storage_port

    def get_diff(self, vulnerability_id: str) -> Diff | None:
        diff = self.storage_port.load(Diff, vulnerability_id)

        if diff:
            return diff

        vulnerability_locator = self.storage_port.load(VulnerabilityLocator, vulnerability_id)

        if vulnerability_locator:
            diff = self.oss_port.get_diff(vulnerability_locator.repository_id, vulnerability_locator.commit_sha)

            if diff:
                self.storage_port.save(diff, vulnerability_id)

                return diff

        return None
