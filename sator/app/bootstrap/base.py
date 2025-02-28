from sator.core.ports.driven.gateways.oss import OSSGatewayPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort


class BaseBuilder:
    def __init__(self, oss_gateway: OSSGatewayPort, storage_port: StoragePersistencePort):
        self.storage_port = storage_port
        # TODO: temporary solution, should be moved somewhere else
        self.oss_gateway = oss_gateway
