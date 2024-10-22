from collections import defaultdict
from typing import List, Iterator, Union, Dict

from sator.core.adapters.base import BaseAdapter

from nvdutils.types.configuration import Configuration, CPEMatch, Node

from arepo.models.common.platform.vendor import VendorModel
from arepo.models.common.platform.product import ProductModel
from arepo.models.common.platform.cpe import CPEModel, CPEMatchModel
from arepo.models.common.platform.configuration import ConfigurationModel, NodeModel


class ConfigurationAdapter(BaseAdapter):
    def __init__(self, cve_id: str, configurations: List[Configuration]):
        super().__init__()
        self.cve_id = cve_id
        self.configurations = configurations
        self.config_ids = defaultdict(list)

    def __call__(self) -> Iterator[Dict[str, ConfigurationModel]]:
        for i, config in enumerate(self.configurations):
            # TODO: configuration ids should convey their content, to avoid duplicates
            config_id = f"{self.cve_id}_{i}"

            for j, node in enumerate(config.nodes):
                # TODO: node ids should convey their content, to avoid duplicates
                yield from self.convert_node(node, config_id, f"{config_id}_{j}")

            # TODO: vulnerability_id is still making part of the model, there should be a table for those associations
            config_model = ConfigurationModel(
                id=config_id,
                vulnerability_id=self.cve_id,
                operator=config.operator,
                is_vulnerable=config.is_vulnerable,
                is_multi_component=config.is_multi_component,
                is_platform_specific=config.is_platform_specific
            )

            yield from self.yield_if_new(config_model, ConfigurationModel.__tablename__)

    def convert_node(self, node: Node, config_id: str, node_id: str) -> Iterator[Dict[str, NodeModel]]:
        for cpe_match in node.cpe_match:
            yield from self.convert_cpe_match(cpe_match, node_id=node_id)

        # TODO: NodeAssociationModel for the associations between nodes and configurations and CPEMatches
        node_model = NodeModel(
            id=node_id,
            configuration_id=config_id,
            operator=node.operator,
            negate=node.negate,
            is_vulnerable=node.is_vulnerable,
            is_multi_component=node.is_multi_component,
            is_context_dependent=node.is_context_dependent
        )

        yield from self.yield_if_new(node_model, NodeModel.__tablename__)

    def convert_cpe_match(self, cpe_match: CPEMatch, node_id: str) -> (
            Iterator[Dict[str, Union[VendorModel, ProductModel, CPEModel]]]):
        vendor_model = VendorModel(name=cpe_match.cpe.vendor)

        yield from self.yield_if_new(vendor_model, VendorModel.__tablename__)

        product_model = ProductModel(name=cpe_match.cpe.product, part=cpe_match.cpe.part, vendor_id=vendor_model.id)

        yield from self.yield_if_new(product_model, ProductModel.__tablename__)

        cpe_model = CPEModel(
            product_id=product_model.id,
            version=cpe_match.cpe.version,
            update=cpe_match.cpe.update,
            edition=cpe_match.cpe.edition,
            language=cpe_match.cpe.language,
            sw_edition=cpe_match.cpe.sw_edition,
            target_sw=cpe_match.cpe.target_sw,
            target_hw=cpe_match.cpe.target_hw,
            other=cpe_match.cpe.other
        )

        yield from self.yield_if_new(cpe_model, CPEModel.__tablename__)

        cpe_match_model = CPEMatchModel(
            id=cpe_match.criteria_id,
            cpe_id=cpe_model.id,
            node_id=node_id,
            vulnerable=cpe_match.vulnerable,
            version_start_including=cpe_match.version_start_including,
            version_start_excluding=cpe_match.version_start_excluding,
            version_end_including=cpe_match.version_end_including,
            version_end_excluding=cpe_match.version_end_excluding
        )

        yield from self.yield_if_new(cpe_match_model, CPEMatchModel.__tablename__)
