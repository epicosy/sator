from typing import List, Iterator, Union, Dict
from sator.utils.misc import get_digest
from nvdutils.types.configuration import Configuration
from arepo.models.common.platform import VendorModel, ProductModel, ConfigurationModel, ConfigurationVulnerabilityModel
from sator.core.adapters.base import BaseAdapter


class ConfigurationAdapter(BaseAdapter):
    def __init__(self, cve_id: str, configurations: List[Configuration]):
        super().__init__()
        self.cve_id = cve_id
        self.configurations = configurations

    def __call__(self) -> Iterator[
        Dict[str, Union[VendorModel, ProductModel, ConfigurationModel, ConfigurationVulnerabilityModel]]]:
        for config in self.configurations:
            # TODO: this needs a Node table
            for node in config.nodes:
                # TODO: this needs a CPE table
                for cpe_match in node.cpe_match:
                    vendor_digest = get_digest(cpe_match.cpe.vendor)
                    self._ids[VendorModel.__tablename__].add(vendor_digest)

                    yield {
                        vendor_digest: VendorModel(
                            id=vendor_digest,
                            name=cpe_match.cpe.vendor
                        )
                    }

                    product_digest = get_digest(f"{cpe_match.cpe.vendor}:{cpe_match.cpe.product}")
                    self._ids[ProductModel.__tablename__].add(product_digest)
                    # TODO: the Product Type should be removed from the ProductModel
                    yield {
                        product_digest: ProductModel(
                            id=product_digest,
                            name=cpe_match.cpe.product,
                            vendor_id=vendor_digest,
                            product_type_id=8
                        )
                    }

                    # TODO: the vulnerability_id should not be part of the ConfigurationModel since configurations
                    #   can occur in multiple vulnerabilities
                    # TODO: update ConfigurationModel to CPEModel
                    self._ids[ConfigurationModel.__tablename__].add(cpe_match.criteria_id)
                    yield {
                        cpe_match.criteria_id: ConfigurationModel(
                            id=cpe_match.criteria_id,
                            vulnerable=cpe_match.vulnerable,
                            part=cpe_match.cpe.part,
                            version=cpe_match.cpe.version,
                            update=cpe_match.cpe.update,
                            edition=cpe_match.cpe.edition,
                            language=cpe_match.cpe.language,
                            sw_edition=cpe_match.cpe.sw_edition,
                            target_sw=cpe_match.cpe.target_sw,
                            target_hw=cpe_match.cpe.target_hw,
                            other=cpe_match.cpe.other,
                            vendor_id=vendor_digest,
                            product_id=product_digest
                        )
                    }

                    _id = f"{cpe_match.criteria_id}_{self.cve_id}"
                    self._ids[ConfigurationVulnerabilityModel.__tablename__].add(_id)
                    # TODO: need to find a way to keep track of the configuration_id, vulnerability_id pair
                    yield {
                        _id: ConfigurationVulnerabilityModel(
                            configuration_id=cpe_match.criteria_id,
                            vulnerability_id=self.cve_id
                        )
                    }
