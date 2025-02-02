from cement import Controller, ex

from sator.core.use_cases.resolution.product import ProductResolution
from sator.core.use_cases.resolution.vulnerability import VulnerabilityResolutionUseCase

from sator.adapters.driven.persistence.json import JsonPersistence
from sator.adapters.driven.gateways.oss.github import GithubGateway
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.repositories.vulnerability.nvd import NVDVulnerabilityRepository


class Resolve(Controller):
    class Meta:
        label = 'resolve'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator resolve'

        # TODO: should come from some configuration
        arguments = [
            (['-pp', '--persistence_path'], {'help': 'persistence path', 'type': str, 'required': True}),
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-vn', '--vendor_name'], {'help': 'product name', 'type': str, 'required': True}),
            (['-pn', '--product_name'], {'help': 'product name', 'type': str, 'required': True}),
            (['-cpe', '--cpe_path'], {'help': 'path for cpe data', 'type': str, 'required': True}),
            (['-gl', '--github_login'], {'help': 'github login', 'type': str, 'required': True})
        ]
    )
    def product(self):
        # TODO: not sure if I can directly pass the arguments to the driven ports
        product_resolution = ProductResolution(
            product_reference_port=CPEDictionary(self.app.pargs.cpe_path),
            oss_port=GithubGateway(self.app.pargs.github_login),
            storage_port=JsonPersistence(self.app.pargs.persistence_path)
        )

        locators = product_resolution.get_product_locators(
            vendor_name=self.app.pargs.vendor_name, product_name=self.app.pargs.product_name
        )
        print(f'Product Locators: {locators}')

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability(self):
        vulnerability_resolution = VulnerabilityResolutionUseCase(
            repository_ports=[NVDVulnerabilityRepository()],
            storage_port=JsonPersistence(self.app.pargs.persistence_path)
        )

        vulnerability = vulnerability_resolution.get_vulnerability(self.app.pargs.vuln_id)

        if vulnerability:
            affected_products = vulnerability_resolution.get_affected_products(vulnerability)
            print(f'Affected Products: {affected_products}')
