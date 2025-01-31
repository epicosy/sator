from cement import Controller, ex
from sator.core.use_cases.product_resolution import ProductResolution

from sator.adapters.driven.gateways.oss.github import GithubGateway
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.repositories.vulnerability.nvd import NVDVulnerabilityRepository
from sator.adapters.driven.classifiers.product.keyword_based import KeywordBasedProductClassifier


class Product(Controller):
    class Meta:
        label = 'product'
        stacked_on = 'base'
        stacked_type = 'nested'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator source'

        # controller level arguments. ex: 'sator --version'
        arguments = [
            (['-n', '--name'], {'help': 'Name of the source. Should map available handlers', 'type': str,
                                'required': False})
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-np', '--nvd_path'], {'help': 'path for nvd data', 'type': str, 'required': False}),
            (['-cpe', '--cpe_path'], {'help': 'path for cpe data', 'type': str, 'required': False}),
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True}),
            (['-gl', '--github_login'], {'help': 'github login', 'type': str, 'required': True})
        ]
    )
    def resolution(self):
        product_resolution = ProductResolution(
            vulnerability_port=NVDVulnerabilityRepository(),
            product_classifier_port=KeywordBasedProductClassifier(),
            product_reference_port=CPEDictionary(self.app.pargs.cpe_path),
            oss_port=GithubGateway(self.app.pargs.github_login)
        )

        product = product_resolution.get_vulnerable_product(self.app.pargs.vuln_id)
        locators = product_resolution.get_product_locators(product)

        print(f'Product Locators: {locators}')
