import unittest

from sator.core.adapters.nvd.configuration import ConfigurationAdapter

from nvdutils.types.configuration import Configuration, CPEMatch, Node, CPE

from arepo.models.common.platform.vendor import VendorModel
from arepo.models.common.platform.product import ProductModel
from arepo.models.common.platform.cpe import CPEModel, CPEMatchModel
from arepo.models.common.platform.configuration import ConfigurationModel, NodeModel


# Test class for ConfigurationAdapter
class TestConfigurationAdapter(unittest.TestCase):

    def setUp(self):
        # Sample data
        self.cve_id = 'CVE-1234'

        # Configurations with and without CPE matches
        self.configurations = [
            Configuration(
                operator='OR',
                is_vulnerable=True,
                is_multi_component=False,
                is_platform_specific=False,
                nodes=[
                    Node(
                        operator='OR',
                        negate=False,
                        is_vulnerable=True,
                        is_multi_component=False,
                        is_context_dependent=False,
                        cpe_match=[
                            CPEMatch(
                                criteria='cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*',
                                criteria_id='8460d589f587dc26178ffc601254b284',
                                cpe=CPE(
                                    cpe_version='2.3',
                                    part='a',
                                    vendor='vendor1',
                                    product='product1',
                                    version='1.0',
                                    update='*',
                                    edition='*',
                                    language='*',
                                    sw_edition='*',
                                    target_sw='*',
                                    target_hw='*',
                                    other='*'
                                ),
                                vulnerable=True,
                                is_platform_specific_sw=False,
                                is_platform_specific_hw=False
                            ),
                            CPEMatch(
                                criteria='cpe:2.3:a:vendor1:product2:1.0:*:*:*:*:*:*:*',
                                criteria_id='17b0019dfba9cfca7b5f8970e3f0d344',
                                cpe=CPE(
                                    cpe_version='2.3',
                                    part='a',
                                    vendor='vendor1',
                                    product='product2',
                                    version='1.0',
                                    update='*',
                                    edition='*',
                                    language='*',
                                    sw_edition='*',
                                    target_sw='*',
                                    target_hw='*',
                                    other='*'
                                ),
                                vulnerable=True,
                                is_platform_specific_sw=False,
                                is_platform_specific_hw=False
                            )
                        ]
                    )
                ]
            )
        ]

    def test_configuration_adapter_yields_correct_models(self):
        # Instantiate ConfigurationAdapter with test data
        adapter = ConfigurationAdapter(cve_id=self.cve_id, configurations=self.configurations)

        # Collect the yielded models
        yielded_models = list(adapter())
        expected_models = [VendorModel, ProductModel, CPEModel, CPEMatchModel, ProductModel, CPEModel, CPEMatchModel,
                           NodeModel, ConfigurationModel]

        # Collect the IDs that were yielded
        for model_dict, expected_model in zip(yielded_models, expected_models):
            for model_id, model in model_dict.items():
                # asser that the model is one of the expected models
                self.assertTrue(isinstance(model, expected_model))


if __name__ == '__main__':
    unittest.main()
