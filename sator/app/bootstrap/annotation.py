from sator.app.bootstrap.base import BaseBuilder

from sator.core.use_cases.annotation.attributes import (
    PatchAttributesAnnotation, ProductAttributesAnnotation, VulnerabilityAttributesAnnotation
)


from sator.core.ports.driven.classifiers.diff import DiffClassifierPort
from sator.core.ports.driven.classifiers.impact import ImpactClassifierPort
from sator.core.ports.driven.classifiers.product import ProductClassifierPort
from sator.core.ports.driven.classifiers.weakness import WeaknessClassifierPort
from sator.core.ports.driven.classifiers.patch_action import PatchActionClassifierPort


class AnnotationBuilder(BaseBuilder):
    def __init__(
            self, product_classifier: ProductClassifierPort, weakness_classifier: WeaknessClassifierPort,
            patch_action_classifier: PatchActionClassifierPort, impact_classifier: ImpactClassifierPort,
            diff_classifier: DiffClassifierPort, **kwargs
    ):
        super().__init__(**kwargs)

        self.diff_classifier = diff_classifier
        self.impact_classifier = impact_classifier
        self.product_classifier = product_classifier
        self.weakness_classifier = weakness_classifier
        self.patch_action_classifier = patch_action_classifier

    def create_vulnerability_attributes_annotation(self) -> VulnerabilityAttributesAnnotation:
        return VulnerabilityAttributesAnnotation(
            weakness_classifier=self.weakness_classifier,
            impact_classifier=self.impact_classifier,
            storage_port=self.storage_port
        )

    def create_product_attributes_annotation(self) -> ProductAttributesAnnotation:
        return ProductAttributesAnnotation(
            product_classifier=self.product_classifier,
            storage_port=self.storage_port
        )

    def create_patch_attributes_annotation(self) -> PatchAttributesAnnotation:
        return PatchAttributesAnnotation(
            patch_action_classifier=self.patch_action_classifier,
            weakness_classifier=self.weakness_classifier,
            diff_classifier=self.diff_classifier,
            storage_port=self.storage_port
        )
