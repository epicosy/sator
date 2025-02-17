

from sator.core.models.vulnerability.details import VulnerabilityDetails
from sator.core.models.vulnerability.descriptor import VulnerabilityDescriptor

from sator.core.ports.driven.classifiers.impact import ImpactClassifierPort
from sator.core.ports.driven.classifiers.weakness import WeaknessClassifierPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driving.annotation.details import DetailsAnnotationPort


class DetailsAnnotation(DetailsAnnotationPort):
    def __init__(self, weakness_classifier: WeaknessClassifierPort, impact_classifier: ImpactClassifierPort,
                 storage_port: StoragePersistencePort):
        self.weakness_classifier = weakness_classifier
        self.impact_classifier = impact_classifier
        self.storage_port = storage_port

    def annotate_details(self, vulnerability_id: str) -> VulnerabilityDescriptor | None:
        descriptor = self.storage_port.load(VulnerabilityDescriptor, vulnerability_id)

        if descriptor:
            return descriptor

        details = self.storage_port.load(VulnerabilityDetails, vulnerability_id)

        if details:
            impact_types = self.impact_classifier.classify_impact(details)
            weakness_type = self.weakness_classifier.classify_weakness(details)

            descriptor = VulnerabilityDescriptor(
                impact_types=impact_types,
                weakness_type=weakness_type
            )

            if descriptor.any():
                self.storage_port.save(descriptor, vulnerability_id)
                return descriptor

        return None
