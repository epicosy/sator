from sator.core.models.patch.attributes import PatchAttributes
from sator.core.models.patch.descriptor import PatchDescriptor

from sator.core.ports.driven.classifiers.diff import DiffClassifierPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driven.classifiers.weakness import WeaknessClassifierPort
from sator.core.ports.driven.classifiers.patch_action import PatchActionClassifierPort
from sator.core.ports.driving.annotation.attributes.patch import PatchAttributesAnnotationPort


class PatchAttributesAnnotation(PatchAttributesAnnotationPort):
    def __init__(self, diff_classifier_port: DiffClassifierPort, patch_action_classifier: PatchActionClassifierPort,
                 weakness_classifier: WeaknessClassifierPort, storage_port: StoragePersistencePort):
        self.weakness_classifier = weakness_classifier
        self.diff_classifier = diff_classifier_port
        self.patch_action_classifier = patch_action_classifier
        self.storage_port = storage_port

    def annotate_patch_attributes(self, vulnerability_id: str) -> PatchDescriptor | None:
        patch_descriptor = self.storage_port.load(PatchDescriptor, vulnerability_id)

        if patch_descriptor:
            return patch_descriptor

        patch_attributes = self.storage_port.load(PatchAttributes, vulnerability_id)

        if patch_attributes:
            weakness_keywords = patch_attributes.sec_words

            if patch_attributes.flaw:
                weakness_keywords.append(patch_attributes.flaw)

            weakness_type = self.weakness_classifier.classify_weakness(weakness_keywords)
            action_type = self.patch_action_classifier.classify_patch_action(patch_attributes.action)
            diff_descriptor = self.diff_classifier.classify_diff(patch_attributes.diff)

            patch_descriptor = PatchDescriptor(
                action_type=action_type, weakness_type=weakness_type, diff_descriptor=diff_descriptor
            )
            self.storage_port.save(patch_descriptor, vulnerability_id)

            return patch_descriptor

        return None
