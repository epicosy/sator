
from sator.core.models.oss.diff import Diff
from sator.core.models.enums import DiffHunkType


from sator.core.ports.driving.annotation.diff import DiffAnnotationPort
from sator.core.ports.driven.classifiers.diff import DiffClassifierPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort


class DiffAnnotation(DiffAnnotationPort):
    def __init__(self, diff_classifier_port: DiffClassifierPort, storage_port: StoragePersistencePort):
        self.diff_classifier = diff_classifier_port
        self.storage_port = storage_port

    def annotate_diff(self, vulnerability_id: str) -> DiffHunkType | None:
        diff = self.storage_port.load(Diff, vulnerability_id)

        if diff:
            print(f"Annotating diff {diff.commit_sha}")
            diff_annotation = self.diff_classifier.classify_diff(diff)

            return diff_annotation

        return None
