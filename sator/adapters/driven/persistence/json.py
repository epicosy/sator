import json
from pathlib import Path

from sator.core.models.patch import PatchReferences, PatchAttributes, PatchDescriptor, PatchLocator
from sator.core.models.product import ProductLocator, ProductAttributes, ProductDescriptor, ProductReferences

from sator.core.models.vulnerability import (VulnerabilityLocator, VulnerabilityMetadata, VulnerabilityAttributes,
                                             VulnerabilityReferences, VulnerabilityDescriptor, VulnerabilityDescription)

from sator.core.ports.driven.persistence.storage import StoragePersistencePort, T


PATHS_BY_ENTITY = {
    PatchLocator: "patch/locators",
    PatchReferences: "patch/references",
    PatchAttributes: "patch/attributes",
    PatchDescriptor: "patch/descriptors",
    ProductLocator: "product/locators",
    ProductAttributes: "product/attributes",
    ProductReferences: "product/references",
    ProductDescriptor: "product/descriptors",
    VulnerabilityLocator: "vulnerability/locators",
    VulnerabilityMetadata: "vulnerability/metadata",
    VulnerabilityAttributes: "vulnerability/attributes",
    VulnerabilityReferences: "vulnerability/references",
    VulnerabilityDescriptor: "vulnerability/descriptors",
    VulnerabilityDescription: "vulnerability/descriptions"
}


class JsonPersistence(StoragePersistencePort):
    """Generic file-based persistence for domain models, using JSON storage."""

    def __init__(self, base_folder: str):
        self.base_folder = Path(base_folder).expanduser()
        self.base_folder.mkdir(parents=True, exist_ok=True)

    def save(self, entity: T, entity_id: str) -> bool:
        """Persist an entity as a JSON file in a dynamic folder structure."""

        # check if the entity has the method dump
        if not hasattr(entity, "model_dump_json"):
            return False

        file_path = self.base_folder / PATHS_BY_ENTITY[type(entity)] / f"{entity_id}.json"

        # Ensure the directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(entity.model_dump_json(indent=4))

        return True

    def load(self, entity: T, entity_id: str) -> T:
        file_path = self.base_folder / PATHS_BY_ENTITY[entity] / f"{entity_id}.json"

        if not file_path.exists():
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return entity(
            **data
        )
