from typing import List
from pydantic import BaseModel


class ProductMetadata(BaseModel):
    name: str
    vendor: str
    versions: List[str]

    def __str__(self):
        return f"{self.name} by {self.vendor} with {len(self.versions)} versions"
