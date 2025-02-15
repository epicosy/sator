from pydantic import BaseModel
from sator.core.models.product import Product


class ProductOwnership(BaseModel):
    product: Product
    owner_id: int

    def __hash__(self):
        return hash((self.product, self.owner_id))

    def __eq__(self, other):
        if not isinstance(other, ProductOwnership):
            return False

        return self.product == other.product and self.owner_id == other.owner_id

    def __str__(self):
        return f"{self.product} | Owner ID - {self.owner_id}"


class ProductLocator(BaseModel):
    product_ownership: ProductOwnership
    repository_id: int

    def __hash__(self):
        return hash((self.product_ownership, self.repository_id))

    def __eq__(self, other):
        if not isinstance(other, ProductLocator):
            return False

        return self.product_ownership == other.product_ownership and self.repository_id == other.repository_id

    def __str__(self):
        return f"{self.product_ownership} | Repository ID - {self.repository_id}"
