from pydantic import BaseModel


class Product(BaseModel):
    name: str
    vendor: str

    @property
    def id(self):
        return f"{self.vendor}/{self.name}"

    def __hash__(self):
        return hash((self.name, self.vendor))

    def __eq__(self, other):
        if not isinstance(other, Product):
            return False

        return self.name == other.name and self.vendor == other.vendor

    def __str__(self):
        return self.id
