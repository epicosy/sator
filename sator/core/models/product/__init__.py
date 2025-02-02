from dataclasses import dataclass


@dataclass
class Product:
    name: str
    vendor: str

    def __hash__(self):
        return hash((self.name, self.vendor))

    def __eq__(self, other):
        if not isinstance(other, Product):
            return False

        return self.name == other.name and self.vendor == other.vendor
