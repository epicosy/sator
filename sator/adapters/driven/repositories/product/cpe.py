import json

from typing import List
from pathlib import Path
from cpelib.core.loaders.json import JSONLoader

from sator.core.ports.driven.repositories.product import ProductReferencePort


class CPEDictionary(ProductReferencePort):
    def __init__(self, path: str):
        self.loader = JSONLoader(path)

    def get_vendor_products(self, vendor_name: str):
        pass

    def get_product_references(self, vendor_name: str, product_name: str) -> List[str]:
        cpe_dict = self.loader.load(vendor_name=vendor_name, product_name=product_name)

        return [ref.href for ref in cpe_dict.get_references()]
