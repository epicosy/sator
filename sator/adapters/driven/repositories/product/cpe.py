from typing import List
from rapidfuzz import fuzz
from pydantic import AnyUrl

from cpelib.types.definitions import CPEPart
from cpelib.core.loaders.json import JSONLoader

from sator.core.models.product import Product, ProductReferences
from sator.core.models.enums import ProductPart, ProductType

from sator.core.ports.driven.repositories.product import ProductRepositoryPort


CPE_PART_TO_PRODUCT_PART = {
    CPEPart.Application: ProductPart.APPLICATION,
    CPEPart.OS: ProductPart.OPERATING_SYSTEM,
    CPEPart.Hardware: ProductPart.HARDWARE,
}

WILDCARDS = ["*", "-", ""]


class CPEDictionary(ProductRepositoryPort):
    def __init__(self, path: str):
        self.loader = JSONLoader(path)

    def get_vendor_products(self, vendor_name: str) -> List[Product]:
        # TODO: Implement this method
        return []

    def get_product(self, vendor_name: str, product_name: str) -> Product | None:
        cpe_dict = self.loader.load(vendor_name=vendor_name, product_name=product_name)

        if len(cpe_dict) > 0:
            return Product(
                vendor=vendor_name,
                name=product_name,
            )

        return None

    def search(self, vendor_name: str, product_name: str, n: int = 10) -> List[Product]:
        cpe_dict = self.loader.load(vendor_name=vendor_name, product_name=product_name)

        if len(cpe_dict.vendors) > 1:
            print("Multiple vendors found")
            # TODO: implement this case to return the n most relevant products
            pass

        if len(cpe_dict.vendors) == 1:
            print("Single vendor found")
            if not vendor_name:
                vendor_name = list(cpe_dict.vendors.keys())[0]

            best_matches = {}

            for item in cpe_dict.items.values():
                product = item.cpe.get_product()

                if product.name in best_matches:
                    continue

                similarity = fuzz.ratio(product_name.lower(), product.name)  # Compute similarity
                best_matches[product.name] = similarity

            # Sort by similarity score (descending) and return top `n` matches
            sorted_matches = sorted(best_matches.items(), key=lambda x: x[1], reverse=True)

            return [Product(vendor=vendor_name, name=product_name) for product_name, sim in sorted_matches[:n]]

        # TODO: implement case that loads everything and returns the n most relevant products

        return []

    def get_version(self, product: Product, version: str) -> str | None:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        # TODO: find the best way to parse the version
        clean_version = version.replace("before", "").replace("after", "").strip()

        if len(cpe_dict) > 0:
            # TODO: maybe should keep track of the closest version, and return it if it is close enough
            for cpe_item in cpe_dict.items.values():
                if cpe_item.cpe.version == clean_version:
                    return clean_version

        return None

    def get_versions(self, product: Product) -> List[str]:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        return [cpe_item.cpe.version for cpe_item in cpe_dict.items.values() if cpe_item.cpe.version not in WILDCARDS]

    def get_product_references(self, product: Product) -> ProductReferences:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)
        if not cpe_dict:
            return ProductReferences()  # Early return if no data is loaded

        product_references = ProductReferences()
        seen_refs = set()

        # Define a mapping of tag types to product reference categories
        tag_to_category = {
            "Project": product_references.product,
            "Product": product_references.product,
            "Advisory": product_references.advisories,
            "Version": product_references.releases,
            "Website": product_references.website,
        }

        for cpe_item in cpe_dict.items.values():
            for reference in cpe_item.references:
                if reference.href in seen_refs:
                    continue  # Skip duplicates

                seen_refs.add(reference.href)

                intersection = set(reference.tags).intersection(tag_to_category.keys())

                # TODO: AnyUrl should not be a thing here
                if intersection:
                    tag = intersection.pop()
                    tag_to_category[tag].append(AnyUrl(reference.href))
                else:
                    product_references.other.append(AnyUrl(reference.href))

        return product_references

    def get_product_part(self, product: Product) -> ProductPart:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        if len(cpe_dict) > 0:
            first_item = list(cpe_dict.items.values())[0]
            return CPE_PART_TO_PRODUCT_PART[first_item.cpe.part]

        return ProductPart.UNDEFINED

    def get_product_type(self, product: Product) -> ProductType:
        return ProductType.UNDEFINED
