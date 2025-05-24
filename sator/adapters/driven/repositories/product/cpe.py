import re
from typing import List
from rapidfuzz import fuzz
from pydantic import AnyUrl
from packaging.version import Version

from cpelib.types.definitions import CPEPart
from cpelib.core.loaders.json import JSONLoader

from sator_core.models.product import Product, ProductReferences, Configuration
from sator_core.models.enums import ProductPart, ProductType

from sator_core.ports.driven.repositories.product import ProductRepositoryPort


CPE_PART_TO_PRODUCT_PART = {
    CPEPart.Application: ProductPart.APPLICATION,
    CPEPart.OS: ProductPart.OPERATING_SYSTEM,
    CPEPart.Hardware: ProductPart.HARDWARE,
}

WILDCARDS = ["*", "-", ""]

VERSION_PATTERN = r'\b((?:v\.|v|R)*(?:\d+(?:\.(?:\d+|x))+)(?:\-\d|a)*|\d{4}-\d{2}-\d{2}|[0-9a-f]{5,40})\b'

CONFIG_STOP_WORDS = [
    "through",
    "and",
    "versions",
    "prior",
    "before",
    "version",
    "to",
    "library",
    "project",
    "master",
    "all",
    "below",
    "component",
    "the",
    "commit",
    "earlier",
    "<=",
    "software",
    "up",
    "including"
]

PHRASINGS = [
    "HTTP server",
    "FTP server",
    "binary in"
]


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

    @staticmethod
    def _get_n_most_similar_products(vendor_name: str, product_name: str, cpe_dict, n: int = 10) -> List[Product]:
        results = []
        best_matches = {}

        for item in cpe_dict.items.values():
            product = item.cpe.get_product()

            if product.name in best_matches:
                continue

            similarity = fuzz.ratio(product_name.lower(), product.name)
            best_matches[product.name] = similarity

        # Sort by similarity score (descending) and return top `n` matches
        for product_name, sim in sorted(best_matches.items(), key=lambda x: x[1], reverse=True)[:n]:
            results.append(Product(vendor=vendor_name, name=product_name))

        return results

    def search(self, vendor_name: str, product_name: str, n: int = 10) -> List[Product]:
        results = []

        if not vendor_name and not product_name:
            return []

        # TODO: approach multi-vendors by iterating
        if vendor_name:
            print(f"Searching by vendor name {vendor_name}")
            vendor_name = vendor_name.lower()
            cpe_dict = self.loader.load(vendor_name=vendor_name)
            print(f"Found {len(cpe_dict.items)} items")

            if len(cpe_dict.vendors) == 1:
                results = self._get_n_most_similar_products(vendor_name, product_name, cpe_dict, n)

            if len(results) > 0:
                return results

            vendor_name = None

        if product_name:
            print(f"Searching by product name {product_name}")
            product_name = product_name.lower()
            cpe_dict = self.loader.load(vendor_name=vendor_name, product_name=product_name)
            print(f"Found {len(cpe_dict.items)} items")

            if len(cpe_dict.vendors) == 1:
                print("Single vendor found")
                vendor_name = list(cpe_dict.vendors.keys())[0]

                return self._get_n_most_similar_products(vendor_name, product_name, cpe_dict, n)

        # TODO: implement case that loads everything and returns the n most relevant products

        return results

    def search_config_by_str(self, configuration: str) -> Configuration | None:
        config_clean = configuration.replace(",", "").strip()

        # Remove phrases from the configuration string
        for phrasing in PHRASINGS:
            config_clean = config_clean.replace(phrasing, "")

        config_clean = config_clean.lower()
        stop_words_to_remove = list(set(config_clean.split()).intersection(CONFIG_STOP_WORDS))
        print(f"Stop words to remove: {stop_words_to_remove}")
        # Remove stop words from the configuration string
        for stop_word in stop_words_to_remove:
            config_clean = re.sub(rf"\b{stop_word}\b", "", config_clean)

        # Extract the versions from the configuration string
        matches = re.findall(VERSION_PATTERN, config_clean)
        versions = []

        if matches:
            for match in matches:
                versions.append(match)
                config_clean = config_clean.replace(match, "")

        print(versions)
        config_clean = re.sub(r'\s+', ' ', config_clean)
        config_clean = config_clean.strip()

        if config_clean == "":
            return None

        try:
            oldest = min(versions, key=Version) if len(versions) > 0 else ""
        except ValueError:
            # TODO: Handle the case where no valid version is found
            # TODO: make the Configuration model accept None
            oldest = ""

        terms = config_clean.split(" ", maxsplit=1)
        print(terms)

        if len(terms) > 1:
            vendor_name = terms[0]
            product_name = terms[1].replace(" ", "_")
        else:
            vendor_name = None
            product_name = terms[0]

        products = self.search(vendor_name=vendor_name, product_name=product_name, n=1)

        if len(products) > 0:
            return Configuration(
                product=products[0],
                version=oldest,
            )

        return None

    def get_version(self, product: Product, version: str) -> str | None:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        # TODO: find the best way to parse the version
        match = re.search(VERSION_PATTERN, version)

        if match:
            match_version = match.group(0)
        else:
            match_version = version.replace("before", "").replace("after", "").strip()

        if len(cpe_dict) > 0:
            # TODO: maybe should keep track of the closest version, and return it if it is close enough
            for cpe_item in cpe_dict.items.values():
                if cpe_item.cpe.version == match_version:
                    return match_version

        return None

    def get_versions(self, product: Product) -> List[str]:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        return [cpe_item.cpe.version for cpe_item in cpe_dict.items.values() if cpe_item.cpe.version not in WILDCARDS]

    def get_product_references(self, product: Product) -> ProductReferences:
        product_references = ProductReferences(
            product_id=product.id,
        )
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        if not cpe_dict:
            return product_references  # Early return if no data is loaded

        seen_refs = set()

        # Define a mapping of tag types to product reference categories
        tag_to_category = {
            "Repositories": product_references.repositories,
            "PURLs": product_references.purls,
            "Homepage": product_references.homepage,
        }

        for cpe_item in cpe_dict.items.values():
            for reference in cpe_item.references:
                if reference.href in seen_refs:
                    continue  # Skip duplicates

                seen_refs.add(reference.href)

                if 'github.com' in reference.href:
                    reference.tags.append("Repositories")

                if reference.href.startswith("pkg:"):
                    reference.tags.append("PURLs")

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
