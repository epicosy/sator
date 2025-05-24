import re
import requests
from typing import List, Counter as CounterType
from collections import Counter
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from sator_core.models.product import Product, ProductAttributes, ProductReferences
from sator_core.ports.driven.extraction.attributes.product import ProductAttributesExtractorPort


class KeywordBasedProductAttributesExtractor(ProductAttributesExtractorPort):
    # Define platform keywords
    PLATFORM_KEYWORDS = {
        'linux': ['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'redhat', 'rhel'],
        'macos': ['macos', 'mac os', 'osx', 'mac', 'apple'],
        'windows': ['windows', 'win32', 'win64', 'win', 'microsoft'],
        'android': ['android'],
        'ios': ['ios', 'iphone', 'ipad'],
        'unix': ['unix', 'solaris', 'freebsd', 'openbsd', 'netbsd'],
    }

    # Define architecture keywords
    ARCHITECTURE_KEYWORDS = {
        'x86': ['x86', 'x86_64', 'x64', 'amd64', 'intel'],
        'arm': ['arm', 'arm64', 'aarch64', 'armv7', 'armv8'],
        'powerpc': ['powerpc', 'ppc'],
        'mips': ['mips'],
        'risc-v': ['risc-v', 'riscv'],
    }

    # Common words to exclude from keyword extraction
    STOP_WORDS = {
        'the', 'and', 'is', 'in', 'it', 'to', 'of', 'for', 'with', 'on', 'at', 'from', 'by', 'about',
        'as', 'an', 'are', 'be', 'this', 'that', 'these', 'those', 'was', 'were', 'has', 'have', 'had',
        'a', 'or', 'if', 'but', 'not', 'what', 'all', 'when', 'where', 'which', 'who', 'will', 'more',
        'no', 'there', 'their', 'than', 'them', 'then', 'they', 'can', 'could', 'should', 'would',
        'may', 'might', 'must', 'now', 'been', 'do', 'does', 'did', 'just', 'into', 'only', 'other',
        'some', 'such', 'than', 'very', 'how', 'many', 'most', 'own', 'same', 'so', 'too', 'use',
        'any', 'each', 'few', 'her', 'his', 'its', 'our', 'she', 'we', 'you', 'your',
    }

    def extract_product_attributes(self, product: Product, references: ProductReferences) -> ProductAttributes | None:
        """
        Extract product attributes by analyzing content from product references.

        Args:
            product: The product to extract attributes for
            references: References to the product (URLs)

        Returns:
            ProductAttributes object with extracted information
        """
        print(f"Starting extraction for product: {product.name} (vendor: {product.vendor})")

        # Initialize attributes with Counter instead of set
        keywords = Counter()
        platforms = Counter()

        # Add product name and vendor as initial keywords
        name_tokens = self._tokenize_text(product.name)
        vendor_tokens = self._tokenize_text(product.vendor)
        print(f"Initial name tokens: {name_tokens}")
        print(f"Initial vendor tokens: {vendor_tokens}")

        keywords.update(name_tokens)
        keywords.update(vendor_tokens)
        print(f"Keywords after adding name and vendor: {dict(keywords)}")

        # Process each reference URL
        print(f"Processing {len(references)} reference URLs")
        for i, url in enumerate(references):
            print(f"Processing URL {i+1}/{len(references)}: {url}")
            try:
                # Skip URLs that are likely not to contain useful text content
                parsed_url = urlparse(str(url))
                if parsed_url.path.lower().endswith(('.jpg', '.png', '.gif', '.pdf', '.zip', '.tar.gz')):
                    print(f"Skipping URL with non-text extension: {url}")
                    continue

                # Fetch content from URL
                print(f"Fetching content from URL: {url}")
                content = self._fetch_url_content(str(url))
                if not content:
                    print(f"No content retrieved from URL: {url}")
                    continue
                print(f"Retrieved {len(content)} characters of content")

                # Extract keywords from content
                print(f"Extracting keywords from content")
                content_keywords = self._extract_keywords(content)
                print(f"Extracted {len(content_keywords)} unique keywords from content")
                keywords.update(content_keywords)
                print(f"Total keywords count after update: {len(keywords)}")

                # Detect platforms and architectures
                print(f"Detecting platforms from content")
                detected_platforms = self._detect_platforms(content)
                print(f"Detected platforms: {dict(detected_platforms)}")
                platforms.update(detected_platforms)
                print(f"Total platforms after update: {dict(platforms)}")

            except Exception as e:
                # Skip URLs that can't be processed
                print(f"Error processing URL {url}: {str(e)}")
                continue

        # If no platforms were detected from content, try to detect from keywords
        if not platforms:
            print("No platforms detected from content, trying to detect from keywords")
            platforms = self._detect_platforms_from_keywords(keywords)
            print(f"Platforms detected from keywords: {dict(platforms)}")

        # Get the most common keywords (up to 20)
        print("Getting top keywords")
        top_keywords = self._get_top_keywords(keywords, max_count=20)
        print(f"Top keywords: {top_keywords}")
        print(f"Final platforms: {dict(platforms)}")

        return ProductAttributes(
            product_id=product.id,
            name=product.name,
            keywords=list(top_keywords),
            platforms=[p for p, _ in platforms.most_common()]
        )

    def _fetch_url_content(self, url: str) -> str:
        """Fetch content from a URL"""
        try:
            response = requests.get(str(url), timeout=10)
            response.raise_for_status()
            return response.text
        except Exception:
            return ""

    def _tokenize_text(self, text: str) -> List[str]:
        """Split text into tokens and remove stop words"""
        if not text:
            return []

        # Convert to lowercase and split by non-alphanumeric characters
        tokens = re.findall(r'\b[a-zA-Z0-9]{3,}\b', text.lower())

        # Remove stop words and short tokens
        return [token for token in tokens if token not in self.STOP_WORDS and len(token) > 2]

    def _extract_text_from_html(self, html_content: str) -> str:
        """
        Extract text from HTML content, focusing on elements that contain meaningful text
        like divs, headers, paragraphs, etc. to avoid noisy HTML tags and attributes.
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements that contain non-relevant text
            for element in soup(['script', 'style', 'meta', 'link', 'svg', 'path']):
                element.decompose()

            # Extract text from common text-containing elements
            text_elements = []

            # Define elements that typically contain meaningful text
            text_containing_elements = [
                'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                'div', 'span', 'li', 'a', 'td', 'th', 
                'caption', 'label', 'button', 'article',
                'section', 'main', 'header', 'footer',
                'blockquote', 'cite', 'code', 'pre',
                'strong', 'em', 'b', 'i', 'u', 'small',
                'mark', 'del', 'ins', 'sub', 'sup'
            ]

            # Get text from text-containing elements
            for element in soup.find_all(text_containing_elements):
                # Skip empty elements or those with only whitespace
                if element.string and element.string.strip():
                    text_elements.append(element.string.strip())
                else:
                    # For elements with mixed content, get all text
                    extracted_text = element.get_text(separator=' ', strip=True)
                    if extracted_text:
                        text_elements.append(extracted_text)

            # If no text was extracted from specific elements, fall back to getting all text
            if not text_elements:
                print("No text found in specific elements, extracting all text...")
                text = soup.get_text(separator=' ', strip=True)
                return text

            # Join all extracted text with spaces and remove excessive whitespace
            text = ' '.join(text_elements)
            # Replace multiple spaces with a single space
            text = re.sub(r'\s+', ' ', text).strip()

            return text
        except Exception as e:
            print(f"Error parsing HTML: {str(e)}")
            # If parsing fails, return the original content
            return html_content

    def _extract_keywords(self, text: str) -> CounterType[str]:
        """Extract keywords from text"""
        # First extract meaningful text from HTML if the content appears to be HTML
        # Check for common HTML tags and patterns
        html_indicators = [
            # Common HTML structural tags
            '<html', '<body', '<head', '<div', '<p>', '<h1', '<h2', '<h3', '<h4', '<h5', '<h6',
            '<span', '<a href', '<table', '<tr', '<td', '<th', '<ul', '<ol', '<li>', '<br', 
            # Script and style tags
            '<script', '<style', '<link rel=', '<meta',
            # Common attributes
            'class=', 'id=', 'style=', 'href=', 'src=', 'alt=', 'title=',
            # HTML entities
            '&lt;', '&gt;', '&amp;', '&quot;', '&apos;', '&#', '&nbsp;',
            # Other indicators
            '<!DOCTYPE', '<!--', '-->', '<![CDATA[', 
            # SVG and XML related
            '<svg', '<path', '<rect', '<circle', '<g>', '<xml', '<xmlns'
        ]

        is_likely_html = any(indicator in text.lower() for indicator in html_indicators)

        if is_likely_html:
            print("Content appears to be HTML, extracting meaningful text...")
            text = self._extract_text_from_html(text)
            print(f"Extracted text from HTML, new length: {len(text)}")

        tokens = self._tokenize_text(text)
        return Counter(tokens)

    def _get_top_keywords(self, keywords: CounterType[str], max_count: int = 20) -> List[str]:
        """Get the most common keywords"""
        if not keywords:
            return []

        # Get the most common keywords
        most_common = keywords.most_common(max_count)
        print(f"Most common keywords: {most_common}")

        # If multiple keywords have the same count, prefer longer ones
        result = []
        current_count = None
        same_count_keywords = []

        for keyword, count in most_common:
            if current_count is None:
                current_count = count

            if count == current_count:
                same_count_keywords.append(keyword)
            else:
                # Sort keywords with the same count by length
                result.extend(sorted(same_count_keywords, key=len, reverse=True))
                same_count_keywords = [keyword]
                current_count = count

        # Add the last group of keywords
        result.extend(sorted(same_count_keywords, key=len, reverse=True))

        return result[:max_count]

    def _detect_platforms(self, text: str) -> CounterType[str]:
        """Detect platforms mentioned in text"""
        text = text.lower()
        platforms = Counter()

        # Check for platform keywords
        for platform, keywords in self.PLATFORM_KEYWORDS.items():
            # Count occurrences of each keyword
            matches = sum(text.count(keyword) for keyword in keywords)
            if matches > 0:
                platforms[platform] = matches
                print(f"  Found platform '{platform}' with {matches} matches")

        # Check for architecture keywords
        for arch, keywords in self.ARCHITECTURE_KEYWORDS.items():
            # Count occurrences of each keyword
            matches = sum(text.count(keyword) for keyword in keywords)
            if matches > 0:
                platforms[arch] = matches
                print(f"  Found architecture '{arch}' with {matches} matches")

        return platforms

    def _detect_platforms_from_keywords(self, keywords: CounterType[str]) -> CounterType[str]:
        """Detect platforms from extracted keywords"""
        platforms = Counter()

        # Convert keywords to lowercase for matching
        lowercase_keywords = {k.lower(): v for k, v in keywords.items()}

        # Check for platform keywords
        for platform, platform_keywords in self.PLATFORM_KEYWORDS.items():
            matches = sum(lowercase_keywords.get(keyword, 0) for keyword in platform_keywords if keyword in lowercase_keywords)
            if matches > 0:
                platforms[platform] = matches
                print(f"  Found platform '{platform}' with {matches} matches from keywords")

        # Check for architecture keywords
        for arch, arch_keywords in self.ARCHITECTURE_KEYWORDS.items():
            matches = sum(lowercase_keywords.get(keyword, 0) for keyword in arch_keywords if keyword in lowercase_keywords)
            if matches > 0:
                platforms[arch] = matches
                print(f"  Found architecture '{arch}' with {matches} matches from keywords")

        return platforms
