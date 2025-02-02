from enum import Enum


class ProductPart(str, Enum):
    """
        Enum for different parts of a product.
    """
    HARDWARE = "Hardware"
    OPERATING_SYSTEM = "Operating System"
    APPLICATION = "Application"
    UNDEFINED = "Undefined"


class ProductType(str, Enum):
    """
        Enum for different types of product technologies.
    """
    FIRMWARE = "Firmware"
    EMBEDDED = "Embedded"
    DESKTOP = "Desktop"
    MOBILE = "Mobile"
    UTILITY = "Utility"
    LIBRARY = "Library"
    FRAMEWORK = "Framework"
    DATABASE = "Database"
    PLUGIN = "Plugin"
    SERVER = "Server"
    WEB_APPLICATION = "Web Application"
    UNDEFINED = "Undefined"
