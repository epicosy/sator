from enum import Enum


class ProductPart(Enum):
    """
        Enum for different parts of a product.
    """
    HARDWARE = "Hardware"
    OPERATING_SYSTEM = "Operating System"
    APPLICATION = "Application"


class ProductType(Enum):
    """
        Enum for different types of product technologies.
    """
    FIRMWARE = "Firmware"
    UTILITY = "Utility"
    LIBRARY = "Library"
    FRAMEWORK = "Framework"
    DATABASE = "Database"
    PLUGIN = "Plugin"
    SERVER = "Server"
    WEB_APPLICATION = "Web Application"
    UNDEFINED = "Undefined"
