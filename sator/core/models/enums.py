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


class RootCauseType(str, Enum):
    """
        Enum for different types of root causes.
    """
    MISSING_CODE = "Missing Code"
    ERRONEOUS_CODE = "Erroneous Code"
    UNDEFINED = "Undefined"


class DiffHunkType(str, Enum):
    """
        Enum for different types of diff hunk annotations.
    """
    IF_STMT_ADD = "If Statement Addition"
    BIN_EXPR_ADD = "Binary Expression Addition"
    ADDITION = "Addition"
    DELETION = "Deletion"
    MODIFICATION = "Modification"
    WHITESPACE = "Whitespace"
    COMMENT = "Comment"
