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


class LicenseType(str, Enum):
    """
        Enum for different types of licenses.
    """
    PROPRIETARY = "Proprietary"
    OPEN_SOURCE = "Open Source"
    UNDEFINED = "Undefined"


class RootCauseType(str, Enum):
    """
        Enum for different types of root causes.
    """
    MISSING_CODE = "Missing Code"
    ERRONEOUS_CODE = "Erroneous Code"
    UNDEFINED = "Undefined"


class ImproperOperationType(str, Enum):
    """
        Enum for different types of operations.
    """
    INITIALIZE = "Initialize"
    READ = "Read"
    WRITE = "Write"
    CLEAR = "Clear"
    UNDEFINED = "Undefined"


class ErrorType(str, Enum):
    """
        Enum for different types of consequences.
    """
    NCO = "Not Cleared Object"
    OC = "Object Corruption"
    TC = "Type Confusion"
    UAD = "Use After Deallocate"
    BOF = "Buffer Overflow"
    BUF = "Buffer Underflow"
    BOR = "Buffer Over-Read"
    BUR = "Buffer Under-Read"


class DiffChangeType(str, Enum):
    """
        Enum for different types of diff hunk annotations.
    """
    ADDITION = "Addition"
    DELETION = "Deletion"
    MODIFICATION = "Modification"


class DiffContentType(str, Enum):
    """
        Enum for different types of diff hunk annotations.
    """
    IF_STMT_ADD = "If Statement Addition"
    BIN_EXPR_ADD = "Binary Expression Addition"
    WHITESPACE = "Whitespace"
    COMMENT = "Comment"
    UNDEFINED = "Undefined"


class DescriptionType(str, Enum):
    """
        Enum for different types of descriptions.
    """
    CVE = "CVE"
    OTHER = "Other"
    # TODO: add more description types


class ImpactType(str, Enum):
    """
        Enum for different types of impacts.
    """
    DENIAL_OF_SERVICE = "Denial of Service"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    CODE_EXECUTION = "Code Execution"
    PRIVILEGE_ESCALATION = "Privilege Escalation"


class WeaknessType(str, Enum):
    """
    Enum for different types of weaknesses.
    """
    MEMORY_SAFETY = "Memory Safety"
    TYPE_SAFETY = "Type Safety"
    INPUT_SAFETY = "Input Safety"


class PatchActionType(str, Enum):
    CORRECTIVE = "Corrective"
    ADAPTIVE = "Adaptive"
    ENHANCEMENT = "Enhancement"

    # TODO: add more patch action types
