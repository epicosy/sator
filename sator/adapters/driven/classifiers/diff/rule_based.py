import code_diff as cd
from code_diff.gumtree import EditScript, Insert, Delete

from pathlib import Path
from sator.core.models.enums import DiffChangeType, DiffContentType
from sator.core.models.oss.annotation import DiffHunkAnnotation, PatchAnnotation, DiffAnnotation
from sator.core.ports.driven.classifiers.diff import DiffClassifierPort

LANG_MAP = {
    ".c": "c",
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
}


# syntactically valid but semantically neutral statement to ensure the tokenizer works
NTL_STMT_PLH = {
    ".py": "pass",
    ".js": ";",
    ".java": "{}",
    ".c": "{}",
}

ADDITION_MAP = {
    "if_statement": DiffContentType.IF_STMT_ADD,
    "binary_expression": DiffContentType.BIN_EXPR_ADD,
}


def parse_ast_diff(ast_diff: EditScript):
    root_node = ast_diff[0]

    if isinstance(root_node, Insert):
        return ADDITION_MAP.get(root_node.node[0], DiffContentType.UNDEFINED)

        # TODO: implement more cases
    elif isinstance(root_node, Delete):
        # TODO: to be implemented
        pass

    return DiffContentType.UNDEFINED


def get_diff_hunk_annotation(order: int, new_code: str, change_type: DiffChangeType, file_suffix: str,
                             old_code: str = None) -> DiffHunkAnnotation:
    """Computes the AST-based diff type for additions and modifications."""
    old_code = old_code if old_code is not None else NTL_STMT_PLH[file_suffix]
    output = cd.difference(old_code, new_code, lang=LANG_MAP[file_suffix])
    ast_diff = output.edit_script()
    diff_hunk_type = parse_ast_diff(ast_diff)

    return DiffHunkAnnotation(order=order, change_type=change_type, content_type=diff_hunk_type)


def analyze_hunk(order: int, hunk, file_suffix: str) -> DiffHunkAnnotation:
    """Analyzes a single hunk and returns its annotation."""
    clean_old_code, clean_new_code = hunk.old_code.strip(), hunk.new_code.strip()

    if not clean_old_code and not clean_new_code:
        return DiffHunkAnnotation(order=order, change_type=DiffChangeType.MODIFICATION,
                                  content_type=DiffContentType.WHITESPACE)

    if not clean_old_code:
        return get_diff_hunk_annotation(order, hunk.new_code, DiffChangeType.ADDITION, file_suffix)

    if not clean_new_code:
        return DiffHunkAnnotation(order=order, change_type=DiffChangeType.DELETION,
                                  content_type=DiffContentType.UNDEFINED)

    return get_diff_hunk_annotation(order, hunk.new_code, DiffChangeType.MODIFICATION, file_suffix, hunk.old_code)


class RuleBasedDiffClassifier(DiffClassifierPort):
    def classify_diff(self, diff) -> DiffAnnotation | None:
        patches = []

        for patch in diff.patches:
            path = Path(patch.new_file)

            if path.suffix not in LANG_MAP:
                continue

            hunks = [analyze_hunk(i, hunk, path.suffix) for i, hunk in enumerate(patch.hunks)]
            patches.append(PatchAnnotation(new_file=patch.new_file, hunks=hunks))

        return DiffAnnotation(patches=patches) if patches else None
