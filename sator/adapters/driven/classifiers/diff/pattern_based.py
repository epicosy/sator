import code_diff as cd
from code_diff.gumtree import EditScript, Insert, Delete

from pathlib import Path
from sator.core.models.enums import DiffHunkType
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


def parse_ast_diff(ast_diff: EditScript):
    root_node = ast_diff[0]

    if isinstance(root_node, Insert):
        if root_node.node[0] == "if_statement":
            return DiffHunkType.IF_STMT_ADD

        if root_node.node[0] == "binary_expression":
            return DiffHunkType.BIN_EXPR_ADD

        # TODO: implement more cases
    elif isinstance(root_node, Delete):
        # TODO: to be implemented
        pass

    return DiffHunkType.MODIFICATION


class PatternBasedDiffClassifier(DiffClassifierPort):
    def classify_diff(self, diff) -> DiffAnnotation | None:
        patches = []

        for patch in diff.patches:
            path = Path(patch.old_file)

            if path.suffix not in LANG_MAP:
                continue

            hunks = []

            for i, hunk in enumerate(patch.hunks):
                clean_old_code = hunk.old_code.strip()
                clean_new_code = hunk.new_code.strip()
                # check for empty strings
                if len(clean_old_code) == 0:
                    if len(clean_new_code) == 0:
                        hunk_annotation = DiffHunkAnnotation(order=i, type=DiffHunkType.WHITESPACE)
                    else:
                        output = cd.difference(NTL_STMT_PLH[path.suffix], hunk.new_code, lang=LANG_MAP[path.suffix])
                        ast_diff = output.edit_script()
                        diff_hunk_type = parse_ast_diff(ast_diff)
                        hunk_annotation = DiffHunkAnnotation(order=i, type=diff_hunk_type)

                elif len(clean_new_code) == 0:
                    # TODO: find a way to parse only deletion hunks
                    hunk_annotation = DiffHunkAnnotation(order=i, type=DiffHunkType.DELETION)
                else:
                    output = cd.difference(hunk.old_code, hunk.new_code, lang=LANG_MAP[path.suffix])
                    ast_diff = output.edit_script()
                    diff_hunk_type = parse_ast_diff(ast_diff)
                    hunk_annotation = DiffHunkAnnotation(order=i, type=diff_hunk_type)

                hunks.append(hunk_annotation)

            patch_annotation = PatchAnnotation(new_file=patch.new_file, hunks=hunks)
            patches.append(patch_annotation)

        return DiffAnnotation(commit_sha=diff.commit_sha, patches=patches) if patches else None
