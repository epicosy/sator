from typing import Tuple

from sator.core.models.enums import DiffChangeType, DiffContentType
from sator.core.models.patch import PatchAttributes, PatchDescriptor
from sator.core.ports.driven.analyzers.patch import PatchAttributesAnalyzerPort


CHANGE_TYPE_SCORE = {
    DiffChangeType.DELETION: 1,
    DiffChangeType.MODIFICATION: 2,
    DiffChangeType.ADDITION: 3,
}

CONTENT_TYPE_SCORE = {
    DiffContentType.COMMENT: 0,
    DiffContentType.WHITESPACE: 0,
    DiffContentType.BIN_EXPR_ADD: 1,
    DiffContentType.IF_STMT_ADD: 2,
}


class ScorePatchAttributesAnalyzer(PatchAttributesAnalyzerPort):
    def analyze_patch_attributes(self, patch_attributes: PatchAttributes, patch_descriptor: PatchDescriptor) \
            -> Tuple[str, int, int] | None:
        max_hunk_score = (0, None)

        for diff_patch_descriptor in patch_descriptor.diff_descriptor:
            for hunk in diff_patch_descriptor:
                hunk_score = CHANGE_TYPE_SCORE[hunk.change_type] * CONTENT_TYPE_SCORE[hunk.content_type]

                if hunk_score > max_hunk_score[0]:
                    max_hunk_score = (hunk_score, f"{diff_patch_descriptor.new_file} | {hunk.order}")

        if max_hunk_score[1]:
            file, hunk_order = max_hunk_score[1].split(" | ")

            for diff_patch in patch_attributes.diff:
                if diff_patch.new_file == file:
                    for diff_hunk in diff_patch:
                        if diff_hunk.order == int(hunk_order):
                            # TODO: make this to be more precise
                            if len(diff_hunk.old_lines) > 0 and len(diff_hunk.new_lines) == 0:
                                # TODO: find out how to handle deletion hunks
                                return None

                            # Returns the file and the start/end lines of the hunk that address the bug
                            return file, diff_hunk.new_lines[0].lineno, diff_hunk.new_lines[-1].lineno

        return None
