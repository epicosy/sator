from typing import Tuple
from sator.core.models.oss.diff import Diff
from sator.core.models.enums import DiffChangeType, DiffContentType
from sator.core.models.oss.annotation import DiffAnnotation


from sator.core.ports.driven.analyzers.diff import DiffAnalyzerPort

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


class ScoreBasedDiffAnalyzer(DiffAnalyzerPort):
    def analyze_diff(self, diff: Diff, annotation: DiffAnnotation) -> Tuple[str, int] | None:
        max_hunk_score = (0, None)

        for patch in annotation:
            for hunk in patch:
                hunk_score = CHANGE_TYPE_SCORE[hunk.change_type] * CONTENT_TYPE_SCORE[hunk.content_type]

                if hunk_score > max_hunk_score[0]:
                    max_hunk_score = (hunk_score, f"{patch.new_file} | {hunk.order}")

        if max_hunk_score[1]:
            file, hunk_order = max_hunk_score[1].split(" | ")

            for patch in diff:
                if patch.new_file == file:
                    for hunk in patch:
                        if hunk.order == int(hunk_order):
                            # TODO: make this to be more precise
                            if len(hunk.old_lines) > 0:
                                # Return the first old_line of the hunk
                                return file, hunk.old_lines[0].lineno
                            elif len(hunk.new_lines) > 0:
                                # Return the first new_line of the hunk
                                return file, hunk.new_lines[0].lineno

        return None
