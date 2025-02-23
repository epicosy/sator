
from sator.core.models.enums import PatchActionType
from sator.core.ports.driven.classifiers.patch_action import PatchActionClassifierPort

PATCH_ACTION_KEYWORD_MAPPING = {
    PatchActionType.CORRECTIVE: ("fix", "patch", "mitigate", "protect"),
    PatchActionType.ADAPTIVE: ("update", "change"),
    PatchActionType.ENHANCEMENT: ("add", "remove")
}


class KeywordPatchActionClassifier(PatchActionClassifierPort):
    def classify_patch_action(self, action: str) -> PatchActionType | None:
        """
            Classify the action of a patch based on its details.
        """

        patch_action = {"type": None, "count": 0}
        patch_action_keywords = action.lower().split(" ")

        for patch_action_type, keywords in PATCH_ACTION_KEYWORD_MAPPING.items():
            keywords_count = len(set(patch_action_keywords) & set(keywords))

            if keywords_count > patch_action["count"]:
                patch_action["type"] = patch_action_type
                patch_action["count"] = keywords_count

        return patch_action["type"]
