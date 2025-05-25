from secomlint.message import Message
from secomlint.section import Body, Header

from sator_core.models.oss.diff import Diff
from sator_core.models.patch.attributes import PatchAttributes
from sator_core.ports.driven.extraction.attributes.patch import PatchAttributesExtractorPort


class RegexPatchAttributesExtractor(PatchAttributesExtractorPort):
    def __init__(self):
        self.message = None
        self.patch_attributes = None

    def extract_patch_attributes(self, vulnerability_id, diff: Diff) -> PatchAttributes | None:
        commit_msg = [line.lower() for line in diff.message.split('\n')]

        if not commit_msg:
            return None

        self.message = Message(commit_msg)
        self.message.get_sections()
        self.patch_attributes = PatchAttributes(diff=diff, vulnerability_id=vulnerability_id)

        self._process_section(Header)
        self._process_section(Body)

        return self.patch_attributes

    def _process_section(self, section_type):
        section = next((s for s in self.message.sections if isinstance(s, section_type)), None)

        if section:
            for entity in section.entities:
                self.add_entities_to_patch_attributes(list(entity))

    def add_entities_to_patch_attributes(self, entity_list):
        if entity_list[1] == 'SECWORD':
            self.patch_attributes.sec_words.append(entity_list[0])
        elif entity_list[1] == 'ACTION':
            self.patch_attributes.action = entity_list[0]
        elif entity_list[1] == 'FLAW':
            self.patch_attributes.flaw = entity_list[0]
        elif entity_list[1] == 'VERSION':
            self.patch_attributes.version = entity_list[0]
