from dataclasses import dataclass


@dataclass
class Change:
    content: str
    number: int
    type: str

    @property
    def start_col(self):
        # TODO: This is a temporary solution. Need to find a better way to calculate the start column
        line_with_spaces = self.content.expandtabs(4)
        return (len(line_with_spaces) - len(line_with_spaces.lstrip())) + 1

    @property
    def end_col(self):
        return len(self.content) - 1


@dataclass
class Addition(Change):
    type: str = 'addition'


@dataclass
class Deletion(Change):
    type: str = 'deletion'


@dataclass
class DiffBlock:
    start: int
    a_path: str
    b_path: str

    def to_dict(self):
        return {"start": self.start, "a_path": self.a_path, "b_path": self.b_path}
