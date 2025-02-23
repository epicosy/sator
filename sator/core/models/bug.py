from pydantic import BaseModel


class BugLocator(BaseModel):
    commit: str
    file: str
    line: int
