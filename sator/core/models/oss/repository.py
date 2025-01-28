from dataclasses import dataclass, field


@dataclass
class Repository:
    id: int
    name: str
    owner: str
    platform: str
    aliases: list = field(default_factory=list)
