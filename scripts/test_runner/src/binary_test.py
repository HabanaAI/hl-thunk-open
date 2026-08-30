import os
from dataclasses import dataclass, field
from typing import List

from src.test import SUDO, Test, TestGroup


@dataclass(frozen=True)
class BinaryTestGroup(TestGroup):
    binary_path: os.PathLike = ""
    sudo: bool = False


@dataclass(frozen=False)
class BinaryTest(Test):
    test_name: str = ""
    arguments: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.test_name

    def run(self, group) -> List[str]:
        if not isinstance(group, BinaryTestGroup):
            raise TypeError(f"group expected BinaryTestGroup, got: {type(group)}")

        command = []

        if group.sudo:
            command = [SUDO, "-E", f"LD_LIBRARY_PATH={os.environ['LD_LIBRARY_PATH']}"]

        command.append(group.binary_path)
        command.extend(self.arguments)

        return self._run(command)
