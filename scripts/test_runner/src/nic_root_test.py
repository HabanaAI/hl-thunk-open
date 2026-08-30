import collections
import copy
import itertools
import os
import tempfile
from dataclasses import dataclass, field
from typing import Generator, List, Optional, TextIO

import click
from device import Device
from feature import EXCLUSIVE_FEATURES
from parameterizations import TestParametrization
from src.test import Test, TestGroup, TestResult
from sympy.logic.inference import satisfiable
from tests.default import DEFAULT_CONFIG, DEVICE_DEFAULT_CONFIG

from src import test


@dataclass(frozen=True)
class NicRootTestGroup(TestGroup):
    group_parameter: str = ""
    config_overrides: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def test_list(self) -> List["NicRootTest"]:
        if not hasattr(self, "_parameterized_tests"):
            # Use the setattr to bypass frozen dataclass limitations
            object.__setattr__(
                self, "_parameterized_tests", list(self._generate_parameterized_tests())
            )

        return self._parameterized_tests

    def _generate_parameterized_tests(self) -> Generator["NicRootTest", None, None]:
        for test in self.tests:
            if not isinstance(test, NicRootTest):
                raise TypeError(f"Expected NicRootTest, got: {type(test)}")

            if len(test.parameterization) == 0:
                yield test
                continue

            params = [
                [(p.group, p.param, v) for v in p.values] for p in test.parameterization
            ]
            permutations = list(itertools.product(*params))

            for permutation in permutations:
                parameterized_test = copy.deepcopy(test)
                for p in permutation:
                    group = p[0]
                    param = p[1]
                    value = p[2]
                    # If value is a tuple - it contains the parameter value and list required features.
                    if type(value) is tuple:
                        override_configs(
                            parameterized_test.config_overrides,
                            {group: {param: value[0]}},
                        )
                        parameterized_test.required_features &= value[1]
                    else:
                        override_configs(
                            parameterized_test.config_overrides, {group: {param: value}}
                        )

                # Don't yield impossible combinations
                if not satisfiable(
                    parameterized_test.required_features & EXCLUSIVE_FEATURES
                ):
                    continue

                yield parameterized_test


@dataclass(frozen=False)
class NicRootTest(Test):
    config_overrides: dict[str, dict[str, str]] = field(default_factory=dict)
    parameterization: List[TestParametrization] = field(default_factory=list)
    name_prefix: Optional[str] = None

    @property
    def name(self) -> str:
        if self.name_prefix is not None:
            prefix = self.name_prefix + " ("
            suffix = ")"
        else:
            prefix = ""
            suffix = ""

        name = [
            f"{k}: {v}" for g in self.config_overrides.values() for k, v in g.items()
        ]

        if len(name) == 0:
            return "basic"

        return prefix + ", ".join(name) + suffix

    def run(self, group: TestGroup) -> TestResult:
        if not isinstance(group, NicRootTestGroup):
            raise TypeError(f"group expected NicRootTestGroup, got: {type(group)}")

        c = click.get_current_context()

        bin_path: os.PathLike = c.params["bin_path"]
        path_to_binary = os.path.join(bin_path, "nic_root")
        pci_addr = c.params.get("pci_addr", None)

        with tempfile.NamedTemporaryFile(mode="w") as conf:
            dump_config(conf, group, self)

            command = [
                test.SUDO,
                f"LD_LIBRARY_PATH={os.environ['LD_LIBRARY_PATH']}",
                "HABANA_SHIM_DISABLE=1",
                f"UBSAN_OPTIONS={os.environ.get('UBSAN_OPTIONS','')}",
                path_to_binary,
                "-s",
                group.group_parameter,
                "-c",
                conf.name,
            ]

            if pci_addr is not None:
                command.extend(["-p", pci_addr])

            return self._run(command)


def override_configs(d, u):
    """Recursively updates only the leaves of the dictionary"""
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = override_configs(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def dump_config(file: TextIO, group: NicRootTestGroup, test: NicRootTest):
    """Dumps the test's configuration to a file."""
    context = click.get_current_context()
    device = Device(context.params["device"])
    # First override by device default configs
    config = override_configs(
        copy.deepcopy(DEFAULT_CONFIG), DEVICE_DEFAULT_CONFIG[device]
    )
    # Then override by group specific configs
    config = override_configs(config, group.config_overrides)
    # Then override by test specific configs
    config = override_configs(config, test.config_overrides)

    for section, parameters in config.items():
        file.write(f"[{section}]\n")
        for k, v in parameters.items():
            file.write(f"{k}={v}\n")
        file.write("\n")

    file.flush()
