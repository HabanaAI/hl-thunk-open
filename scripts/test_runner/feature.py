import enum
from typing import Iterable, Set

import click
import sympy
from functools import reduce
from sympy.logic.boolalg import BooleanFunction, Exclusive


class DirectValueMeta(enum.EnumMeta):
    "Metaclass that allows for directly getting an enum attribute"

    def __getattribute__(cls, name):
        value = super().__getattribute__(name)
        if isinstance(value, cls):
            value = value.value
        return value


@enum.unique
class Feature(enum.Enum, metaclass=DirectValueMeta):
    SIM = sympy.symbols("SIM")
    ASIC = sympy.symbols("ASIC")
    PLDM = sympy.symbols("PLDM")
    DRAM = sympy.symbols("DRAM")
    WQ_DRAM = sympy.symbols("WQ_DRAM")
    DEVICE_CQ = sympy.symbols("DEVICE_CQ")
    SACK = sympy.symbols("SACK")
    MAC_LOOPBACK = sympy.symbols("MAC_LOOPBACK")
    ETH_LOOPBACK = sympy.symbols("ETH_LOOPBACK")
    NO_MAC_LOOPBACK = sympy.symbols("NO_MAC_LOOPBACK")
    NO_ETH_LOOPBACK = sympy.symbols("NO_ETH_LOOPBACK")
    NIC_200G = sympy.symbols("NIC_200G")
    NIC_400G = sympy.symbols("NIC_400G")
    # This one is useful if we have tests with no requirements, but run the test runner multiple
    # times in CI
    # to prevent such tests from running every time - we can add this "run_once" requirement, and
    # provide it only in one of the runner invocations.
    RUN_ONCE = sympy.symbols("RUN_ONCE")

    @staticmethod
    def normalize_features(features: Iterable[str]) -> Set[sympy.Symbol]:
        """Makes sure that no conflicting features are present, and adds default features if
        necessary."""
        features: Set[sympy.Symbol] = {Feature[f].value for f in features}

        for exclusive in EXCLUSIVE_FEATURES_LIST:
            if not Feature.requirements_satisfied(features, exclusive):
                raise click.UsageError(
                    f"Got conflict in exclusive features: {exclusive}"
                )

        # If some features are not provided, insert their complementary default.
        default_features = {
            # Since most tests need mac loopback, add it by default unless explicitly told not to.
            Feature.NO_MAC_LOOPBACK: Feature.MAC_LOOPBACK,
        }

        for k, v in default_features.items():
            if k not in features:
                features.add(v)

        return features

    @staticmethod
    def requirements_satisfied(
        features: Set[sympy.Symbol], requirements: BooleanFunction
    ):
        """Checks that all requirements are satisfied by the features set."""
        values = {f.value: f.value in features for f in Feature}

        return requirements.subs(values)


EXCLUSIVE_FEATURES_LIST = [
    Exclusive(Feature.SIM, Feature.ASIC, Feature.PLDM),
    Exclusive(Feature.MAC_LOOPBACK, Feature.NO_MAC_LOOPBACK),
    Exclusive(Feature.ETH_LOOPBACK, Feature.NO_ETH_LOOPBACK),
    Exclusive(Feature.NIC_200G, Feature.NIC_400G),
]

EXCLUSIVE_FEATURES = reduce(lambda x, y: x & y, EXCLUSIVE_FEATURES_LIST)
