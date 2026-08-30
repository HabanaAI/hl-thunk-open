#!/usr/bin/env python3

import itertools
import os
import pathlib
import re
import sys
import xml.etree.ElementTree as ET
from typing import List, Optional, Set, TextIO, Tuple

import click
import sympy
from device import Device
from feature import EXCLUSIVE_FEATURES, Feature
from logger import LOGGER, colored
from src.nic_root_test import dump_config
from src.test import Test, TestGroup, TestResult, TestStatus
from tests.default import DEVICE_DEFAULT_FEATURES
from tests.test_list import TEST_LIST

# ============================================= CLI ============================================== #

try:
    TERMINAL_SIZE = os.get_terminal_size().columns
except:
    TERMINAL_SIZE = 100

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
def main():
    pass


@main.command()
@click.option(
    "-d",
    "--device",
    required=True,
    type=click.Choice(Device._member_names_, case_sensitive=False),
    help="The current device that we want to run the tests on",
)
@click.option(
    "-f",
    "--feature",
    "features",
    type=click.Choice(Feature._member_names_, case_sensitive=False),
    multiple=True,
    help="Feature that's available, tests won't run until all their requirements are satisfied, can be used multiple times",
)
@click.option(
    "-g",
    "--group",
    help="Run tests only from a specific group",
    type=click.Choice([group.name for group in TEST_LIST], case_sensitive=False),
)
@click.option("-r", "--regex", help="Run tests whose name matches provided regex")
@click.option(
    "--bin-path",
    show_default=True,
    help=f"Path to hl-thunk build output binaries directory (default: {os.environ.get('HLTHUNK_RELEASE_BIN')})",
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, path_type=pathlib.Path
    ),
    envvar="HLTHUNK_RELEASE_BIN",
)
@click.option(
    "--junit",
    help="Export results to a JUnit compatible XML",
    type=click.Path(file_okay=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--summary/--no-summary",
    help="Print summary after running all the tests",
    default=True,
    show_default=True,
)
@click.option(
    "--capture/--no-capture",
    help="Capture the tests' stdout",
    default=False,
    show_default=True,
)
@click.option(
    "--id",
    help="Run only the test with the requested ID, ignoring all requirements (best combined with the test group)",
    type=click.INT,
)
@click.option(
    "--color",
    help="Colorize output",
    type=click.Choice(["none", "auto", "always"]),
    default="auto",
)
@click.option(
    "-p", "--pci-addr",
    help="Device PCI address (affects nic_root based tests)",
    type=click.STRING
)
def run(
    device: str,
    features: List[str],
    group: Optional[str],
    regex: Optional[str],
    junit: Optional[pathlib.Path],
    summary: bool,
    **kwargs,
):
    """Runs the tests"""
    device = Device(device)
    features = Feature.normalize_features(features)

    results, failed = run_tests(device, features, group, regex)

    if junit is not None:
        dump_junit(junit, results)

    if summary:
        print_summary(results)

    if failed:
        sys.exit(1)

    sys.exit(0)


@main.command(name="list")
@click.option(
    "-d",
    "--device",
    type=click.Choice(Device._member_names_, case_sensitive=False),
    help="List tests that support specific device",
)
@click.option(
    "-f",
    "--feature",
    "features",
    type=click.Choice(Feature._member_names_, case_sensitive=False),
    multiple=True,
    help="List tests that require a feature, can be used multiple times",
)
@click.option(
    "-g",
    "--group",
    help="List tests from a specific test group",
    type=click.Choice([group.name for group in TEST_LIST], case_sensitive=False),
)
@click.option("-r", "--regex", help="List tests whose name matches provided regex")
@click.option(
    "-a", "--all", help="List all tests, regardless of the options", is_flag=True
)
@click.option(
    "--dump",
    help="Dump the test configuration to file, will only dump if filter matches only one test",
    type=click.File(mode="w"),
)
@click.option(
    "--id",
    help="List only the test with the requested ID (best combined with the test group)",
    type=click.INT,
)
def list_tests(
    device: Optional[str],
    features: List[str],
    group: Optional[str],
    regex: Optional[str],
    all: bool,
    dump: TextIO,
    **kwargs,
):
    """Lists the tests

    This command prints out a table containing all the tests that match the provided options.

    If no tests match, an empty table will be shown.
    To print all available tests, use the `-a` option.

    To inspect a specific test's configuration, you can use the various filter
    parameters to narrow down the selection to a single test, then use the `--dump` option to dump
    the configuration to a text file.
    """
    features = Feature.normalize_features(features)

    if device is not None:
        device = Device(device)
        [features.add(f) for f in DEVICE_DEFAULT_FEATURES[device]]

    from prettytable.colortable import ColorTable, Themes

    table = ColorTable(theme=Themes.OCEAN, max_table_width=TERMINAL_SIZE)

    table.field_names = [
        "Group",
        "ID",
        "Test",
        "Supported devices",
        "Required Features",
    ]
    table.align = "l"

    matching_tests = []

    for test_group in TEST_LIST:
        if group is not None and group.casefold() != test_group.name.casefold():
            continue

        # Hack to add dividers to the table between groups, as we need to know the group's end
        # ahead of time if we want to do this the right way.
        if len(table._dividers) > 0:
            table._dividers[-1] = True

        for idx, test in enumerate(test_group.test_list):
            if not all:
                skip, _ = should_skip_test(
                    test_group, test, idx, device, features, group, regex
                )

                if skip:
                    continue

            matching_tests.append((test_group, test))

            table.add_row(
                [
                    test_group.name,
                    idx,
                    test.name,
                    ", ".join([d.name for d in test.supported_devices]),
                    sympy.to_dnf(test.required_features, simplify=True, force=True),
                ],
            )

    print(table)

    if dump is not None:
        if device is None:
            print("Can't dump config without device!")
        elif len(matching_tests) == 0:
            print("Can't dump config, no matches.")
        elif len(matching_tests) > 1:
            print("Can't dump config, too many matches.")
        else:
            dump_config(dump, matching_tests[0][0], matching_tests[0][1])

    return 0


# ======================================== Business Logic ======================================== #

from sympy.logic.inference import satisfiable


def should_skip_test(
    test_group: TestGroup,
    test: Test,
    idx: int,
    device: Optional[Device],
    features: Set[Feature],
    group: Optional[str],
    regex: Optional[str],
) -> Tuple[bool, Optional[str]]:
    """Checks if the test should be skipped, and returns a reason if so."""
    c = click.get_current_context()
    id = c.params["id"]

    if group is not None and test_group.name.casefold() != group.casefold():
        return True, f"'{group}' does not match test group: '{test_group.name}'"

    if id is not None:
        if id == idx:
            # If ID matches, we always run the test, regardless of provided features or device support.
            return False, None
        else:
            return True, f"'{id}' does not match test ID: '{idx}'"

    if regex is not None and re.search(regex, test.name) is None:
        return True, f"'{regex}' does not match test name: '{test.name}'"

    if device is not None and device not in test.supported_devices:
        return (
            True,
            f"'{device.name}' not in supported device list: {[d.name for d in test.supported_devices]}",
        )

    if not Feature.requirements_satisfied(features, test.required_features):
        return (
            True,
            f"Missing features: not all requirements were satisfied: {test.required_features}",
        )

    if not satisfiable(test.required_features & EXCLUSIVE_FEATURES):
        return (
            True,
            f"Test has conflicting requirements!",
        )

    return False, None


def run_tests(
    device: Device,
    features: Set[Feature],
    group: Optional[str],
    regex: Optional[str],
) -> Tuple[dict[str, dict[str, TestResult]], bool]:
    """Runs the tests"""

    all_test_results = {}

    [features.add(f) for f in DEVICE_DEFAULT_FEATURES[device]]

    tests_to_run: List[Tuple[TestGroup, Test]] = []

    for test_group in TEST_LIST:
        group_results = all_test_results[test_group.name] = {}

        for idx, test in enumerate(test_group.test_list):
            skip, reason = should_skip_test(
                test_group, test, idx, device, features, group, regex
            )
            if skip:
                LOGGER.debug(
                    f"SKIPPED [{test_group.name}] {test.name}, reason: {reason}"
                )
                group_results[test.name] = TestResult(test, skip_reason=reason)
                continue

            tests_to_run.append((test_group, test))

    failed = False
    LOGGER.set_progress_total(len(tests_to_run))

    for idx, (test_group, test) in enumerate(tests_to_run):
        group_results = all_test_results[test_group.name]

        LOGGER.set_progress_current(idx + 1)

        LOGGER.info(f"{colored('RUNNING','blue')} [{test_group.name}] {test.name}")

        group_results[test.name] = result = test.run(test_group)

        if result.status == TestStatus.FAILED:
            LOGGER.info(f"{colored('FAILED','red')}  [{test_group.name}] {test.name}")
            failed = True
        else:
            LOGGER.info(f"{colored('PASSED','green')}  [{test_group.name}] {test.name}")

    LOGGER.clear_progress()

    return all_test_results, failed


def xml_escape(str_xml: str):
    # Remove illegal characters using regex
    illegal_xml_chars = r"[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]"
    return re.sub(illegal_xml_chars, "", str_xml)


def dump_junit(junit: pathlib.Path, results: dict[str, dict[str, TestResult]]):
    testsuites = ET.Element("testsuites")

    total_tests = 0
    total_failed = 0
    total_time = 0

    package = f"hl_thunk ({', '.join(sorted(click.get_current_context().params['features']))})"

    for group_name, group_results in results.items():
        testsuite = ET.SubElement(testsuites, "testsuite")
        class_name = f"{package}.{group_name}"

        group_tests = 0
        group_failed = 0
        group_skipped = 0
        group_time = 0

        for test_name, test_result in group_results.items():
            # Don't generate result for skipped tests as it spams jenkins.
            if test_result.status is TestStatus.SKIPPED:
                continue

            testcase = ET.SubElement(testsuite, "testcase")

            testcase.set("name", test_name)
            testcase.set("classname", class_name)
            testcase.set("time", f"{test_result.time:.3f}")
            ET.SubElement(testcase, "system-out").text = xml_escape(test_result.stdout)
            ET.SubElement(testcase, "system-err").text = xml_escape(test_result.stderr)

            group_tests += 1
            group_time += test_result.time

            if test_result.status is TestStatus.FAILED:
                failure = ET.SubElement(testcase, "failure")
                failure.text = xml_escape(f"dmesg:\n{test_result.dmesg}")
                group_failed += 1

        testsuite.set("name", group_name)
        testsuite.set("package", class_name)
        testsuite.set("time", f"{group_time:.3f}")

        testsuite.set("tests", str(group_tests))
        testsuite.set("skipped", str(group_skipped))
        testsuite.set("failures", str(group_failed))

        total_tests += group_tests
        total_failed += group_failed
        total_time += group_time

    testsuites.set("name", "THUNK")
    testsuites.set("tests", str(total_tests))
    testsuites.set("failures", str(total_failed))
    testsuites.set("time", f"{total_time:.3f}")

    et = ET.ElementTree(testsuites)
    et.write(junit, xml_declaration=True)


def print_summary(results: dict[str, dict[str, TestResult]]):
    results_list = list(
        itertools.chain.from_iterable(
            [
                [(f"[{gn}] {tn}", t) for (tn, t) in g.items()]
                for (gn, g) in results.items()
            ]
        )
    )

    passed = list(filter(lambda t: t[1].status is TestStatus.PASSED, results_list))
    skipped = list(filter(lambda t: t[1].status is TestStatus.SKIPPED, results_list))
    failed = list(filter(lambda t: t[1].status is TestStatus.FAILED, results_list))

    passed_num = len(passed)
    skipped_num = len(skipped)
    failed_num = len(failed)
    total_tests_num = len(results_list)

    print("Summary:")

    if failed_num > 0:
        print("=" * TERMINAL_SIZE)
        [print(f"FAILED - {name}") for (name, _) in failed]
        print("=" * TERMINAL_SIZE)

    print(f"Passed:        {passed_num}")
    print(f"Skipped:       {skipped_num}")
    print(f"Failed:        {failed_num}")

    print(f"Total tests:   {total_tests_num}")


if __name__ == "__main__":
    main()
