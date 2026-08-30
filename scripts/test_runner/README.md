# 1. Hl-Thunk Test Runner

- [1. Hl-Thunk Test Runner](#1-hl-thunk-test-runner)
- [2. Overview](#2-overview)
- [3. Features](#3-features)
- [4. Usage](#4-usage)
  - [4.1 Prerequisites](#41-prerequisites)
  - [4.2 Using the test runner](#42-using-the-test-runner)
- [5. Development Guide](#5-development-guide)
  - [5.1. Test Structure](#51-test-structure)
  - [5.2. Key Classes](#52-key-classes)
- [6. Test Configuration](#6-test-configuration)
  - [6.1. NicRootTest](#61-nicroottest)
    - [6.1.1. Configuration Generation](#611-configuration-generation)
    - [6.1.2. Debugging Configurations](#612-debugging-configurations)
  - [6.2. BinaryTest](#62-binarytest)
- [7. Adding Tests](#7-adding-tests)
- [8. Glossary](#8-glossary)

# 2. Overview

The Hl-Thunk Test Runner is a framework for running and managing tests. It provides a CLI for running, listing, and debugging tests, and supports test grouping, parameterization, and configuration overrides.

---

# 3. Features

- **NIC Test Support:** Currently, only NIC tests are supported.
- **CLI Interface:** Easily run and manage tests from the command line.
- **Test Grouping:** Organize tests into logical groups.
- **Parameterization:** Generate multiple test permutations with different configurations.
- **Configuration Overrides:** Layered configuration system for flexible test setups.

---

# 4. Usage

## 4.1 Prerequisites

Setting up a Python virtual environment is not strictly required but highly recommended to avoid dependency conflicts:

1. Create a virtual environment in the `.venv` directory:
   ```bash
   python -m venv .venv
   ```

2. Activate the virtual environment:

   For bash/zsh:
   ```bash
   source .venv/bin/activate
   ```

   For fish:
   ```fish
   source .venv/bin/activate.fish
   ```

3. Install the required dependencies:
   ```bash
   pip install -r scripts/requirements.txt
   ```

## 4.2 Using the test runner

The test runner provides a CLI with built-in help. To get started, run:

```bash
./scripts/test_runner/cli.py --help
./scripts/test_runner/cli.py <command> --help
```

---

# 5. Development Guide

## 5.1. Test Structure

- **TestGroup:** A base class for a collection of related tests.
- **Test:** The base class for all tests.

## 5.2. Key Classes

| Class | Description |
| ----- | ----------- |
| `Test` | Abstract base class for all tests. Handles running a process, capturing stdout, stderr, and dmesg. |
| `NicRootTest` | Inherits from `Test`.<br>Adds logic for running `nic_root`-based tests, including dynamic config file generation. |
| `BinaryTest` | Inherits from `Test`.<br>Runs an executable with specified arguments. |
| `Device` | Enum of supported devices. |
| `Feature` | Enum of supported features. |
| `DirectValueMeta` | Metaclass allowing `Feature.FEAT` to return its value directly. |
| `TestParametrization` | Enables generating multiple test permutations via parameterization. |
| `TestGroup` | Groups tests with shared properties. |
| `NicRootTestGroup` | Groups `NicRootTest` tests by type (e.g., basic, collective). |
| `BinaryTestGroup` | Groups `BinaryTest` tests by executable. |
| `TestStatus` | Represents a test's execution status. |
| `TestResult` | Represents a test's execution result. |

---

# 6. Test Configuration

Each `Test` can be configured with:

| Parameter | Description |
| --------- | ----------- |
| `supported_devices` | Set of devices this test can run on (e.g., `{Device.GAUDI3}`). |
| `required_features` | Set of features required for the test.<br>If conflicting features are required (e.g., `Feature.ASIC & Feature.SIM`), the test will never run.<br>To run on both, use an "OR" requirement: `Feature.ASIC \| Feature.SIM`. |

---

## 6.1. NicRootTest

Extends `Test` with additional parameters:

| Parameter | Description |
| --------- | ----------- |
| `config_overrides` | Dict of config values to override defaults. |
| `parameterization` | List of parameterizations to generate test permutations. |
| `name_prefix` | Prefix for test names (useful when parameterized). |

### 6.1.1. Configuration Generation

When running `nic_root` tests, the runner generates a config file as follows:

1. Duplicate the test for all parameterization permutations.
2. For each permutation:
   - Start with the default config: `DEFAULT_CONFIG`.
   - Override with device-specific defaults: `DEVICE_DEFAULT_CONFIG[device]`.
   - Override with group config: `NicRootTestGroup.config_overrides`.
   - Override with test config: `NicRootTest.config_overrides`.
   - Override with current permutation's parameterization.

**Order of precedence:**
`NicRootTest.parameterization` > `NicRootTest.config_overrides` > `NicRootTestGroup.config_overrides` > `DEVICE_DEFAULT_CONFIG[device]` > `DEFAULT_CONFIG`

### 6.1.2. Debugging Configurations

To dump a test configuration:

```bash
./scripts/test_runner/cli.py list --dump dump.txt -d gaudi3 -r "data_loc: host, cq_type: port"
```
This dumps the selected test's configuration to `dump.txt`.
_Note: The `list` command only displays information; it does not run tests._

---

## 6.2. BinaryTest

Extends `Test` with:

| Parameter | Description |
| --------- | ----------- |
| `test_name` | Name of the test. |
| `arguments` | List of arguments for the executable. |

Runs the binary with the specified arguments.

---

# 7. Adding Tests

To add a new test, append it to the relevant test list. For example:
Add to `tests/basic.py` in the `TESTS_BASIC` list for basic tests.

---

# 8. Glossary

- **Test:** The base unit of execution.
- **TestGroup:** A collection of related tests.
- **Parameterization:** Creating multiple test variants with different configs.
- **Config Override:** Replacing default config values at various levels.
- **Device/Feature:** Enum values specifying hardware and capabilities.

---
