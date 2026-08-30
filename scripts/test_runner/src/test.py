import io
import selectors
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Set

import click
import psutil
from device import Device
from logger import LOGGER, colored
from sympy.logic.boolalg import BooleanFunction

SUDO = shutil.which("sudo")
if SUDO is None:
    raise RuntimeError("sudo not found!")

DMESG = shutil.which("dmesg")
if DMESG is None:
    raise RuntimeError("dmesg not found!")


class TestStatus(Enum):
    SKIPPED = 0
    PASSED = 1
    FAILED = 2


@dataclass()
class TestResult:
    test: Any
    status: TestStatus = TestStatus.SKIPPED
    stdout: str = ""
    stderr: str = ""
    dmesg: str = ""
    skip_reason: str = ""
    time: float = 0


@dataclass(frozen=True)
class TestGroup:
    name: str
    tests: list["Test"]

    @property
    def test_list(self) -> List["Test"]:
        return self.tests


@dataclass(frozen=False)
class Test(ABC):
    supported_devices: Set[Device] = field(default_factory=lambda: set(Device))
    required_features: BooleanFunction = field(default_factory=BooleanFunction)

    @abstractmethod
    def run(self, group) -> TestResult:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def _run(self, command: List[str]) -> TestResult:
        c = click.get_current_context()
        capture = c.params["capture"]

        test_result = TestResult(self)

        sudo_dmesg = subprocess.Popen(
            [SUDO, DMESG, "-dWT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        start_time = time.time()

        LOGGER.debug(f"Test command: {' '.join(command)}")
        test_process = subprocess.Popen(
            command,
            bufsize=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        def handle_stdout(stream, _):
            line: str = stream.readline()
            stdout_buf.write(line)
            if not capture:
                line = line.strip()

                if len(line) > 0:
                    LOGGER.info(f"{colored('stdout', 'white')}: {line}")

        def handle_stderr(stream, _):
            line: str = stream.readline()
            stderr_buf.write(line)
            if not capture:
                line = line.strip()

                if len(line) > 0:
                    LOGGER.info(f"{colored('stderr', 'light_red')}: {line}")

        selector = selectors.DefaultSelector()
        selector.register(test_process.stdout, selectors.EVENT_READ, handle_stdout)
        selector.register(test_process.stderr, selectors.EVENT_READ, handle_stderr)

        while test_process.poll() is None:
            events = selector.select()
            for k, m in events:
                callback = k.data
                callback(k.fileobj, m)

        return_code = test_process.wait()

        events = selector.select()
        for k, m in events:
            callback = k.data
            callback(k.fileobj, m)
        selector.close()

        test_result.time = time.time() - start_time

        test_result.stdout = stdout_buf.getvalue()
        test_result.stderr = stderr_buf.getvalue()

        stdout_buf.close()
        stderr_buf.close()

        # Since we run dmesg via sudo, `dmesg.pid` will give us the pid of sudo, not the dmesg
        # process it runs.
        # Killing the sudo process seems to hang.
        # So instead, we'll kill all it's children (should only be 1 child - dmesg itself) which
        # will also make sudo terminate.
        sudo_dmesg_ps = psutil.Process(sudo_dmesg.pid)
        for child in sudo_dmesg_ps.children():
            subprocess.run([f"{SUDO} kill {child.pid}"], shell=True)

        sudo_dmesg.wait()

        if sudo_dmesg.stdout is not None:
            dmesg_stdout = sudo_dmesg.stdout.read().decode()
        else:
            LOGGER.error("Failed to get dmesg!")
            dmesg_stdout = ""

        test_result.dmesg = dmesg_stdout
        test_result.status = (
            TestStatus.PASSED if return_code == 0 else TestStatus.FAILED
        )

        return test_result
