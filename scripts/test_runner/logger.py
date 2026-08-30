import logging

import click
import termcolor

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
)


class TestLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra)
        self.count = None
        self.progress = 0

    def process(self, msg, kwargs):
        if self.count is not None:
            return (
                f"[{self.progress:{self.counter_width}}/{self.count}] {msg}",
                kwargs,
            )

        return f"{msg}", kwargs

    def set_progress_total(self, count):
        self.count = count
        self.counter_width = len(str(count))

    def set_progress_current(self, count):
        self.progress = count

    def clear_progress(self):
        self.count = None
        self.progress = 0


LOGGER = TestLoggerAdapter(logging.getLogger())


def colored(
    text: str,
    color: str | None = None,
    *args,
    **kwargs,
) -> str:
    c = click.get_current_context()

    use_color: str = c.params["color"]

    if use_color == "none":
        return text
    elif use_color == "always":
        return termcolor.colored(text, color, *args, force_color=True, **kwargs)
    else:
        return termcolor.colored(text, color, *args, **kwargs)
