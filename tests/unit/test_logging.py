import json
import logging

from chinescan.core.logging.structured import JsonFormatter, configure_logging


def test_json_formatter_redacts_message() -> None:
    record = logging.LogRecord("test", logging.INFO, "", 1, "token=%s", ("abc",), None)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "token=[REDACTED]"
    assert payload["level"] == "INFO"


def test_logger_configuration_sets_level() -> None:
    logger = configure_logging("DEBUG")
    assert logger.level == logging.DEBUG
