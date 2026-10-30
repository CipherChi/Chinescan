"""JSON-line formatter and logger configuration."""

import json
import logging
import uuid
from datetime import UTC, datetime

from chinescan.core.logging.redaction import REDACTED, redact

_REDACTION_INSTALLED = False
_STANDARD_RECORD_FIELDS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:
            message = REDACTED
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(message),
        }
        for field in ("request_id", "route", "status", "duration_ms"):
            if hasattr(record, field):
                payload[field] = redact(getattr(record, field))
        if record.exc_text:
            payload["exception"] = redact(record.exc_text)
        if record.stack_info:
            payload["stack_info"] = redact(record.stack_info)
        for field, value in record.__dict__.items():
            if field not in _STANDARD_RECORD_FIELDS and field not in payload:
                payload[field] = redact(value)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> logging.Logger:
    global _REDACTION_INSTALLED
    logger = logging.getLogger("chinescan")
    logger.setLevel(level.upper())
    factory = logging.getLogRecordFactory()
    if not _REDACTION_INSTALLED:

        def redacting_factory(*args: object, **kwargs: object) -> logging.LogRecord:
            record = factory(*args, **kwargs)
            try:
                record.msg = redact(record.getMessage())
                record.args = ()
                if record.exc_info:
                    record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
                    record.exc_info = None
                if record.stack_info:
                    record.stack_info = redact(record.stack_info)
                for key, value in tuple(record.__dict__.items()):
                    if key not in _STANDARD_RECORD_FIELDS:
                        record.__dict__[key] = redact(value)
            except Exception:
                record.msg = REDACTED
                record.args = ()
                record.exc_info = None
                record.exc_text = None
                record.stack_info = None
            return record

        logging.setLogRecordFactory(redacting_factory)
        _REDACTION_INSTALLED = True
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger


def new_request_id() -> str:
    """Return a server-generated request identifier."""
    return str(uuid.uuid4())
