import logging
import time
from logging import Handler, LogRecord
from logging.handlers import MemoryHandler
from threading import Thread
from typing import Optional, cast

from twisted.internet.interfaces import IReactorCore

from synapse.util.check_dependencies import check_requirements


class PeriodicallyFlushingMemoryHandler(MemoryHandler):
    """
    This is a subclass of MemoryHandler that additionally spawns a background
    thread to periodically flush the buffer.

    This prevents messages from being buffered for too long.

    Additionally, all messages will be immediately flushed if the reactor has
    not yet been started.
    """

    def __init__(
        self,
        capacity: int,
        flushLevel: int = logging.ERROR,
        target: Optional[Handler] = None,
        flushOnClose: bool = True,
        period: float = 5.0,
        reactor: Optional[IReactorCore] = None,
    ) -> None:
        """
        period: the period between automatic flushes

        reactor: if specified, a custom reactor to use. If not specifies,
            defaults to the globally-installed reactor.
            Log entries will be flushed immediately until this reactor has
            started.
        """
        super().__init__(capacity, flushLevel, target, flushOnClose)

        self._flush_period: float = period
        self._active: bool = True
        self._reactor_started = False

        self._flushing_thread: Thread = Thread(
            name="PeriodicallyFlushingMemoryHandler flushing thread",
            target=self._flush_periodically,
            daemon=True,
        )
        self._flushing_thread.start()

        def on_reactor_running() -> None:
            self._reactor_started = True

        reactor_to_use: IReactorCore
        if reactor is None:
            from twisted.internet import reactor as global_reactor

            reactor_to_use = cast(IReactorCore, global_reactor)
        else:
            reactor_to_use = reactor

        # call our hook when the reactor start up
        reactor_to_use.callWhenRunning(on_reactor_running)

    def shouldFlush(self, record: LogRecord) -> bool:
        """
        Before reactor start-up, log everything immediately.
        Otherwise, fall back to original behaviour of waiting for the buffer to fill.
        """

        if self._reactor_started:
            return super().shouldFlush(record)
        else:
            return True

    def _flush_periodically(self) -> None:
        """
        Whilst this handler is active, flush the handler periodically.
        """

        while self._active:
            # flush is thread-safe; it acquires and releases the lock internally
            self.flush()
            time.sleep(self._flush_period)

    def close(self) -> None:
        self._active = False
        super().close()


try:
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource

    USE_REAL_OTLP = True

    class RealOtlpHandler(LoggingHandler):
        def __init__(self, level: int = logging.NOTSET) -> None:
            self.logger_provider = LoggerProvider(
                resource=Resource(attributes={"service.name": "synapse"})
            )
            self.logger_provider.add_log_record_processor(
                BatchLogRecordProcessor(OTLPLogExporter())
            )
            super().__init__(level, self.logger_provider)
except ImportError as e:
    OTLP_IMPORT_EXC = e

    USE_REAL_OTLP = False

    class StubOtlpHandler:
        def __init__(self) -> None:
            check_requirements("opentelemetry-log-handler")
            raise OTLP_IMPORT_EXC


OtlpHandler = RealOtlpHandler if USE_REAL_OTLP else StubOtlpHandler
