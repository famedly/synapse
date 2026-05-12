#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright (C) 2025 Famedly GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
"""
OTLP-backed metric instruments with an API compatible with ``prometheus_client``.

Provides :class:`Counter`, :class:`Gauge` and :class:`Histogram` drop-in
replacements that forward measurements to an OpenTelemetry OTLP exporter
instead of the Prometheus scrape endpoint.

The OTLP exporter picks up its configuration from the standard ``OTEL_*``
environment variables (``OTEL_EXPORTER_OTLP_ENDPOINT``, etc.).

This module is only imported when ``SYNAPSE_METRICS_BACKEND=otlp``.
"""

from __future__ import annotations

import contextlib
import gc
import logging
import os
import resource
import threading
import time
from typing import (
    Any,
    Callable,
    Generator,
    Iterable,
    Sequence,
)

from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.metrics import Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

logger = logging.getLogger(__name__)

# Global OTel meter – created eagerly so that module-level metric definitions
# (the common pattern in Synapse) can use it immediately.

_resource = Resource.create(attributes={"service.name": "synapse"})
_exporter = OTLPMetricExporter()
_reader = PeriodicExportingMetricReader(_exporter)
_meter_provider = MeterProvider(resource=_resource, metric_readers=[_reader])
_meter = _meter_provider.get_meter("synapse")


def shutdown() -> None:
    """Flush pending metrics and release resources.  Call on server shutdown."""
    _meter_provider.shutdown()


# Pre-collect hook machinery
#
# Some metrics in Synapse (e.g. cache metrics) are updated lazily via hooks
# that normally run during a Prometheus scrape.  When exporting via OTLP we
# need to trigger these hooks ourselves before the periodic metric reader
# collects observations.
#
# Each :class:`Gauge` observable callback calls :func:`_run_pre_collect_hooks`
# which, at most once per collection cycle, invokes every registered hook.

_pre_collect_hooks: list[Callable[[], None]] = []
_pre_collect_lock = threading.Lock()
_last_pre_collect_time: float = 0.0
_PRE_COLLECT_MIN_INTERVAL: float = 0.5  # seconds


def register_pre_collect_hook(hook: Callable[[], None]) -> None:
    """Register a callable invoked before observable metrics are read.

    This is intended for things like
    ``DynamicCollectorRegistry.run_hooks``, which must run before Gauge
    observation callbacks so that the stored values are up-to-date.
    """
    with _pre_collect_lock:
        _pre_collect_hooks.append(hook)


def _run_pre_collect_hooks() -> None:
    """Run registered hooks, but at most once per ``_PRE_COLLECT_MIN_INTERVAL``."""
    global _last_pre_collect_time
    now = time.monotonic()
    if now - _last_pre_collect_time < _PRE_COLLECT_MIN_INTERVAL:
        return
    _last_pre_collect_time = now
    for hook in _pre_collect_hooks:
        try:
            hook()
        except Exception:
            logger.debug("Pre-collect hook %s failed", hook, exc_info=True)


class _GaugeChild:
    """A single label-set projection of an :class:`Gauge`."""

    __slots__ = ("_parent", "_attrs", "_key")

    def __init__(self, parent: Gauge, attrs: dict[str, str], key: tuple) -> None:
        self._parent = parent
        self._attrs = attrs
        self._key = key

    def set(self, value: float) -> None:
        self._parent._values[self._key] = float(value)

    def inc(self, amount: float = 1) -> None:
        k = self._key
        vals = self._parent._values
        vals[k] = vals.get(k, 0.0) + float(amount)

    def dec(self, amount: float = 1) -> None:
        k = self._key
        vals = self._parent._values
        vals[k] = vals.get(k, 0.0) - float(amount)

    def set_function(self, fn: Callable[[], float]) -> None:
        self._parent._functions[self._key] = (self._attrs, fn)
        self._parent._values.pop(self._key, None)

    def set_to_current_time(self) -> None:
        self.set(time.time())

    @contextlib.contextmanager
    def track_inprogress(self) -> Generator[None, None, None]:
        """Context-manager that increments the gauge on entry and decrements on exit."""
        self.inc()
        try:
            yield
        finally:
            self.dec()


class Gauge:
    """OTLP-backed drop-in replacement for ``prometheus_client.Gauge``.

    Internally this creates an OTel *ObservableGauge* whose callback returns
    the most recently stored values.  This is a natural fit because Synapse
    gauges are written to sporadically (e.g. from hooks) and read periodically.
    """

    def __init__(
        self,
        name: str,
        documentation: str = "",
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Any = None,
        _labelvalues: Any = None,
        multiprocess_mode: str = "all",
    ) -> None:
        self._name = name
        self._labelnames = list(labelnames)

        # {attrs_key_tuple: float}
        self._values: dict[tuple, float] = {}
        # {attrs_key_tuple: (attrs_dict, callable)}
        self._functions: dict[tuple, tuple[dict[str, str], Callable[[], float]]] = {}
        self._children: dict[tuple, _GaugeChild] = {}

        # When there are no label names the metric is used directly (.set(), .inc(), …).
        if not self._labelnames:
            self._no_label_child: _GaugeChild | None = _GaugeChild(self, {}, ())
        else:
            self._no_label_child = None

        def _callback(options: Any) -> Sequence[Observation]:
            _run_pre_collect_hooks()
            obs: list[Observation] = []
            for key, value in list(self._values.items()):
                obs.append(Observation(value, dict(key)))
            for attrs, fn in list(self._functions.values()):
                try:
                    obs.append(Observation(fn(), attrs))
                except Exception:
                    pass
            return obs

        self._instrument = _meter.create_observable_gauge(
            name,
            callbacks=[_callback],
            description=documentation,
        )

    def labels(self, *args: str, **kwargs: str) -> _GaugeChild:
        if args:
            attrs = dict(zip(self._labelnames, args))
        else:
            attrs = kwargs
        key = tuple(sorted(attrs.items()))
        child = self._children.get(key)
        if child is None:
            child = _GaugeChild(self, attrs, key)
            self._children[key] = child
        return child

    def remove(self, *labelvalues: str) -> None:
        """Remove the child and all stored data for the given label values.

        This mirrors ``prometheus_client.Gauge.remove`` so that callers like
        ``BatchingQueue.shutdown()`` work identically under the OTLP backend.
        """
        attrs = dict(zip(self._labelnames, labelvalues))
        key = tuple(sorted(attrs.items()))
        self._values.pop(key, None)
        self._functions.pop(key, None)
        self._children.pop(key, None)

    def set(self, value: float) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.set(value)

    def inc(self, amount: float = 1) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.inc(amount)

    def dec(self, amount: float = 1) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.dec(amount)

    def set_function(self, fn: Callable[[], float]) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.set_function(fn)

    def set_to_current_time(self) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.set_to_current_time()

    def describe(self) -> list:
        # prometheus compat stub (not needed for OTLP)
        return []

    def collect(self) -> list:
        # prometheus compat stub (not needed for OTLP)
        return []


class _CounterChild:
    """A single label-set projection of a :class:`Counter`."""

    __slots__ = ("_instrument", "_attrs")

    def __init__(self, instrument: Any, attrs: dict[str, str]) -> None:
        self._instrument = instrument
        self._attrs = attrs

    def inc(self, amount: float = 1) -> None:
        if amount < 0:
            raise ValueError(
                "Counter.inc amount must not be negative (got %s)" % amount
            )
        self._instrument.add(amount, self._attrs)


class Counter:
    """OTLP-backed drop-in replacement for ``prometheus_client.Counter``."""

    def __init__(
        self,
        name: str,
        documentation: str = "",
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Any = None,
        _labelvalues: Any = None,
    ) -> None:
        self._name = name
        self._labelnames = list(labelnames)
        self._instrument = _meter.create_counter(name, description=documentation)
        self._children: dict[tuple, _CounterChild] = {}

        if not self._labelnames:
            self._no_label_child: _CounterChild | None = _CounterChild(
                self._instrument,
                {},
            )
        else:
            self._no_label_child = None

    def labels(self, *args: str, **kwargs: str) -> _CounterChild:
        if args:
            attrs = dict(zip(self._labelnames, args))
        else:
            attrs = kwargs
        key = tuple(sorted(attrs.items()))
        child = self._children.get(key)
        if child is None:
            child = _CounterChild(self._instrument, attrs)
            self._children[key] = child
        return child

    def inc(self, amount: float = 1) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.inc(amount)

    def describe(self) -> list:
        return []

    def collect(self) -> list:
        return []


class _HistogramTimer:
    """Context-manager returned by ``Histogram.time()``."""

    __slots__ = ("_child", "_start")

    def __init__(self, child: _HistogramChild) -> None:
        self._child = child
        self._start: float | None = None

    def __enter__(self) -> _HistogramTimer:
        self._start = time.monotonic()
        return self

    def __exit__(self, *args: Any) -> None:
        assert self._start is not None
        self._child.observe(time.monotonic() - self._start)


class _HistogramChild:
    """A single label-set projection of a :class:`Histogram`."""

    __slots__ = ("_instrument", "_attrs")

    def __init__(self, instrument: Any, attrs: dict[str, str]) -> None:
        self._instrument = instrument
        self._attrs = attrs

    def observe(self, value: float) -> None:
        self._instrument.record(value, self._attrs)

    def time(self) -> _HistogramTimer:
        """Return a context-manager that observes the elapsed wall-clock time."""
        return _HistogramTimer(self)


class Histogram:
    """OTLP-backed drop-in replacement for ``prometheus_client.Histogram``.

    .. note::

       The *buckets* parameter is accepted for API compatibility but is
       **not** forwarded to the OTel instrument.  Bucket boundaries in
       OpenTelemetry are configured via *Views* on the ``MeterProvider``;
       the SDK default boundaries apply unless overridden there.
    """

    DEFAULT_BUCKETS = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.075,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        7.5,
        10.0,
        float("inf"),
    )

    def __init__(
        self,
        name: str,
        documentation: str = "",
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Any = None,
        _labelvalues: Any = None,
        buckets: Sequence[float | str] = DEFAULT_BUCKETS,
    ) -> None:
        self._name = name
        self._labelnames = list(labelnames)
        self._instrument = _meter.create_histogram(name, description=documentation)
        self._children: dict[tuple, _HistogramChild] = {}

        if not self._labelnames:
            self._no_label_child: _HistogramChild | None = _HistogramChild(
                self._instrument,
                {},
            )
        else:
            self._no_label_child = None

    def labels(self, *args: str, **kwargs: str) -> _HistogramChild:
        if args:
            attrs = dict(zip(self._labelnames, args))
        else:
            attrs = kwargs
        key = tuple(sorted(attrs.items()))
        child = self._children.get(key)
        if child is None:
            child = _HistogramChild(self._instrument, attrs)
            self._children[key] = child
        return child

    def observe(self, value: float) -> None:
        assert self._no_label_child is not None, "Must call .labels() first"
        self._no_label_child.observe(value)

    def time(self) -> _HistogramTimer:
        assert self._no_label_child is not None, "Must call .labels() first"
        return self._no_label_child.time()

    def describe(self) -> list:
        return []

    def collect(self) -> list:
        return []


# Process-level metrics
#
# Replicate the metrics normally provided by prometheus_client's
# built-in ProcessCollector and Synapse's CPUMetrics / GCCounts
# custom collectors, which only feed the Prometheus REGISTRY.

_HAVE_PROC_SELF_STAT = os.path.exists("/proc/self/stat")

try:
    _PAGESIZE: int = os.sysconf("SC_PAGESIZE")
except (ValueError, OSError, AttributeError):
    _PAGESIZE = 4096

try:
    _TICKS_PER_SEC: int = os.sysconf("SC_CLK_TCK")
except (ValueError, OSError, AttributeError):
    _TICKS_PER_SEC = 100

# Boot time (seconds since epoch) for process_start_time_seconds.
_BOOT_TIME: float | None = None
try:
    with open("/proc/stat") as _f:
        for _line in _f:
            if _line.startswith("btime "):
                _BOOT_TIME = float(_line.split()[1])
                break
except OSError:
    pass


def _read_proc_self_stat() -> list[str] | None:
    """Return fields of ``/proc/self/stat`` after the *comm* field.

    Index 11 = utime, 12 = stime, 19 = starttime, 20 = vsize, 21 = rss.
    """
    try:
        with open("/proc/self/stat") as fh:
            data = fh.read()
        return data.split(") ", 1)[1].split(" ")
    except Exception:
        return None


if _HAVE_PROC_SELF_STAT:

    def _observe_cpu_seconds(options: Any) -> Sequence[Observation]:
        fields = _read_proc_self_stat()
        if fields is None:
            return []
        utime = float(fields[11]) / _TICKS_PER_SEC
        stime = float(fields[12]) / _TICKS_PER_SEC
        return [Observation(utime + stime)]

    _meter.create_observable_gauge(
        "process_cpu_seconds_total",
        callbacks=[_observe_cpu_seconds],
        description="Total user and system CPU time spent in seconds.",
    )

    def _observe_cpu_user(options: Any) -> Sequence[Observation]:
        fields = _read_proc_self_stat()
        if fields is None:
            return []
        return [Observation(float(fields[11]) / _TICKS_PER_SEC)]

    _meter.create_observable_gauge(
        "process_cpu_user_seconds_total",
        callbacks=[_observe_cpu_user],
        description="Total user CPU time spent in seconds.",
    )

    def _observe_cpu_system(options: Any) -> Sequence[Observation]:
        fields = _read_proc_self_stat()
        if fields is None:
            return []
        return [Observation(float(fields[12]) / _TICKS_PER_SEC)]

    _meter.create_observable_gauge(
        "process_cpu_system_seconds_total",
        callbacks=[_observe_cpu_system],
        description="Total system CPU time spent in seconds.",
    )

    def _observe_resident_memory(options: Any) -> Sequence[Observation]:
        fields = _read_proc_self_stat()
        if fields is None:
            return []
        # Index 21 = rss in pages.
        return [Observation(float(fields[21]) * _PAGESIZE)]

    _meter.create_observable_gauge(
        "process_resident_memory_bytes",
        callbacks=[_observe_resident_memory],
        description="Resident memory size in bytes.",
    )

    def _observe_virtual_memory(options: Any) -> Sequence[Observation]:
        fields = _read_proc_self_stat()
        if fields is None:
            return []
        # Index 20 = vsize in bytes.
        return [Observation(float(fields[20]))]

    _meter.create_observable_gauge(
        "process_virtual_memory_bytes",
        callbacks=[_observe_virtual_memory],
        description="Virtual memory size in bytes.",
    )

    if _BOOT_TIME is not None:

        def _observe_start_time(options: Any) -> Sequence[Observation]:
            fields = _read_proc_self_stat()
            if fields is None:
                return []
            # Index 19 = starttime in ticks since boot.
            return [Observation(float(fields[19]) / _TICKS_PER_SEC + _BOOT_TIME)]

        _meter.create_observable_gauge(
            "process_start_time_seconds",
            callbacks=[_observe_start_time],
            description="Start time of the process since unix epoch in seconds.",
        )

    def _observe_open_fds(options: Any) -> Sequence[Observation]:
        try:
            return [Observation(float(len(os.listdir("/proc/self/fd"))))]
        except OSError:
            return []

    _meter.create_observable_gauge(
        "process_open_fds",
        callbacks=[_observe_open_fds],
        description="Number of open file descriptors.",
    )

    def _observe_max_fds(options: Any) -> Sequence[Observation]:
        try:
            soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            return [Observation(float(soft))]
        except (ValueError, OSError):
            return []

    _meter.create_observable_gauge(
        "process_max_fds",
        callbacks=[_observe_max_fds],
        description="Maximum number of open file descriptors.",
    )


def _observe_gc_counts(options: Any) -> Sequence[Observation]:
    return [
        Observation(float(count), {"gen": str(gen)})
        for gen, count in enumerate(gc.get_count())
    ]


_meter.create_observable_gauge(
    "python_gc_counts",
    callbacks=[_observe_gc_counts],
    description="GC object counts per generation.",
)


class CollectorRegistry:
    def collect(self):
        return []


class Registry:
    def register(self, other):
        def _drain():
            for _ in other.collect():
                pass

        register_pre_collect_hook(_drain)


REGISTRY = Registry()
