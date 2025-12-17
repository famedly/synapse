#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2022 The Matrix.org Foundation C.I.C.
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright (C) 2023 New Vector, Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#

import itertools
import logging
import os
import platform
import threading
from importlib import metadata
from time import time
from types import MethodType
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    Literal,
    Mapping,
    Optional,
    Sequence,
    TypeVar,
    Union,
    cast,
)

import attr
from opentelemetry import metrics
from opentelemetry.exporter.prometheus import (
    PrometheusMetricReader,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource as OtelResource
from packaging.version import parse as parse_version
from prometheus_client import (
    CollectorRegistry,
    Metric,
    generate_latest,
    values,
)
from prometheus_client.context_managers import Timer
from prometheus_client.core import (
    REGISTRY,
    GaugeHistogramMetricFamily,
    GaugeMetricFamily,
    Sample,
)
from prometheus_client.metrics import _get_use_created
from prometheus_client.samples import Exemplar
from prometheus_client.utils import INF, floatToGoString
from prometheus_client.values import ValueClass
from typing_extensions import Dict, Self

from twisted.python.threadpool import ThreadPool
from twisted.web.resource import Resource
from twisted.web.server import Request

# This module is imported for its side effects; flake8 needn't warn that it's unused.
import synapse.metrics._reactor_metrics  # noqa: F401
from synapse.metrics._gc import MIN_TIME_BETWEEN_GCS, install_gc_manager
from synapse.metrics._types import Collector
from synapse.types import StrSequence
from synapse.util import SYNAPSE_VERSION

logger = logging.getLogger(__name__)

METRICS_PREFIX = "/_synapse/metrics"

HAVE_PROC_SELF_STAT = os.path.exists("/proc/self/stat")

SERVER_NAME_LABEL = "server_name"
"""
The `server_name` label is used to identify the homeserver that the metrics correspond
to. Because we support multiple instances of Synapse running in the same process and all
metrics are in a single global `REGISTRY`, we need to manually label any metrics.

In the case of a Synapse homeserver, this should be set to the homeserver name
(`hs.hostname`).

We're purposely not using the `instance` label for this purpose as that should be "The
<host>:<port> part of the target's URL that was scraped.". Also: "In Prometheus
terms, an endpoint you can scrape is called an *instance*, usually corresponding to a
single process." (source: https://prometheus.io/docs/concepts/jobs_instances/)
"""


CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
"""
Content type of the latest text format for Prometheus metrics.

Pulled directly from the prometheus_client library.
"""


def _set_prometheus_client_use_created_metrics(new_value: bool) -> None:
    """
    Sets whether prometheus_client should expose `_created`-suffixed metrics for
    all gauges, histograms and summaries.

    There is no programmatic way in the old versions of `prometheus_client` to disable
    this without poking at internals; the proper way in the old `prometheus_client`
    versions (> `0.14.0` < `0.18.0`) is to use an environment variable which
    prometheus_client loads at import time. For versions > `0.18.0`, we can use the
    dedicated `disable_created_metrics()`/`enable_created_metrics()`.

    The motivation for disabling these `_created` metrics is that they're a waste of
    space as they're not useful but they take up space in Prometheus. It's not the end
    of the world if this doesn't work.
    """
    import prometheus_client.metrics

    if hasattr(prometheus_client.metrics, "_use_created"):
        prometheus_client.metrics._use_created = new_value
    # Just log an error for old versions that don't support disabling the unecessary
    # metrics. It's not the end of the world if this doesn't work as it just means extra
    # wasted space taken up in Prometheus but things keep working.
    elif parse_version(metadata.version("prometheus_client")) < parse_version("0.14.0"):
        logger.error(
            "Can't disable `_created` metrics in prometheus_client (unsupported `prometheus_client` version, too old)"
        )
    # If the attribute doesn't exist on a newer version, this is a sign that the brittle
    # hack is broken. We should consider updating the minimum version of
    # `prometheus_client` to a version (> `0.18.0`) where we can use dedicated
    # `disable_created_metrics()`/`enable_created_metrics()` functions.
    else:
        raise Exception(
            "Can't disable `_created` metrics in prometheus_client (brittle hack broken?)"
        )


# Set this globally so it applies wherever we generate/collect metrics
_set_prometheus_client_use_created_metrics(False)

# This will create a Resource that can do the displaying of the prometheus metrics. The
# start_http_server() that is used by the listen_metrics() call in _base.py will pick
# this up and serve it.
resource = OtelResource(attributes={SERVICE_NAME: "synapse"})
reader = PrometheusMetricReader()
provider = MeterProvider(resource=resource, metric_readers=[reader])
metrics.set_meter_provider(provider)
# Global meter for registering otel metrics
meter = provider.get_meter("synapse-otel-meter")


class _RegistryProxy:
    @staticmethod
    def collect() -> Iterable[Metric]:
        for metric in REGISTRY.collect():
            if not metric.name.startswith("__"):
                yield metric


# A little bit nasty, but collect() above is static so a Protocol doesn't work.
# _RegistryProxy matches the signature of a CollectorRegistry instance enough
# for it to be usable in the contexts in which we use it.
# TODO Do something nicer about this.
RegistryProxy = cast(CollectorRegistry, _RegistryProxy)


def _build_full_name(
    metric_type: str, name: str, namespace: str, subsystem: str, unit: str
) -> str:
    # Ripped from prometheus_client/metrics.py
    if not name:
        raise ValueError("Metric name should not be empty")
    full_name = ""
    if namespace:
        full_name += namespace + "_"
    if subsystem:
        full_name += subsystem + "_"
    full_name += name
    if metric_type == "counter" and full_name.endswith("_total"):
        full_name = full_name[:-6]  # Munge to OpenMetrics.
    if unit and not full_name.endswith("_" + unit):
        full_name += "_" + unit
    if unit and metric_type in ("info", "stateset"):
        raise ValueError(
            "Metric name is of a type that cannot have a unit: " + full_name
        )
    return full_name


T = TypeVar("T", bound="SynapseMetricWrapperBase")


class SynapseMetricWrapperBase:
    def _raise_if_not_observable(self) -> None:
        # Functions that mutate the state of the metric, for example incrementing
        # a counter, will fail if the metric is not observable, because only if a
        # metric is observable will the value be initialized.
        if not self._is_observable():
            raise ValueError("%s metric is missing label values" % str(self._type))

    def _is_observable(self):  # type: ignore[no-untyped-def]
        # Whether this metric is observable, i.e.
        # * a metric without label names and values, or
        # * the child of a labelled metric.
        return not self._labelnames or (self._labelnames and self._labelvalues)

    def __init__(
        self: T,
        name: str,
        documentation: str,
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Optional[CollectorRegistry] = REGISTRY,
        _labelvalues: Optional[Sequence[str]] = None,
    ) -> None:
        self._type: str = ""
        self._original_name = name
        self._namespace = namespace
        self._subsystem = subsystem
        self._name = _build_full_name(self._type, name, namespace, subsystem, unit)
        # prom validates these, should we do that?
        # labelnames provide a simple way to register that a given set of kwargs call
        # from labels can be used. All should be used in a call?
        self._labelnames = tuple(labelnames or ())
        self._labelvalues = tuple(_labelvalues or ())
        self._kwargs: Dict[str, Any] = {}
        self._documentation = documentation
        self._unit = unit
        self._metrics = {}  # type: ignore[var-annotated]
        self._lock = threading.Lock()

        # if self._is_parent():
        #     # Prepare the fields needed for child metrics.
        #     self._lock = Lock()
        #     self._metrics: Dict[Sequence[str], T] = {}

        if self._is_observable():
            self._metric_init()

        # if not self._labelvalues:
        #     # Register the multi-wrapper parent metric, or if a label-less metric, the whole shebang.
        #     if registry:
        #         registry.register(self)
        self._registry = registry

    def _metric_init(self):  # type: ignore[no-untyped-def]  # pragma: no cover
        """
        Initialize the metric object as a child, i.e. when it has labels (if any) set.

        This is factored as a separate function to allow for deferred initialization.
        """
        raise NotImplementedError("_metric_init() must be implemented by %r" % self)

    def labels(self, *labelvalues: Any, **labelkwargs: Any) -> Self:
        if not self._labelnames:
            raise ValueError("No label names were set when constructing %s" % self)

        if self._labelvalues:
            raise ValueError(
                "{} already has labels set ({}); can not chain calls to .labels()".format(
                    self, dict(zip(self._labelnames, self._labelvalues))
                )
            )

        if labelvalues and labelkwargs:
            raise ValueError("Can't pass both *args and **kwargs")

        if labelkwargs:
            if sorted(labelkwargs) != sorted(self._labelnames):
                raise ValueError("Incorrect label names")
            labelvalues = tuple(
                str(labelkwargs[lablename]) for lablename in self._labelnames
            )
        else:
            if len(labelvalues) != len(self._labelnames):
                raise ValueError("Incorrect label count")
            labelvalues = tuple(str(labelvalue) for labelvalue in labelvalues)
        with self._lock:
            if labelvalues not in self._metrics:
                original_name = getattr(self, "_original_name", self._name)
                namespace = getattr(self, "_namespace", "")
                subsystem = getattr(self, "_subsystem", "")
                unit = getattr(self, "_unit", "")

                child_kwargs = dict(self._kwargs) if self._kwargs else {}
                for k in ("namespace", "subsystem", "unit"):
                    child_kwargs.pop(k, None)

                self._metrics[labelvalues] = self.__class__(
                    original_name,
                    documentation=self._documentation,
                    labelnames=self._labelnames,
                    namespace=namespace,
                    subsystem=subsystem,
                    unit=unit,
                    _labelvalues=labelvalues,
                    **child_kwargs,
                )
            return self._metrics[labelvalues]

    def _get_metric(self):  # type: ignore[no-untyped-def]
        return Metric(self._name, self._documentation, self._type, self._unit)

    def collect(self) -> Iterable[Metric]:
        metric = self._get_metric()
        for (
            suffix,
            labels,
            value,
            timestamp,
            exemplar,
            native_histogram_value,
        ) in self._samples():
            metric.add_sample(
                self._name + suffix,
                labels,
                value,
                timestamp,
                exemplar,
                native_histogram_value,
            )
        return [metric]

    def _is_parent(self):  # type: ignore[no-untyped-def]
        return self._labelnames and not self._labelvalues

    def _child_samples(self) -> Iterable[Sample]:  # pragma: no cover
        raise NotImplementedError("_child_samples() must be implemented by %r" % self)

    def _samples(self) -> Iterable[Sample]:
        if self._is_parent():
            return self._multi_samples()
        else:
            return self._child_samples()

    def _multi_samples(self) -> Iterable[Sample]:
        with self._lock:
            metrics = self._metrics.copy()
        for labels, metric in metrics.items():
            series_labels = list(zip(self._labelnames, labels))
            for (
                suffix,
                sample_labels,
                value,
                timestamp,
                exemplar,
                native_histogram_value,
            ) in metric._samples():
                yield Sample(
                    suffix,
                    dict(series_labels + list(sample_labels.items())),
                    value,
                    timestamp,
                    exemplar,
                    native_histogram_value,
                )

    # not sure if this is needed, putting it there for now to make the linter happy
    def remove(self, *labelvalues: Any) -> None:
        if not self._labelnames:
            raise ValueError("No label names were set when constructing %s" % self)

        """Remove the given labelset from the metric."""
        if len(labelvalues) != len(self._labelnames):
            raise ValueError(
                "Incorrect label count (expected %d, got %s)"
                % (len(self._labelnames), labelvalues)
            )
        labelvalues = tuple(str(labelvalue) for labelvalue in labelvalues)
        with self._lock:
            if labelvalues in self._metrics:
                del self._metrics[labelvalues]


class SynapseCounter(SynapseMetricWrapperBase):
    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Optional[CollectorRegistry] = REGISTRY,
        _labelvalues: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__(
            name,
            documentation,
            labelnames,
            namespace,
            subsystem,
            unit,
            registry,
            _labelvalues,
        )
        self._type = "counter"
        # Here is where we grab the global meter to create a FauxCounter
        self._counter = meter.create_counter(
            self._name, unit=self._unit, description=self._documentation
        )

        self._current_attributes = ()

    def inc(self, amount: float = 1.0) -> None:
        # Need to verify what happens with Counters that do not have labels as children,
        # this may not be appropriate in those cases. Can probably just leave the
        # attributes param as empty in that case?
        self._value.inc(amount)
        self._counter.add(amount, dict(zip(self._labelnames, self._current_attributes)))
        # # If this was a "child" metric, then the lock will have been taken in labels()
        # if self._lock.locked():
        #     self._lock.release()

    def _metric_init(self) -> None:
        self._value = ValueClass(
            self._type,
            self._name,
            self._name + "_total",
            self._labelnames,
            self._labelvalues,
            self._documentation,
        )
        self._created = time()

    def _child_samples(self) -> Iterable[Sample]:
        sample = Sample(
            "_total", {}, self._value.get(), None, self._value.get_exemplar()
        )
        if _get_use_created():
            return (sample, Sample("_created", {}, self._created, None, None))
        return (sample,)


F = TypeVar("F", bound=Callable[..., Any])


class InprogressTracker:
    def __init__(self, gauge) -> None:  # type: ignore[no-untyped-def]
        self._gauge = gauge

    def __enter__(self) -> None:
        self._gauge.inc()

    def __exit__(self, typ, value, traceback) -> None:  # type: ignore[no-untyped-def]
        self._gauge.dec()

    # def __call__(self, f: "F") -> "F":
    #     def wrapped(func, *args, **kwargs):
    #         with self:
    #             return func(*args, **kwargs)

    #     return decorate(f, wrapped)


class SynapseGauge(SynapseMetricWrapperBase):
    _MULTIPROC_MODES = frozenset(
        (
            "all",
            "liveall",
            "min",
            "livemin",
            "max",
            "livemax",
            "sum",
            "livesum",
            "mostrecent",
            "livemostrecent",
        )
    )
    _MOST_RECENT_MODES = frozenset(("mostrecent", "livemostrecent"))

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Optional[CollectorRegistry] = REGISTRY,
        _labelvalues: Optional[Sequence[str]] = None,
        multiprocess_mode: Literal[
            "all",
            "liveall",
            "min",
            "livemin",
            "max",
            "livemax",
            "sum",
            "livesum",
            "mostrecent",
            "livemostrecent",
        ] = "all",
    ):
        self._multiprocess_mode = multiprocess_mode
        if multiprocess_mode not in self._MULTIPROC_MODES:
            raise ValueError("Invalid multiprocess mode: " + multiprocess_mode)
        super().__init__(
            name=name,
            documentation=documentation,
            labelnames=labelnames,
            namespace=namespace,
            subsystem=subsystem,
            unit=unit,
            registry=registry,
            _labelvalues=_labelvalues,
        )
        self._type = "gauge"
        # Here is where we grab the global meter to create a FauxGauge
        self._gauge = meter.create_gauge(
            self._name, unit=self._unit, description=self._documentation
        )
        self._kwargs["multiprocess_mode"] = self._multiprocess_mode
        self._is_most_recent = self._multiprocess_mode in self._MOST_RECENT_MODES
        self._gauge_value: float = 0

        if not self._labelvalues and self._registry:
            # TODO: look into what to do here, and maybe move it to the wrapperbase?
            self._registry.register(self)  # type: ignore

    def set(self, value: float) -> None:
        """Set gauge to the given value."""
        self._raise_if_not_observable()
        if self._is_most_recent:
            self._value.set(float(value), timestamp=time())
        else:
            self._value.set(float(value))
        self._gauge.set(value)
        self._gauge_value = value
        # self._value.set(0)

    def inc(self, amount: float = 1) -> None:
        """Increment gauge by the given amount."""
        if self._is_most_recent:
            raise RuntimeError("inc must not be used with the mostrecent mode")
        # self._raise_if_not_observable()
        self._value.inc(amount)
        self._gauge_value += amount
        self._gauge.set(self._gauge_value)

    def dec(self, amount: float = 1) -> None:
        """Decrement gauge by the given amount."""
        if self._is_most_recent:
            raise RuntimeError("inc must not be used with the mostrecent mode")
        # self._raise_if_not_observable()
        self._gauge_value -= amount
        self._gauge.set(self._gauge_value)
        self._value.inc(-amount)

    def track_inprogress(self) -> InprogressTracker:
        """Track inprogress blocks of code or functions.

        Can be used as a function decorator or context manager.
        Increments the gauge when the code is entered,
        and decrements when it is exited.
        """
        # self._raise_if_not_observable()
        return InprogressTracker(self)

    def set_function(self, f: Callable[[], float]) -> None:
        """Call the provided function to return the Gauge value.

        The function must return a float, and may be called from
        multiple threads. All other methods of the Gauge become NOOPs.
        """
        # self._raise_if_not_observable()

        def samples(_: SynapseGauge) -> Iterable[Sample]:
            return (Sample("", {}, float(f()), None, None),)

        self._child_samples = MethodType(samples, self)  # type: ignore

    def _child_samples(self) -> Iterable[Sample]:
        return (Sample("", {}, self._value.get(), None, None),)

    def _metric_init(self) -> None:
        self._value = ValueClass(
            self._type,
            self._name,
            self._name,
            self._labelnames,
            self._labelvalues,
            self._documentation,
            multiprocess_mode=self._multiprocess_mode,
        )


class SynapseHistogram(SynapseMetricWrapperBase):
    _type = "histogram"
    _reserved_labelnames = ["le"]
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
        INF,
    )

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Iterable[str] = (),
        namespace: str = "",
        subsystem: str = "",
        unit: str = "",
        registry: Optional[CollectorRegistry] = REGISTRY,
        _labelvalues: Optional[Sequence[str]] = None,
        buckets: Sequence[float] = DEFAULT_BUCKETS,
    ):
        self._prepare_buckets(buckets)
        super().__init__(
            name=name,
            documentation=documentation,
            labelnames=labelnames,
            namespace=namespace,
            subsystem=subsystem,
            unit=unit,
            registry=registry,
            _labelvalues=_labelvalues,
        )
        self._histogram = meter.create_histogram(
            self._name,
            unit=self._unit,
            description=self._documentation,
            explicit_bucket_boundaries_advisory=buckets,
        )
        self._kwargs["buckets"] = buckets

    def _prepare_buckets(self, source_buckets: Sequence[Union[float, str]]) -> None:
        buckets = [float(b) for b in source_buckets]
        if buckets != sorted(buckets):
            # This is probably an error on the part of the user,
            # so raise rather than sorting for them.
            raise ValueError("Buckets not in sorted order")
        if buckets and buckets[-1] != INF:
            buckets.append(INF)
        if len(buckets) < 2:
            raise ValueError("Must have at least two buckets")
        self._upper_bounds = buckets

    def _metric_init(self) -> None:
        self._buckets: list[values.ValueClass] = []
        self._created = time()
        bucket_labelnames = self._labelnames + ("le",)
        self._sum = values.ValueClass(
            self._type,
            self._name,
            self._name + "_sum",
            self._labelnames,
            self._labelvalues,
            self._documentation,
        )
        for b in self._upper_bounds:
            self._buckets.append(
                values.ValueClass(
                    self._type,
                    self._name,
                    self._name + "_bucket",
                    bucket_labelnames,
                    self._labelvalues + (floatToGoString(b),),
                    self._documentation,
                )
            )

    def observe(self, amount: float, exemplar: Optional[Dict[str, str]] = None) -> None:
        """Observe the given amount.

        The amount is usually positive or zero. Negative values are
        accepted but prevent current versions of Prometheus from
        properly detecting counter resets in the sum of
        observations. See
        https://prometheus.io/docs/practices/histograms/#count-and-sum-of-observations
        for details.
        """
        self._raise_if_not_observable()
        self._sum.inc(amount)
        for i, bound in enumerate(self._upper_bounds):
            if amount <= bound:
                self._buckets[i].inc(1)
                if exemplar:
                    # _validate_exemplar(exemplar)
                    self._buckets[i].set_exemplar(Exemplar(exemplar, amount, time()))
                break

    def time(self) -> Timer:
        """Time a block of code or function, and observe the duration in seconds.

        Can be used as a function decorator or context manager.
        """
        return Timer(self, "observe")

    def _child_samples(self) -> Iterable[Sample]:
        samples = []
        acc = 0.0
        for i, bound in enumerate(self._upper_bounds):
            acc += self._buckets[i].get()
            samples.append(
                Sample(
                    "_bucket",
                    {"le": floatToGoString(bound)},
                    acc,
                    None,
                    self._buckets[i].get_exemplar(),
                )
            )
        samples.append(Sample("_count", {}, acc, None, None))
        if self._upper_bounds[0] >= 0:
            samples.append(Sample("_sum", {}, self._sum.get(), None, None))
        if _get_use_created():
            samples.append(Sample("_created", {}, self._created, None, None))
        return tuple(samples)


@attr.s(slots=True, hash=True, auto_attribs=True, kw_only=True)
class LaterGauge(Collector):
    """A Gauge which periodically calls a user-provided callback to produce metrics."""

    name: str
    desc: str
    labelnames: Optional[StrSequence] = attr.ib(hash=False)
    _instance_id_to_hook_map: dict[
        Optional[str],  # instance_id
        Callable[
            [], Union[Mapping[tuple[str, ...], Union[int, float]], Union[int, float]]
        ],
    ] = attr.ib(factory=dict, hash=False)
    """
    Map from homeserver instance_id to a callback. Each callback should either return a
    value (if there are no labels for this metric), or dict mapping from a label tuple
    to a value.

    We use `instance_id` instead of `server_name` because it's possible to have multiple
    workers running in the same process with the same `server_name`.
    """

    def collect(self) -> Iterable[Metric]:
        # The decision to add `SERVER_NAME_LABEL` is from the `LaterGauge` usage itself
        # (we don't enforce it here, one level up).
        g = GaugeMetricFamily(self.name, self.desc, labels=self.labelnames)  # type: ignore[missing-server-name-label]

        for homeserver_instance_id, hook in self._instance_id_to_hook_map.items():
            try:
                hook_result = hook()
            except Exception:
                logger.exception(
                    "Exception running callback for LaterGauge(%s) for homeserver_instance_id=%s",
                    self.name,
                    homeserver_instance_id,
                )
                # Continue to return the rest of the metrics that aren't broken
                continue

            if isinstance(hook_result, (int, float)):
                g.add_metric([], hook_result)
            else:
                for k, v in hook_result.items():
                    g.add_metric(k, v)

        yield g

    def register_hook(
        self,
        *,
        homeserver_instance_id: Optional[str],
        hook: Callable[
            [], Union[Mapping[tuple[str, ...], Union[int, float]], Union[int, float]]
        ],
    ) -> None:
        """
        Register a callback/hook that will be called to generate a metric samples for
        the gauge.

        Args:
            homeserver_instance_id: The unique ID for this Synapse process instance
                (`hs.get_instance_id()`) that this hook is associated with. This can be used
                later to lookup all hooks associated with a given server name in order to
                unregister them. This should only be omitted for global hooks that work
                across all homeservers.
            hook: A callback that should either return a value (if there are no
                labels for this metric), or dict mapping from a label tuple to a value
        """
        # We shouldn't have multiple hooks registered for the same homeserver `instance_id`.
        existing_hook = self._instance_id_to_hook_map.get(homeserver_instance_id)
        assert existing_hook is None, (
            f"LaterGauge(name={self.name}) hook already registered for homeserver_instance_id={homeserver_instance_id}. "
            "This is likely a Synapse bug and you forgot to unregister the previous hooks for "
            "the server (especially in tests)."
        )

        self._instance_id_to_hook_map[homeserver_instance_id] = hook

    def unregister_hooks_for_homeserver_instance_id(
        self, homeserver_instance_id: str
    ) -> None:
        """
        Unregister all hooks associated with the given homeserver `instance_id`. This should be
        called when a homeserver is shutdown to avoid extra hooks sitting around.

        Args:
            homeserver_instance_id: The unique ID for this Synapse process instance to
                unregister hooks for (`hs.get_instance_id()`).
        """
        self._instance_id_to_hook_map.pop(homeserver_instance_id, None)

    def __attrs_post_init__(self) -> None:
        REGISTRY.register(self)

        # We shouldn't have multiple metrics with the same name. Typically, metrics
        # should be created globally so you shouldn't be running into this and this will
        # catch any stupid mistakes. The `REGISTRY.register(self)` call above will also
        # raise an error if the metric already exists but to make things explicit, we'll
        # also check here.
        existing_gauge = all_later_gauges_to_clean_up_on_shutdown.get(self.name)
        assert existing_gauge is None, f"LaterGauge(name={self.name}) already exists. "

        # Keep track of the gauge so we can clean it up later.
        all_later_gauges_to_clean_up_on_shutdown[self.name] = self


all_later_gauges_to_clean_up_on_shutdown: dict[str, LaterGauge] = {}
"""
Track all `LaterGauge` instances so we can remove any associated hooks during homeserver
shutdown.
"""


# `MetricsEntry` only makes sense when it is a `Protocol`,
# but `Protocol` can't be used as a `TypeVar` bound.
MetricsEntry = TypeVar("MetricsEntry")


class InFlightGauge(Generic[MetricsEntry], Collector):
    """Tracks number of things (e.g. requests, Measure blocks, etc) in flight
    at any given time.

    Each InFlightGauge will create a metric called `<name>_total` that counts
    the number of in flight blocks, as well as a metrics for each item in the
    given `sub_metrics` as `<name>_<sub_metric>` which will get updated by the
    callbacks.

    Args:
        name
        desc
        labels
        sub_metrics: A list of sub metrics that the callbacks will update.
    """

    def __init__(
        self,
        name: str,
        desc: str,
        labels: StrSequence,
        sub_metrics: StrSequence,
    ):
        self.name = name
        self.desc = desc
        self.labels = labels
        self.sub_metrics = sub_metrics

        # Create a class which have the sub_metrics values as attributes, which
        # default to 0 on initialization. Used to pass to registered callbacks.
        self._metrics_class: type[MetricsEntry] = attr.make_class(
            "_MetricsEntry",
            attrs={x: attr.ib(default=0) for x in sub_metrics},
            slots=True,
        )

        # Counts number of in flight blocks for a given set of label values
        self._registrations: dict[
            tuple[str, ...], set[Callable[[MetricsEntry], None]]
        ] = {}

        # Protects access to _registrations
        self._lock = threading.Lock()

        REGISTRY.register(self)

    def register(
        self,
        key: tuple[str, ...],
        callback: Callable[[MetricsEntry], None],
    ) -> None:
        """Registers that we've entered a new block with labels `key`.

        `callback` gets called each time the metrics are collected. The same
        value must also be given to `unregister`.

        `callback` gets called with an object that has an attribute per
        sub_metric, which should be updated with the necessary values. Note that
        the metrics object is shared between all callbacks registered with the
        same key.

        Note that `callback` may be called on a separate thread.

        Args:
            key: A tuple of label values, which must match the order of the
                `labels` given to the constructor.
            callback
        """
        assert len(key) == len(self.labels), (
            f"Expected {len(self.labels)} labels in `key`, got {len(key)}: {key}"
        )

        with self._lock:
            self._registrations.setdefault(key, set()).add(callback)

    def unregister(
        self,
        key: tuple[str, ...],
        callback: Callable[[MetricsEntry], None],
    ) -> None:
        """
        Registers that we've exited a block with labels `key`.

        Args:
            key: A tuple of label values, which must match the order of the
                `labels` given to the constructor.
            callback
        """
        assert len(key) == len(self.labels), (
            f"Expected {len(self.labels)} labels in `key`, got {len(key)}: {key}"
        )

        with self._lock:
            self._registrations.setdefault(key, set()).discard(callback)

    def collect(self) -> Iterable[Metric]:
        """Called by prometheus client when it reads metrics.

        Note: may be called by a separate thread.
        """
        # The decision to add `SERVER_NAME_LABEL` is from the `GaugeBucketCollector`
        # usage itself (we don't enforce it here, one level up).
        in_flight = GaugeMetricFamily(  # type: ignore[missing-server-name-label]
            self.name + "_total", self.desc, labels=self.labels
        )

        metrics_by_key = {}

        # We copy so that we don't mutate the list while iterating
        with self._lock:
            keys = list(self._registrations)

        for key in keys:
            with self._lock:
                callbacks = set(self._registrations[key])

            in_flight.add_metric(labels=key, value=len(callbacks))

            metrics = self._metrics_class()
            metrics_by_key[key] = metrics
            for callback in callbacks:
                callback(metrics)

        yield in_flight

        for name in self.sub_metrics:
            # The decision to add `SERVER_NAME_LABEL` is from the `InFlightGauge` usage
            # itself (we don't enforce it here, one level up).
            gauge = GaugeMetricFamily(  # type: ignore[missing-server-name-label]
                "_".join([self.name, name]), "", labels=self.labels
            )
            for key, metrics in metrics_by_key.items():
                gauge.add_metric(labels=key, value=getattr(metrics, name))
            yield gauge


class GaugeHistogramMetricFamilyWithLabels(GaugeHistogramMetricFamily):
    """
    Custom version of `GaugeHistogramMetricFamily` from `prometheus_client` that allows
    specifying labels and label values.

    A single gauge histogram and its samples.

    For use by custom collectors.
    """

    def __init__(
        self,
        *,
        name: str,
        documentation: str,
        gsum_value: float,
        buckets: Optional[Sequence[tuple[str, float]]] = None,
        labelnames: StrSequence = (),
        labelvalues: StrSequence = (),
        unit: str = "",
    ):
        # Sanity check the number of label values matches the number of label names.
        if len(labelvalues) != len(labelnames):
            raise ValueError(
                "The number of label values must match the number of label names"
            )

        # Call the super to validate and set the labelnames. We use this stable API
        # instead of setting the internal `_labelnames` field directly.
        super().__init__(
            name=name,
            documentation=documentation,
            labels=labelnames,
            # Since `GaugeHistogramMetricFamily` doesn't support supplying `labels` and
            # `buckets` at the same time (artificial limitation), we will just set these
            # as `None` and set up the buckets ourselves just below.
            buckets=None,
            gsum_value=None,
        )

        # Create a gauge for each bucket.
        if buckets is not None:
            self.add_metric(labels=labelvalues, buckets=buckets, gsum_value=gsum_value)


class GaugeBucketCollector(Collector):
    """Like a Histogram, but the buckets are Gauges which are updated atomically.

    The data is updated by calling `update_data` with an iterable of measurements.

    We assume that the data is updated less frequently than it is reported to
    Prometheus, and optimise for that case.
    """

    __slots__ = (
        "_name",
        "_documentation",
        "_labelnames",
        "_bucket_bounds",
        "_metric",
    )

    def __init__(
        self,
        *,
        name: str,
        documentation: str,
        labelnames: Optional[StrSequence],
        buckets: Iterable[float],
        registry: CollectorRegistry = REGISTRY,
    ):
        """
        Args:
            name: base name of metric to be exported to Prometheus. (a _bucket suffix
               will be added.)
            documentation: help text for the metric
            buckets: The top bounds of the buckets to report
            registry: metric registry to register with
        """
        self._name = name
        self._documentation = documentation
        self._labelnames = labelnames if labelnames else ()

        # the tops of the buckets
        self._bucket_bounds = [float(b) for b in buckets]
        if self._bucket_bounds != sorted(self._bucket_bounds):
            raise ValueError("Buckets not in sorted order")

        if self._bucket_bounds[-1] != float("inf"):
            self._bucket_bounds.append(float("inf"))

        # We initially set this to None. We won't report metrics until
        # this has been initialised after a successful data update
        self._metric: Optional[GaugeHistogramMetricFamilyWithLabels] = None

        registry.register(self)

    def collect(self) -> Iterable[Metric]:
        # Don't report metrics unless we've already collected some data
        if self._metric is not None:
            yield self._metric

    def update_data(self, values: Iterable[float], labels: StrSequence = ()) -> None:
        """Update the data to be reported by the metric

        The existing data is cleared, and each measurement in the input is assigned
        to the relevant bucket.

        Args:
            values
            labels
        """
        self._metric = self._values_to_metric(values, labels)

    def _values_to_metric(
        self, values: Iterable[float], labels: StrSequence = ()
    ) -> GaugeHistogramMetricFamilyWithLabels:
        """
        Args:
            values
            labels
        """
        total = 0.0
        bucket_values = [0 for _ in self._bucket_bounds]

        for v in values:
            # assign each value to a bucket
            for i, bound in enumerate(self._bucket_bounds):
                if v <= bound:
                    bucket_values[i] += 1
                    break

            # ... and increment the sum
            total += v

        # now, aggregate the bucket values so that they count the number of entries in
        # that bucket or below.
        accumulated_values = itertools.accumulate(bucket_values)

        # The decision to add `SERVER_NAME_LABEL` is from the `GaugeBucketCollector`
        # usage itself (we don't enforce it here, one level up).
        return GaugeHistogramMetricFamilyWithLabels(  # type: ignore[missing-server-name-label]
            name=self._name,
            documentation=self._documentation,
            labelnames=self._labelnames,
            labelvalues=labels,
            buckets=list(
                zip((str(b) for b in self._bucket_bounds), accumulated_values)
            ),
            gsum_value=total,
        )


#
# Detailed CPU metrics
#


class CPUMetrics(Collector):
    def __init__(self) -> None:
        ticks_per_sec = 100
        try:
            # Try and get the system config
            ticks_per_sec = os.sysconf("SC_CLK_TCK")
        except (ValueError, TypeError, AttributeError):
            pass

        self.ticks_per_sec = ticks_per_sec

    def collect(self) -> Iterable[Metric]:
        if not HAVE_PROC_SELF_STAT:
            return

        with open("/proc/self/stat") as s:
            line = s.read()
            raw_stats = line.split(") ", 1)[1].split(" ")

            # This is a process-level metric, so it does not have the `SERVER_NAME_LABEL`.
            user = GaugeMetricFamily("process_cpu_user_seconds_total", "")  # type: ignore[missing-server-name-label]
            user.add_metric([], float(raw_stats[11]) / self.ticks_per_sec)
            yield user

            # This is a process-level metric, so it does not have the `SERVER_NAME_LABEL`.
            sys = GaugeMetricFamily("process_cpu_system_seconds_total", "")  # type: ignore[missing-server-name-label]
            sys.add_metric([], float(raw_stats[12]) / self.ticks_per_sec)
            yield sys


# This is a process-level metric, so it does not have the `SERVER_NAME_LABEL`.
REGISTRY.register(CPUMetrics())  # type: ignore[missing-server-name-label]


#
# Federation Metrics
#

sent_transactions_counter = SynapseCounter(
    "synapse_federation_client_sent_transactions", "", labelnames=[SERVER_NAME_LABEL]
)

events_processed_counter = SynapseCounter(
    "synapse_federation_client_events_processed", "", labelnames=[SERVER_NAME_LABEL]
)

event_processing_loop_counter = SynapseCounter(
    "synapse_event_processing_loop_count",
    "Event processing loop iterations",
    labelnames=["name", SERVER_NAME_LABEL],
)

event_processing_loop_room_count = SynapseCounter(
    "synapse_event_processing_loop_room_count",
    "Rooms seen per event processing loop iteration",
    labelnames=["name", SERVER_NAME_LABEL],
)


# Used to track where various components have processed in the event stream,
# e.g. federation sending, appservice sending, etc.
event_processing_positions = SynapseGauge(
    "synapse_event_processing_positions", "", labelnames=["name", SERVER_NAME_LABEL]
)

# Used to track the current max events stream position
event_persisted_position = SynapseGauge(
    "synapse_event_persisted_position", "", labelnames=[SERVER_NAME_LABEL]
)

# Used to track the received_ts of the last event processed by various
# components
event_processing_last_ts = SynapseGauge(
    "synapse_event_processing_last_ts", "", labelnames=["name", SERVER_NAME_LABEL]
)

# Used to track the lag processing events. This is the time difference
# between the last processed event's received_ts and the time it was
# finished being processed.
event_processing_lag = SynapseGauge(
    "synapse_event_processing_lag", "", labelnames=["name", SERVER_NAME_LABEL]
)

event_processing_lag_by_event = SynapseHistogram(
    "synapse_event_processing_lag_by_event",
    "Time between an event being persisted and it being queued up to be sent to the relevant remote servers",
    labelnames=["name", SERVER_NAME_LABEL],
)

# Build info of the running server.
#
# This is a process-level metric, so it does not have the `SERVER_NAME_LABEL`. We
# consider this process-level because all Synapse homeservers running in the process
# will use the same Synapse version.
build_info = SynapseGauge(
    "synapse_build_info", "Build information", ["pythonversion", "version", "osversion"]
)
build_info.labels(
    " ".join([platform.python_implementation(), platform.python_version()]),
    SYNAPSE_VERSION,
    " ".join([platform.system(), platform.release()]),
).set(1)

# Loaded modules info
module_instances_info = SynapseGauge(
    "synapse_module_info",
    "Information about loaded modules",
    labelnames=["package_name", "module_name", "module_version", SERVER_NAME_LABEL],
)

# 3PID send info
threepid_send_requests = SynapseHistogram(
    "synapse_threepid_send_requests_with_tries",
    documentation="Number of requests for a 3pid token by try count. Note if"
    " there is a request with try count of 4, then there would have been one"
    " each for 1, 2 and 3",
    buckets=(1, 2, 3, 4, 5, 10),
    labelnames=("type", "reason", SERVER_NAME_LABEL),
)

threadpool_total_threads = SynapseGauge(
    "synapse_threadpool_total_threads",
    "Total number of threads currently in the threadpool",
    labelnames=["name", SERVER_NAME_LABEL],
)

threadpool_total_working_threads = SynapseGauge(
    "synapse_threadpool_working_threads",
    "Number of threads currently working in the threadpool",
    labelnames=["name", SERVER_NAME_LABEL],
)

threadpool_total_min_threads = SynapseGauge(
    "synapse_threadpool_min_threads",
    "Minimum number of threads configured in the threadpool",
    labelnames=["name", SERVER_NAME_LABEL],
)

threadpool_total_max_threads = SynapseGauge(
    "synapse_threadpool_max_threads",
    "Maximum number of threads configured in the threadpool",
    labelnames=["name", SERVER_NAME_LABEL],
)

# Gauges for room counts
known_rooms_gauge = SynapseGauge(
    "synapse_known_rooms_total",
    "Total number of rooms",
    labelnames=[SERVER_NAME_LABEL],
)

locally_joined_rooms_gauge = SynapseGauge(
    "synapse_locally_joined_rooms_total",
    "Total number of locally joined rooms",
    labelnames=[SERVER_NAME_LABEL],
)


def register_threadpool(*, name: str, server_name: str, threadpool: ThreadPool) -> None:
    """
    Add metrics for the threadpool.

    Args:
        name: The name of the threadpool, used to identify it in the metrics.
        server_name: The homeserver name (used to label metrics) (this should be `hs.hostname`).
        threadpool: The threadpool to register metrics for.
    """

    threadpool_total_min_threads.labels(
        name=name, **{SERVER_NAME_LABEL: server_name}
    ).set(threadpool.min)
    threadpool_total_max_threads.labels(
        name=name, **{SERVER_NAME_LABEL: server_name}
    ).set(threadpool.max)

    threadpool_total_threads.labels(
        name=name, **{SERVER_NAME_LABEL: server_name}
    ).set_function(lambda: len(threadpool.threads))
    threadpool_total_working_threads.labels(
        name=name, **{SERVER_NAME_LABEL: server_name}
    ).set_function(lambda: len(threadpool.working))


class MetricsResource(Resource):
    """
    Twisted ``Resource`` that serves prometheus metrics.
    """

    isLeaf = True

    def __init__(self, registry: CollectorRegistry = REGISTRY):
        self.registry = registry

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b"Content-Type", CONTENT_TYPE_LATEST.encode("ascii"))
        response = generate_latest(self.registry)
        request.setHeader(b"Content-Length", str(len(response)))
        return response


__all__ = [
    "Collector",
    "MetricsResource",
    "generate_latest",
    "LaterGauge",
    "InFlightGauge",
    "GaugeBucketCollector",
    "MIN_TIME_BETWEEN_GCS",
    "install_gc_manager",
    "SynapseCounter",
    "SynapseGauge",
    "SynapseHistogram",
]
