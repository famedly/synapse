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
Re-exports ``Counter``, ``Gauge`` and ``Histogram`` from the appropriate
backend.

When the environment variable ``SYNAPSE_METRICS_BACKEND`` is set to ``otlp``,
the classes come from :mod:`synapse.metrics._otel` and measurements are
exported via OTLP (configured through the standard ``OTEL_*`` environment
variables).

Otherwise the classes are the stock ``prometheus_client`` implementations and
metrics are exposed on the Prometheus scrape endpoint as usual.
"""

import os

METRICS_BACKEND = os.environ.get("SYNAPSE_METRICS_BACKEND", "prometheus").lower()

if METRICS_BACKEND == "otlp":
    try:
        from synapse.metrics._otel import (
            REGISTRY,
            CollectorRegistry,
            Counter,
            Gauge,
            Histogram,
        )  # noqa: F401
    except ImportError:
        raise ImportError(
            "SYNAPSE_METRICS_BACKEND is set to 'otlp' but the required "
            "OpenTelemetry packages are not installed. "
            "Install them with:  pip install matrix-synapse[opentelemetry-metrics]"
        )
else:
    from prometheus_client import (  # noqa: F401
        REGISTRY,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
    )

__all__ = [
    "Counter",
    "Gauge",
    "Histogram",
    "CollectorRegistry",
    "REGISTRY",
    "METRICS_BACKEND",
]
