# Copyright 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import Any, Optional

from synapse.config._base import Config
from synapse.config._util import validate_config
from synapse.types import JsonDict


class FederationConfig(Config):
    section = "federation"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        # FIXME: federation_domain_whitelist needs sytests
        self.federation_domain_whitelist: Optional[dict] = None
        federation_domain_whitelist = config.get("federation_domain_whitelist", None)

        if federation_domain_whitelist is not None:
            # turn the whitelist into a hash for speed of lookup
            self.federation_domain_whitelist = {}

            for domain in federation_domain_whitelist:
                self.federation_domain_whitelist[domain] = True

        federation_metrics_domains = config.get("federation_metrics_domains") or []
        validate_config(
            _METRICS_FOR_DOMAINS_SCHEMA,
            federation_metrics_domains,
            ("federation_metrics_domains",),
        )
        self.federation_metrics_domains = set(federation_metrics_domains)

        self.allow_profile_lookup_over_federation = config.get(
            "allow_profile_lookup_over_federation", True
        )

        self.allow_device_name_lookup_over_federation = config.get(
            "allow_device_name_lookup_over_federation", False
        )

        # Configuration for the automatic retries of federation transactions. It starts at the minimum and is multiplied
        # every retry by the multiplier. It is retried for the configured count and each individual retry interval can
        # not exceed the maximum individual interval configured.
        self.federation_transaction_retry_minimum_interval_seconds = config.get(
            "federation_transaction_retry_minimum_interval_seconds", 4.0
        )
        if self.federation_transaction_retry_minimum_interval_seconds < 1:
            self.federation_transaction_retry_minimum_interval_seconds = 1

        self.federation_transaction_retry_multiplier = config.get(
            "federation_transaction_retry_multiplier", 4.0
        )
        if self.federation_transaction_retry_multiplier < 1.5:
            self.federation_transaction_retry_multiplier = 1.5

        self.federation_transaction_retry_maximum_individual_interval_seconds = (
            config.get(
                "federation_transaction_retry_maximum_individual_interval_seconds", 60.0
            )
        )
        if self.federation_transaction_retry_maximum_individual_interval_seconds < 10.0:
            self.federation_transaction_retry_maximum_individual_interval_seconds = 10.0

        self.federation_transaction_retry_count = config.get(
            "federation_transaction_retry_count", 10
        )
        if self.federation_transaction_retry_count < 3:
            self.federation_transaction_retry_count = 3
        if self.federation_transaction_retry_count > 20:
            self.federation_transaction_retry_count = 20

        minimum_backoff = sum(
            [
                min(
                    (
                        self.federation_transaction_retry_minimum_interval_seconds
                        * (self.federation_transaction_retry_multiplier**x)
                    ),
                    self.federation_transaction_retry_maximum_individual_interval_seconds,
                )
                for x in range(self.federation_transaction_retry_count)
            ]
        )

        # The backoff starts after the retries have been exceeded. As such the minimum interval for that should not be
        # lower than the accumulated intervals for the retries. Additionally requests are retried forever. You can still
        # limit the maximum interval of each retry as well as change the minimum interval and multiplier.
        self.federation_destination_backoff_minimum_interval_seconds = config.get(
            "federation_destination_backoff_minimum_interval_seconds", 10.0 * 60
        )
        if (
            self.federation_destination_backoff_minimum_interval_seconds
            < minimum_backoff
        ):
            self.federation_destination_backoff_minimum_interval_seconds = (
                minimum_backoff
            )

        self.federation_destination_backoff_multiplier = config.get(
            "federation_destination_backoff_multiplier", 5.0
        )
        if self.federation_destination_backoff_multiplier < 2.0:
            self.federation_destination_backoff_multiplier = 2.0

        self.federation_destination_backoff_maximum_individual_interval_seconds = (
            config.get(
                "federation_destination_backoff_maximum_individual_interval_seconds",
                2**62,
            )
        )
        if (
            self.federation_destination_backoff_maximum_individual_interval_seconds
            < self.federation_destination_backoff_minimum_interval_seconds
        ):
            self.federation_destination_backoff_maximum_individual_interval_seconds = (
                self.federation_destination_backoff_minimum_interval_seconds
            )


_METRICS_FOR_DOMAINS_SCHEMA = {"type": "array", "items": {"type": "string"}}
