#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import calendar
import logging
import time
from typing import TYPE_CHECKING, cast

from synapse.metrics import SERVER_NAME_LABEL, GaugeBucketCollector
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.metrics.common_usage_metrics import UserMetrics
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.event_push_actions import (
    EventPushActionsWorkerStore,
)
from synapse.util.duration import Duration

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# Collect metrics on the number of forward extremities that exist.
_extremities_collecter = GaugeBucketCollector(
    name="synapse_forward_extremities",
    documentation="Number of rooms on the server with the given number of forward extremities"
    " or fewer",
    labelnames=[SERVER_NAME_LABEL],
    buckets=[1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500],
)

# we also expose metrics on the "number of excess extremity events", which is
# (E-1)*N, where E is the number of extremities and N is the number of state
# events in the room. This is an approximation to the number of state events
# we could remove from state resolution by reducing the graph to a single
# forward extremity.
_excess_state_events_collecter = GaugeBucketCollector(
    name="synapse_excess_extremity_events",
    documentation="Number of rooms on the server with the given number of excess extremity "
    "events, or fewer",
    labelnames=[SERVER_NAME_LABEL],
    buckets=[0] + [1 << n for n in range(12)],
)


class ServerMetricsStore(EventPushActionsWorkerStore, SQLBaseStore):
    """Functions to pull various metrics from the DB, for e.g. phone home
    stats and prometheus metrics.
    """

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Read the extrems every 60 minutes
        if hs.config.worker.run_background_tasks:
            self.clock.looping_call(self._read_forward_extremities, Duration(hours=1))

        # Used in _generate_user_daily_visits to keep track of progress
        self._last_user_visit_update = self._get_start_of_day()

    @wrap_as_background_process("read_forward_extremities")
    async def _read_forward_extremities(self) -> None:
        def fetch(txn: LoggingTransaction) -> list[tuple[int, int]]:
            txn.execute(
                """
                SELECT t1.c, t2.c
                FROM (
                    SELECT room_id, COUNT(*) c FROM event_forward_extremities
                    GROUP BY room_id
                ) t1 LEFT JOIN (
                    SELECT room_id, COUNT(*) c FROM current_state_events
                    GROUP BY room_id
                ) t2 ON t1.room_id = t2.room_id
                """
            )
            return cast(list[tuple[int, int]], txn.fetchall())

        res = await self.db_pool.runInteraction("read_forward_extremities", fetch)

        _extremities_collecter.update_data(
            values=(x[0] for x in res), labels=(self.server_name,)
        )

        _excess_state_events_collecter.update_data(
            values=((x[0] - 1) * x[1] for x in res if x[1]), labels=(self.server_name,)
        )

    async def count_daily_e2ee_messages(self) -> int:
        """
        Returns an estimate of the number of messages sent in the last day.

        If it has been significantly less or more than one day since the last
        call to this function, it will return None.
        """

        def _count_messages(txn: LoggingTransaction) -> int:
            sql = """
                SELECT COUNT(*) FROM events
                WHERE type = 'm.room.encrypted'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = cast(tuple[int], txn.fetchone())
            return count

        return await self.db_pool.runInteraction("count_e2ee_messages", _count_messages)

    async def count_daily_sent_e2ee_messages(self) -> int:
        def _count_messages(txn: LoggingTransaction) -> int:
            # This is good enough as if you have silly characters in your own
            # hostname then that's your own fault.
            like_clause = "%:" + self.hs.hostname

            sql = """
                SELECT COUNT(*) FROM events
                WHERE type = 'm.room.encrypted'
                    AND sender LIKE ?
                AND stream_ordering > ?
            """

            txn.execute(sql, (like_clause, self.stream_ordering_day_ago))
            (count,) = cast(tuple[int], txn.fetchone())
            return count

        return await self.db_pool.runInteraction(
            "count_daily_sent_e2ee_messages", _count_messages
        )

    async def count_daily_active_e2ee_rooms(self) -> int:
        def _count(txn: LoggingTransaction) -> int:
            sql = """
                SELECT COUNT(DISTINCT room_id) FROM events
                WHERE type = 'm.room.encrypted'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = cast(tuple[int], txn.fetchone())
            return count

        return await self.db_pool.runInteraction(
            "count_daily_active_e2ee_rooms", _count
        )

    async def count_daily_messages(self) -> int:
        """
        Returns an estimate of the number of messages sent in the last day.

        If it has been significantly less or more than one day since the last
        call to this function, it will return None.
        """

        def _count_messages(txn: LoggingTransaction) -> int:
            sql = """
                SELECT COUNT(*) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = cast(tuple[int], txn.fetchone())
            return count

        return await self.db_pool.runInteraction("count_messages", _count_messages)

    async def count_daily_sent_messages(self) -> int:
        def _count_messages(txn: LoggingTransaction) -> int:
            # This is good enough as if you have silly characters in your own
            # hostname then that's your own fault.
            like_clause = "%:" + self.hs.hostname

            sql = """
                SELECT COUNT(*) FROM events
                WHERE type = 'm.room.message'
                    AND sender LIKE ?
                AND stream_ordering > ?
            """

            txn.execute(sql, (like_clause, self.stream_ordering_day_ago))
            (count,) = cast(tuple[int], txn.fetchone())
            return count

        return await self.db_pool.runInteraction(
            "count_daily_sent_messages", _count_messages
        )

    async def count_daily_active_rooms(self) -> int:
        def _count(txn: LoggingTransaction) -> int:
            sql = """
                SELECT COUNT(DISTINCT room_id) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = cast(tuple[int], txn.fetchone())
            return count

        return await self.db_pool.runInteraction("count_daily_active_rooms", _count)

    async def count_daily_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 24 hours.
        """
        yesterday = int(self.clock.time_msec()) - (1000 * 60 * 60 * 24)
        return await self.db_pool.runInteraction(
            "count_daily_users", self._count_users, yesterday
        )

    async def count_weekly_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 7 days.
        """
        seven_days_ago = int(self.clock.time_msec()) - (1000 * 60 * 60 * 24 * 7)
        return await self.db_pool.runInteraction(
            "count_weekly_users", self._count_users, seven_days_ago
        )

    async def count_monthly_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 30 days.
        Note this method is intended for phonehome metrics only and is different
        from the mau figure in synapse.storage.monthly_active_users which,
        amongst other things, includes a 3 day grace period before a user counts.
        """
        thirty_days_ago = int(self.clock.time_msec()) - (1000 * 60 * 60 * 24 * 30)
        return await self.db_pool.runInteraction(
            "count_monthly_users", self._count_users, thirty_days_ago
        )

    def _count_users(self, txn: LoggingTransaction, time_from: int) -> int:
        """
        Returns number of users seen in the past time_from period
        """
        exclude_list = [
            "@" + localpart + ":" + self.hs.config.server.server_name
            for localpart in self.hs.config.metrics.report_stats_exclude_alias_list
        ]

        if not exclude_list:
            sql = """
                SELECT COUNT(*) FROM (
                    SELECT user_id FROM user_ips
                    WHERE last_seen > ?
                    GROUP BY user_id
                ) u
            """
            txn.execute(sql, (time_from,))
        else:
            sql = """
                SELECT COUNT(*) FROM (
                    SELECT user_id FROM user_ips
                    WHERE last_seen > ? AND user_id NOT IN ?
                    GROUP BY user_id
                ) u
            """
            txn.execute(sql, (time_from, tuple(exclude_list)))

        # We know better: "SELECT COUNT(...) FROM ..." without any GROUP BY always
        # returns exactly one row.
        (count,) = cast(tuple[int], txn.fetchone())
        return count

    async def count_r30v2_users(self) -> dict[str, int]:
        """
        Counts the number of 30 day retained users, defined as users that:
         - Appear more than once in the past 60 days
         - Have more than 30 days between the most and least recent appearances that
           occurred in the past 60 days.

        (This is the second version of this metric, hence R30'v2')

        Returns:
             A mapping from client type to the number of 30-day retained users for that client.

             The dict keys are:
              - "all" (a combined number of users across any and all clients)
              - "element_android" (Element Android)
              - "element_ios" (Element iOS)
              - "element_electron" (Element Desktop)
              - "web" (any web application -- it's not possible to distinguish Element Web here)
              - "famedly_android" (Famedly Android)
              - "famedly_ios" (Famedly iOS)
              - "unknown_android" (Android clients that are neither Element nor Famedly)
              - "unknown_ios" (iOS clients that are neither Element nor Famedly)
              - "unknown" (any other client)
        """

        def _count_r30v2_users(txn: LoggingTransaction) -> dict[str, int]:
            thirty_days_in_secs = 86400 * 30
            now = int(self.clock.time())
            sixty_days_ago_in_secs = now - 2 * thirty_days_in_secs
            one_day_from_now_in_secs = now + 86400

            # Single scan of user_daily_visits: lower the user-agent once, then
            # derive both per-client and overall R30v2 counts from that set.
            #
            # Classification order matters:
            # 1. Branded native clients (Famedly / Element-Riot)
            # 2. Web browsers (mozilla/gecko) — before bare android/ios, because
            #    mobile browser user agents also contain those platform tokens
            # 3. Unbranded android/ios native clients
            # 4. unknown
            sql = """
                -- `last_60_days_visits`: selects rows within 60 days and normalizes
                -- the user_agent to lowercase as `ua`.
                WITH last_60_days_visits AS (
                    SELECT
                        user_id,
                        timestamp,
                        LOWER(COALESCE(user_agent, '')) AS ua
                    FROM
                        user_daily_visits
                    WHERE
                        timestamp > ?
                        AND
                        timestamp < ?
                ),
                -- `last_60_days_classified`: map user_agent to client type from `last_60_days_visits`.
                last_60_days_classified AS (
                    SELECT
                        user_id,
                        timestamp,
                        CASE
                            WHEN ua LIKE '%%famedly%%'
                                THEN CASE
                                    WHEN ua LIKE '%%android%%' THEN 'famedly_android'
                                    WHEN ua LIKE '%%ios%%' THEN 'famedly_ios'
                                    ELSE 'unknown'
                                END
                            WHEN (ua LIKE '%%element%%' OR ua LIKE '%%riot%%')
                                THEN CASE
                                    WHEN ua LIKE '%%electron%%' THEN 'element_electron'
                                    WHEN ua LIKE '%%android%%' THEN 'element_android'
                                    WHEN ua LIKE '%%ios%%' THEN 'element_ios'
                                    ELSE 'unknown'
                                END
                            WHEN
                                ua LIKE '%%mozilla%%' OR ua LIKE '%%gecko%%' THEN 'web'
                            WHEN
                                ua LIKE '%%android%%' THEN 'unknown_android'
                            WHEN
                                ua LIKE '%%ios%%' THEN 'unknown_ios'
                            ELSE 'unknown'
                        END AS client_type
                    FROM
                        last_60_days_visits
                )
                -- get counts per client type from `last_60_days_classified` for users
                -- who have been active for more than 30 days in the last 60 days.
                SELECT
                    client_type,
                    COUNT(*)
                FROM (
                    SELECT
                        user_id,
                        client_type
                    FROM
                        last_60_days_classified
                    GROUP BY
                        user_id,
                        client_type
                    HAVING
                        MAX(timestamp) - MIN(timestamp) > ?
                ) AS retained_by_client
                GROUP BY
                    client_type

                UNION ALL
                -- get count of all users from `last_60_days_visits` who have been
                -- active for more than 30 days in the last 60 days.
                SELECT
                    'all',
                    COUNT(*)
                FROM (
                    SELECT
                        user_id
                    FROM
                        last_60_days_visits
                    GROUP BY
                        user_id
                    HAVING
                        MAX(timestamp) - MIN(timestamp) > ?
                ) AS retained_all
            """

            # We initialise all the client types to zero, so we get an explicit
            # zero if they don't appear in the query results
            results = {
                "element_electron": 0,
                "element_android": 0,
                "element_ios": 0,
                "famedly_android": 0,
                "famedly_ios": 0,
                "unknown_android": 0,
                "unknown_ios": 0,
                "web": 0,
                "unknown": 0,
                "all": 0,
            }
            txn.execute(
                sql,
                (
                    sixty_days_ago_in_secs * 1000,
                    one_day_from_now_in_secs * 1000,
                    thirty_days_in_secs * 1000,
                    thirty_days_in_secs * 1000,
                ),
            )

            for row in txn:
                results[row[0]] = row[1]

            return results

        return await self.db_pool.runInteraction(
            "count_r30v2_users", _count_r30v2_users
        )

    def _get_start_of_day(self) -> int:
        """
        Returns millisecond unixtime for start of UTC day.
        """
        now = time.gmtime(self.clock.time())
        today_start = calendar.timegm((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0))
        return today_start * 1000

    @wrap_as_background_process("generate_user_daily_visits")
    async def generate_user_daily_visits(self) -> None:
        """
        Generates daily visit data for use in cohort/ retention analysis
        """

        def _generate_user_daily_visits(txn: LoggingTransaction) -> None:
            logger.info("Calling _generate_user_daily_visits")
            today_start = self._get_start_of_day()
            a_day_in_milliseconds = 24 * 60 * 60 * 1000
            now = self.clock.time_msec()

            # A note on user_agent. Technically a given device can have multiple
            # user agents, so we need to decide which one to pick. We could have
            # handled this in number of ways, but given that we don't care
            # _that_ much we have gone for MAX(). For more details of the other
            # options considered see
            # https://github.com/matrix-org/synapse/pull/8503#discussion_r502306111
            sql = """
                INSERT INTO user_daily_visits (user_id, device_id, timestamp, user_agent)
                    SELECT u.user_id, u.device_id, ?, MAX(u.user_agent)
                    FROM user_ips AS u
                    LEFT JOIN (
                      SELECT user_id, device_id, timestamp FROM user_daily_visits
                      WHERE timestamp = ?
                    ) udv
                    ON u.user_id = udv.user_id AND u.device_id=udv.device_id
                    INNER JOIN users ON users.name=u.user_id
                    WHERE ? <= last_seen AND last_seen < ?
                    AND udv.timestamp IS NULL AND users.is_guest=0
                    AND users.appservice_id IS NULL
                    GROUP BY u.user_id, u.device_id
            """

            # This means that the day has rolled over but there could still
            # be entries from the previous day. There is an edge case
            # where if the user logs in at 23:59 and overwrites their
            # last_seen at 00:01 then they will not be counted in the
            # previous day's stats - it is important that the query is run
            # often to minimise this case.
            if today_start > self._last_user_visit_update:
                yesterday_start = today_start - a_day_in_milliseconds
                txn.execute(
                    sql,
                    (
                        yesterday_start,
                        yesterday_start,
                        self._last_user_visit_update,
                        today_start,
                    ),
                )
                self._last_user_visit_update = today_start

            txn.execute(
                sql, (today_start, today_start, self._last_user_visit_update, now)
            )
            # Update _last_user_visit_update to now. The reason to do this
            # rather just clamping to the beginning of the day is to limit
            # the size of the join - meaning that the query can be run more
            # frequently
            self._last_user_visit_update = now

        await self.db_pool.runInteraction(
            "generate_user_daily_visits", _generate_user_daily_visits
        )

    async def get_user_count_per_status(self) -> UserMetrics:
        def _get_user_count_per_status(txn: LoggingTransaction) -> UserMetrics:
            metrics = UserMetrics()
            sql = """
                SELECT
                    SUM(CASE WHEN deactivated = 0 AND locked = FALSE AND suspended = FALSE THEN 1 ELSE 0 END) AS active_users,
                    SUM(CASE WHEN deactivated = 1 THEN 1 ELSE 0 END) AS deactivated_users,
                    SUM(CASE WHEN suspended = TRUE THEN 1 ELSE 0 END) AS suspended_users,
                    SUM(CASE WHEN locked = TRUE THEN 1 ELSE 0 END) AS locked_users
                FROM users;
            """
            txn.execute(sql)
            (active, deactivated, suspended, locked) = cast(
                tuple[int, int, int, int], txn.fetchone()
            )
            if active:
                metrics.active = active
            if deactivated:
                metrics.deactivated = deactivated
            if suspended:
                metrics.suspended = suspended
            if locked:
                metrics.locked = locked

            sql = """
                SELECT COUNT(*)
                FROM (
                    SELECT user_id
                    FROM user_daily_visits
                    WHERE timestamp > ? AND timestamp < ?
                    GROUP BY user_id
                    HAVING max(timestamp) - min(timestamp) > ?
                ) AS r30_users;
            """
            thirty_days_in_ms = 86400 * 30 * 1000
            now_ms = int(self.clock.time()) * 1000
            sixty_days_ago_in_ms = now_ms - 2 * thirty_days_in_ms
            one_day_from_now_in_ms = now_ms + (86400 * 1000)
            txn.execute(
                sql,
                (
                    sixty_days_ago_in_ms,
                    one_day_from_now_in_ms,
                    thirty_days_in_ms,
                ),
            )
            (count,) = cast(tuple[int], txn.fetchone())
            if not count:
                logger.info("No retained user found. Setting it to 0")
            if count:
                metrics.retained_30d = count
            return metrics

        return await self.db_pool.runInteraction(
            "get_user_count_per_status", _get_user_count_per_status
        )
