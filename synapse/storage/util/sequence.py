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
import abc
import logging
import threading
from typing import TYPE_CHECKING, Callable

from synapse.storage.engines import (
    BaseDatabaseEngine,
    IncorrectDatabaseSetup,
    PostgresEngine,
)
from synapse.storage.types import Connection, Cursor

if TYPE_CHECKING:
    from synapse.storage.database import LoggingDatabaseConnection

logger = logging.getLogger(__name__)


_INCONSISTENT_STREAM_ERROR = """
Postgres sequence '%(seq)s' is inconsistent with associated stream position
of '%(stream_name)s' in the 'stream_positions' table.

This is likely a programming error and should be reported at
https://github.com/element-hq/synapse. Please include the following data with
your report:
-----
last_value: '%(last_value)s',    is_called: '%(is_called)s',
max_stream_id: '%(max_stream_id)s',
max_in_stream_positions: '%(max_in_stream_positions)s'
-----

A temporary workaround to fix this error is to shut down Synapse (including
any and all workers) and run the following SQL:

    DELETE FROM stream_positions WHERE stream_name = '%(stream_name)s';

This will need to be done every time the server is restarted.
"""


class SequenceGenerator(metaclass=abc.ABCMeta):
    """A class which generates a unique sequence of integers"""

    @abc.abstractmethod
    def get_next_id_txn(self, txn: Cursor) -> int:
        """Gets the next ID in the sequence"""
        ...

    @abc.abstractmethod
    def get_next_mult_txn(self, txn: Cursor, n: int) -> list[int]:
        """Get the next `n` IDs in the sequence"""
        ...

    @abc.abstractmethod
    def check_consistency(
        self,
        db_conn: "LoggingDatabaseConnection",
        table: str,
        id_column: str,
        stream_name: str | None = None,
        positive: bool = True,
    ) -> None:
        """Should be called during start up to test that the current value of
        the sequence is greater than or equal to the maximum ID in the table.

        This is to handle various cases where the sequence value can get out of
        sync with the table, e.g. if Synapse gets rolled back to a previous
        version and the rolled forwards again.

        If a stream name is given then this will check that any value in the
        `stream_positions` table is less than or equal to the current sequence
        value. If it isn't then it's likely that streams have been crossed
        somewhere (e.g. two ID generators have the same stream name).
        """
        ...

    @abc.abstractmethod
    def get_max_allocated(self, txn: Cursor) -> int:
        """Get the maximum ID that we have allocated"""


class PostgresSequenceGenerator(SequenceGenerator):
    """An implementation of SequenceGenerator which uses a postgres sequence"""

    def __init__(self, sequence_name: str):
        self._sequence_name = sequence_name

    def get_next_id_txn(self, txn: Cursor) -> int:
        txn.execute("SELECT nextval(?)", (self._sequence_name,))
        fetch_res = txn.fetchone()
        assert fetch_res is not None
        return fetch_res[0]

    def get_next_mult_txn(self, txn: Cursor, n: int) -> list[int]:
        txn.execute(
            "SELECT nextval(?) FROM generate_series(1, ?)", (self._sequence_name, n)
        )
        return [i for (i,) in txn]

    def check_consistency(
        self,
        db_conn: "LoggingDatabaseConnection",
        table: str,
        id_column: str,
        stream_name: str | None = None,
        positive: bool = True,
    ) -> None:
        """See SequenceGenerator.check_consistency for docstring."""

        txn = db_conn.cursor(txn_name="sequence.check_consistency")

        # First we get the current max ID from the table.
        table_sql = "SELECT GREATEST(%(agg)s(%(id)s), 0) FROM %(table)s" % {
            "id": id_column,
            "table": table,
            "agg": "MAX" if positive else "-MIN",
        }

        txn.execute(table_sql)
        row = txn.fetchone()
        if not row:
            # Table is empty, so nothing to do.
            txn.close()
            return

        # Now we fetch the current value from the sequence and compare with the
        # above.
        max_stream_id = row[0]
        last_value = self.get_max_allocated(txn)

        # If we have an associated stream check the stream_positions table.
        max_in_stream_positions = None
        if stream_name:
            txn.execute(
                "SELECT MAX(stream_id) FROM stream_positions WHERE stream_name = ?",
                (stream_name,),
            )
            row = txn.fetchone()
            if row:
                max_in_stream_positions = row[0]

        if max_stream_id > last_value:
            # The sequence is lagging behind the tables. This is probably due to
            # rolling back to a version before the sequence was used and then forwards
            # again. We resolve this by setting the sequence to the right value.
            logger.warning(
                "Postgres sequence %s is behind table %s: %d < %d. Updating sequence.",
                self._sequence_name,
                table,
                last_value,
                max_stream_id,
            )

            # There is a potential race here. Subqueries do not guarantee atomic updates
            # so the actual sequence may have been updated between the read and the
            # write. There does not seem to be a better way.
            sql = f"""
                SELECT setval('{self._sequence_name}', GREATEST(
                    (SELECT last_value FROM pg_sequences WHERE sequencename = '{self._sequence_name}'),
                    ({table_sql})
                ));
            """
            txn.execute(sql)

        if max_stream_id < last_value and last_value > 1:
            # The sequence is ahead of the tables, and we only care when the value is
            # greater than 1. 1 begins the sequence, not 0. Advance the sequence to
            # guarantee a Postgres WAL checkpoint of the sequence in case of high
            # availability failover. Sequence gaps are allowed.
            last_value = self.get_next_id_txn(txn)

        txn.close()

        # If we have values in the stream positions table then they have to be
        # less than or equal to `last_value`
        if max_in_stream_positions and max_in_stream_positions > last_value:
            raise IncorrectDatabaseSetup(
                _INCONSISTENT_STREAM_ERROR
                % {
                    "seq": self._sequence_name,
                    "stream_name": stream_name,
                    "last_value": last_value,
                    # `is_called` here is in reference to whether the sequence has
                    # *ever* been called on. If it is 0, then it was never called.
                    "is_called": last_value > 0,
                    "max_stream_id": max_stream_id,
                    "max_in_stream_positions": max_in_stream_positions,
                }
            )

    def get_max_allocated(self, txn: Cursor) -> int:
        """
        Read from the `pq_sequences` Postgres view what the `last_value` is.

        This avoids a racy heap tuple attribute swap that is not covered by the content
        lock on the sequence database row itself.

        Returns: The int representing the maximum sequence value

        """
        # `last_value` will be `NULL` when the sequence has never been called. Since all
        # sequences for Synapse start at `1`, an uncalled sequence would imply a 0.
        # Historically, uncalled stream writer sequences have to start at 1 whereas
        # non-stream writer sequences start at 0.
        # It is unclear why this is. Observe the `get_first_callback` argument used to
        # initialize `SequenceGenerator`s for evidence, and that `max_stream_id` in
        # `check_consistency()` defaults to 0 and `MultiWriterIdGenerator` starts the
        # default at 1. Be aware that `check_consistency()` also used to use this value
        # after subtracting a 1 but that behavior was removed.
        txn.execute(
            "SELECT last_value FROM pg_sequences WHERE sequencename = ?",
            (self._sequence_name,),
        )
        row = txn.fetchone()
        assert row is not None

        last_value = row[0]
        if last_value is None:
            last_value = 1
        return last_value


GetFirstCallbackType = Callable[[Cursor], int]


class LocalSequenceGenerator(SequenceGenerator):
    """An implementation of SequenceGenerator which uses local locking

    This only works reliably if there are no other worker processes generating IDs at
    the same time.
    """

    def __init__(self, get_first_callback: GetFirstCallbackType):
        """
        Args:
            get_first_callback: a callback which is called on the first call to
                 get_next_id_txn; should return the current maximum id
        """
        # the callback. this is cleared after it is called, so that it can be GCed.
        self._callback: GetFirstCallbackType | None = get_first_callback

        # The current max value, or None if we haven't looked in the DB yet.
        self._current_max_id: int | None = None
        self._lock = threading.Lock()

    def get_next_id_txn(self, txn: Cursor) -> int:
        # We do application locking here since if we're using sqlite then
        # we are a single process synapse.
        with self._lock:
            if self._current_max_id is None:
                assert self._callback is not None
                self._current_max_id = self._callback(txn)
                self._callback = None

            self._current_max_id += 1
            return self._current_max_id

    def get_next_mult_txn(self, txn: Cursor, n: int) -> list[int]:
        with self._lock:
            if self._current_max_id is None:
                assert self._callback is not None
                self._current_max_id = self._callback(txn)
                self._callback = None

            first_id = self._current_max_id + 1
            self._current_max_id += n
            return [first_id + i for i in range(n)]

    def check_consistency(
        self,
        db_conn: Connection,
        table: str,
        id_column: str,
        stream_name: str | None = None,
        positive: bool = True,
    ) -> None:
        # There is nothing to do for in memory sequences
        pass

    def get_max_allocated(self, txn: Cursor) -> int:
        with self._lock:
            if self._current_max_id is None:
                assert self._callback is not None
                self._current_max_id = self._callback(txn)
                self._callback = None

            return self._current_max_id


def build_sequence_generator(
    db_conn: "LoggingDatabaseConnection",
    database_engine: BaseDatabaseEngine,
    get_first_callback: GetFirstCallbackType,
    sequence_name: str,
    table: str | None,
    id_column: str | None,
    stream_name: str | None = None,
    positive: bool = True,
) -> SequenceGenerator:
    """Get the best impl of SequenceGenerator available

    This uses PostgresSequenceGenerator on postgres, and a locally-locked impl on
    sqlite.

    Args:
        database_engine: the database engine we are connected to
        get_first_callback: a callback which gets the next sequence ID. Used if
            we're on sqlite.
        sequence_name: the name of a postgres sequence to use.
        table, id_column, stream_name, positive: If set then `check_consistency`
            is called on the created sequence. See docstring for
            `check_consistency` details.
    """
    if isinstance(database_engine, PostgresEngine):
        seq: SequenceGenerator = PostgresSequenceGenerator(sequence_name)
    else:
        seq = LocalSequenceGenerator(get_first_callback)

    if table:
        assert id_column
        seq.check_consistency(
            db_conn=db_conn,
            table=table,
            id_column=id_column,
            stream_name=stream_name,
            positive=positive,
        )

    return seq
