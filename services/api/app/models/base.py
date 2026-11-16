from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Dialect, MetaData
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import TypeDecorator

# JSONB on PostgreSQL; plain JSON elsewhere so the test suite can run on SQLite.
JsonType = JSON().with_variant(JSONB(), "postgresql")


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware timestamps on every backend.

    SQLite (used by the test suite) drops the offset; values are always stored in
    UTC, so it is reattached on the way out.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {
        datetime: UtcDateTime(),
        dict[str, Any]: JsonType,
        list[Any]: JsonType,
    }


def utcnow() -> datetime:
    return datetime.now(UTC)
