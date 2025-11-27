from datetime import date

from enum import Enum

from sqlalchemy import and_, or_, case, true

from geonature.utils.env import db


class Status(str, Enum):
    REFUSED = "REFUSED"
    PENDING = "PENDING"
    EXPIRED = "EXPIRED"
    UPCOMING = "UPCOMING"
    ACTIVE = "ACTIVE"

STATUS_ORDER = [
    Status.REFUSED,
    Status.PENDING,
    Status.EXPIRED,
    Status.UPCOMING,
    Status.ACTIVE,
]
STATUS_ORDER_INDEX = {key: index + 1 for index, key in enumerate(STATUS_ORDER)}


def compute_status(validated, initialization_date, expiration_date, today=None):
    today = today or date.today()

    if validated is False:
        return Status.REFUSED
    if validated is None:
        return Status.PENDING

    # validated is True
    if expiration_date is not None and expiration_date < today:
        return Status.EXPIRED
    if initialization_date is not None and initialization_date > today:
        return Status.UPCOMING
    return Status.ACTIVE


def status_order_case(
    validated_column, initialization_column, expiration_column, current_date=None
):
    current_date = current_date or db.func.current_date()

    return case(
        (validated_column.is_(False), STATUS_ORDER_INDEX[Status.REFUSED]),
        (validated_column.is_(None), STATUS_ORDER_INDEX[Status.PENDING]),
        (
            and_(validated_column.is_(True), expiration_column < current_date),
            STATUS_ORDER_INDEX[Status.EXPIRED],
        ),
        (
            and_(validated_column.is_(True), initialization_column > current_date),
            STATUS_ORDER_INDEX[Status.UPCOMING],
        ),
        else_=STATUS_ORDER_INDEX[Status.ACTIVE],
    )


def status_filter_expression(
    status, *, validated_column, initialization_column, expiration_column
):
    current_date = db.func.current_date()
    if status == Status.REFUSED:
        return validated_column.is_(False)
    if status == Status.PENDING:
        return validated_column.is_(None)
    if status == Status.EXPIRED:
        return and_(validated_column.is_(True), expiration_column < current_date)
    if status == Status.UPCOMING:
        return and_(validated_column.is_(True), initialization_column > current_date)
    if status == Status.ACTIVE:
        return and_(
            validated_column.is_(True),
            or_(expiration_column.is_(None), expiration_column >= current_date),
            or_(initialization_column.is_(None), initialization_column <= current_date),
        )
    return true()
