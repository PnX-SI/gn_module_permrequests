from datetime import date

from enum import Enum

from sqlalchemy import and_, or_, case, true

from geonature.utils.env import db


class Status(str, Enum):
    REFUSED = "REFUSED"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    EXPIRED = "EXPIRED"
    UPCOMING = "UPCOMING"
    ACTIVE = "ACTIVE"


STATUS_ORDER = [
    Status.PENDING,
    Status.IN_PROGRESS,
    Status.UPCOMING,
    Status.ACTIVE,
    Status.EXPIRED,
    Status.REFUSED,
]
STATUS_ORDER_INDEX = {key: index + 1 for index, key in enumerate(STATUS_ORDER)}


def compute_status(validated, created_on, expiration_date, id_validator=None, today=None):
    today = today or date.today()

    if validated is False:
        return Status.REFUSED
    if validated is None:
        if id_validator is not None:
            return Status.IN_PROGRESS
        return Status.PENDING

    # validated is True
    if expiration_date is not None and expiration_date < today:
        return Status.EXPIRED
    if created_on is not None and created_on > today:
        return Status.UPCOMING
    return Status.ACTIVE


def status_order_case(
    validated_column,
    created_on_column,
    expiration_column,
    id_validator_column,
    current_date=None,
):
    current_date = current_date or db.func.current_date()

    return case(
        (validated_column.is_(False), STATUS_ORDER_INDEX[Status.REFUSED]),
        (
            and_(validated_column.is_(None), id_validator_column.is_not(None)),
            STATUS_ORDER_INDEX[Status.IN_PROGRESS],
        ),
        (validated_column.is_(None), STATUS_ORDER_INDEX[Status.PENDING]),
        (
            and_(validated_column.is_(True), expiration_column < current_date),
            STATUS_ORDER_INDEX[Status.EXPIRED],
        ),
        (
            and_(validated_column.is_(True), created_on_column > current_date),
            STATUS_ORDER_INDEX[Status.UPCOMING],
        ),
        else_=STATUS_ORDER_INDEX[Status.ACTIVE],
    )


def status_filter_expression(
    status,
    *,
    validated_column,
    created_on_column,
    expiration_column,
    id_validator_column,
):
    current_date = db.func.current_date()
    if status == Status.REFUSED:
        return validated_column.is_(False)
    if status == Status.PENDING:
        return and_(validated_column.is_(None), id_validator_column.is_(None))
    if status == Status.IN_PROGRESS:
        return and_(validated_column.is_(None), id_validator_column.is_not(None))
    if status == Status.EXPIRED:
        return and_(validated_column.is_(True), expiration_column < current_date)
    if status == Status.UPCOMING:
        return and_(validated_column.is_(True), created_on_column > current_date)
    if status == Status.ACTIVE:
        return and_(
            validated_column.is_(True),
            or_(expiration_column.is_(None), expiration_column >= current_date),
            or_(created_on_column.is_(None), created_on_column <= current_date),
        )
    return true()
