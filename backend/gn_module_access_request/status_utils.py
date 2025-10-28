from datetime import date

from enum import Enum

from sqlalchemy import and_, case

from geonature.utils.env import db


class StatusKey(str, Enum):
    REFUSED = "refused"
    PENDING = "pending"
    EXPIRED = "expired"
    UPCOMING = "upcoming"
    ACTIVE = "active"


STATUS_KEYS = {
    StatusKey.REFUSED: "Refusée",
    StatusKey.PENDING: "Non traitée",
    StatusKey.EXPIRED: "Expirée",
    StatusKey.UPCOMING: "A venir",
    StatusKey.ACTIVE: "Active",
}

STATUS_ORDER = [
    StatusKey.REFUSED,
    StatusKey.PENDING,
    StatusKey.EXPIRED,
    StatusKey.UPCOMING,
    StatusKey.ACTIVE,
]
STATUS_ORDER_INDEX = {key: index + 1 for index, key in enumerate(STATUS_ORDER)}


def compute_status_key(validated, initialization_date, expiration_date, today=None):
    today = today or date.today()

    if validated is False:
        return StatusKey.REFUSED
    if validated is None:
        return StatusKey.PENDING

    # validated is True
    if expiration_date is not None and expiration_date < today:
        return StatusKey.EXPIRED
    if initialization_date is not None and initialization_date > today:
        return StatusKey.UPCOMING
    return StatusKey.ACTIVE


def compute_status_label(validated, initialization_date, expiration_date, today=None):
    key = compute_status_key(validated, initialization_date, expiration_date, today=today)
    return STATUS_KEYS[key]


def status_order_case(validated_column, initialization_column, expiration_column, current_date=None):
    current_date = current_date or db.func.current_date()

    return case(
        (validated_column.is_(False), STATUS_ORDER_INDEX[StatusKey.REFUSED]),
        (validated_column.is_(None), STATUS_ORDER_INDEX[StatusKey.PENDING]),
        (
            and_(validated_column.is_(True), expiration_column < current_date),
            STATUS_ORDER_INDEX[StatusKey.EXPIRED],
        ),
        (
            and_(validated_column.is_(True), initialization_column > current_date),
            STATUS_ORDER_INDEX[StatusKey.UPCOMING],
        ),
        else_=STATUS_ORDER_INDEX[StatusKey.ACTIVE],
    )
