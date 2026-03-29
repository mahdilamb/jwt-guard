from typing import Any, NotRequired, TypedDict


class RequestDetails(TypedDict):
    path: str
    method: str
    payload: NotRequired[dict[str, Any]]
    headers: dict[str, Any]
