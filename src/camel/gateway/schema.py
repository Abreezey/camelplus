"""Local, bounded JSON Schema validation; remote references never perform IO."""

import json
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing.exceptions import Unresolvable

from camel.gateway.models import GatewayError


def bounded_json(value: Any, *, max_bytes: int = 262144, max_depth: int = 32) -> bytes:
    def walk(item: Any, depth: int) -> None:
        if depth > max_depth:
            raise GatewayError("json_depth_exceeded")
        if isinstance(item, dict):
            if not all(isinstance(k, str) for k in item):
                raise GatewayError("non_string_json_key")
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list | tuple):
            for child in item:
                walk(child, depth + 1)
        elif item is not None and not isinstance(item, str | int | float | bool):
            raise GatewayError("non_json_value")

    try:
        walk(value, 0)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError) as err:
        if isinstance(err, GatewayError):
            raise
        raise GatewayError("invalid_json_value") from err
    if len(encoded) > max_bytes:
        raise GatewayError("json_size_exceeded")
    return encoded


def validate_schema(schema: dict[str, Any]) -> None:
    bounded_json(schema)
    if schema.get("type") != "object":
        raise GatewayError("tool_schema_must_be_object")

    def refs(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and (not isinstance(child, str) or not child.startswith("#")):
                    raise GatewayError("external_schema_reference")
                if key == "$id" and (not isinstance(child, str) or not child.startswith("#")):
                    raise GatewayError("external_schema_id")
                refs(child)
        elif isinstance(value, list):
            for child in value:
                refs(child)

    refs(schema)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as err:
        raise GatewayError("invalid_tool_schema") from err


def validate_arguments(arguments: dict[str, Any], schema: dict[str, Any]) -> None:
    bounded_json(arguments)
    try:
        Draft202012Validator(schema).validate(arguments)
    except (ValidationError, RecursionError, Unresolvable) as err:
        raise GatewayError("invalid_tool_arguments") from err
