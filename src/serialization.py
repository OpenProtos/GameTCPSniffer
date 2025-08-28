from typing import Any, Dict
from attr import field
from google.protobuf.message import Message
from google.protobuf.descriptor import FieldDescriptor
import msgpack

TYPE_MAP = {
    FieldDescriptor.TYPE_STRING: "string",
    FieldDescriptor.TYPE_INT32: "int32",
    FieldDescriptor.TYPE_INT64: "int64",
    FieldDescriptor.TYPE_UINT32: "uint32",
    FieldDescriptor.TYPE_UINT64: "uint64",
    FieldDescriptor.TYPE_FLOAT: "float",
    FieldDescriptor.TYPE_DOUBLE: "double",
    FieldDescriptor.TYPE_BOOL: "bool",
    FieldDescriptor.TYPE_BYTES: "bytes",
    FieldDescriptor.TYPE_MESSAGE: "message",
    FieldDescriptor.TYPE_ENUM: "enum",
}


def serialize_protobuf_message(proto_msg: Message) -> bytes:
    """
    Convert a protobuf message into a structured format
    """

    # convert the message as a structured format using Python native types
    structured_data = {
        "message_type": proto_msg.DESCRIPTOR.full_name,
        "fields": {},
        "version": 1,
    }

    for field, value in proto_msg.ListFields():
        field_name = field.name
        structured_data["fields"][field_name] = serialize_field_value(value, field)

    # serialize it as a messagepack
    if (packed := msgpack.packb(structured_data)) is None:
        raise RuntimeError("Packing failed")
    else:
        return packed


def serialize_field_value(
    value: Any, field_descriptor: FieldDescriptor
) -> Dict[str, Any]:
    if field_descriptor.label == FieldDescriptor.LABEL_REPEATED:
        return {
            "type": "array",
            "element_type": TYPE_MAP.get(field_descriptor.type, "unknown"),
            "value": [serialize_single_value(item, field_descriptor) for item in value],
        }
    else:
        return serialize_single_value(value, field_descriptor)


def serialize_single_value(
    value: Any, field_descriptor: FieldDescriptor
) -> Dict[str, Any]:
    """
    Convert a protobuf field value to Python native types
    """
    result: Dict[str, Any] = {
        "type": TYPE_MAP.get(field_descriptor.type, "unknown"),
    }

    if field_descriptor.type == FieldDescriptor.TYPE_MESSAGE:
        result.update(
            {
                "message_type": value.DESCRIPTOR.full_name,
                "value": {
                    f.name: serialize_field_value(v, f) for f, v in value.ListFields()
                },
            }
        )
    elif field_descriptor.type == FieldDescriptor.TYPE_STRING:
        result.update({"value": str(value)})
    elif field_descriptor.type in [
        FieldDescriptor.TYPE_INT32,
        FieldDescriptor.TYPE_INT64,
        FieldDescriptor.TYPE_SINT32,
        FieldDescriptor.TYPE_SINT64,
    ]:
        result.update({"value": int(value)})
    elif field_descriptor.type in [
        FieldDescriptor.TYPE_FLOAT,
        FieldDescriptor.TYPE_DOUBLE,
    ]:
        result.update({"value": float(value)})
    elif field_descriptor.type == FieldDescriptor.TYPE_BOOL:
        result.update({"value": bool(value)})
    elif field_descriptor.type == FieldDescriptor.TYPE_BYTES:
        result.update({"value": value})
    elif field_descriptor.type == FieldDescriptor.TYPE_ENUM:
        result.update(
            {
                "element_type": field_descriptor.enum_type.full_name,
                "value": value,
                "enum_name": field_descriptor.enum_type.values[value].name,
            }
        )
    else:
        result.update({"value": str(value)})

    return result
