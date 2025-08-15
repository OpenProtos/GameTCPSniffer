from typing import Any
from google.protobuf.message import Message
from google.protobuf.descriptor import FieldDescriptor
import msgpack

def serialize_protobuf_message(proto_msg: Message) -> bytes:
    """
    Convert a protobuf message into a structured format 
    """

    # convert the message as a structured format using Python native types
    structured_data = {
        "message_type": proto_msg.DESCRIPTOR.full_name,
        "fields": {},
    }

    for field, value in proto_msg.ListFields():
        field_name = field.name
        structured_data["fields"][field_name] = serialize_field_value(value, field)

    # serialize it as a messagepack
    if (packed := msgpack.packb(structured_data)) is None:
        raise RuntimeError("Packing failed")
    else:
        return packed


def serialize_field_value(value: Any, field_descriptor: FieldDescriptor) -> Any:
    """
    Convert a protobuf field value to Python native types
    """

    # handling array
    if field_descriptor.label == FieldDescriptor.LABEL_REPEATED:
        return [serialize_single_value(item, field_descriptor) for item in value]
    else:
        return serialize_single_value(value, field_descriptor)


def serialize_single_value(value: Any, field_descriptor: FieldDescriptor) -> Any:
    """
    Convert a single protobuf value
    """

    # nested type
    if field_descriptor.type == FieldDescriptor.TYPE_MESSAGE:
        return {
            "message_type": value.DESCRIPTOR.full_name,
            "field": {
                f.name: serialize_field_value(v,f) for f, v in value.ListFields()
            }
        }

    # primitive types
    elif field_descriptor.type == FieldDescriptor.TYPE_STRING:
        return str(value)
    elif field_descriptor.type in [FieldDescriptor.TYPE_INT32, FieldDescriptor.TYPE_INT64, FieldDescriptor.TYPE_SINT32, FieldDescriptor.TYPE_SINT64]:
        return int(value)
    elif field_descriptor.type in [FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_DOUBLE]:
        return float(value)
    elif field_descriptor.type == FieldDescriptor.TYPE_BOOL:
        return bool(value)
    elif field_descriptor.type == FieldDescriptor.TYPE_BYTES:
        return value
    # fallback
    else:
        str(value)

