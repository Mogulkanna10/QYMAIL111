import json

def serialize(obj) -> bytes:
    """
    Canonical, deterministic serialization.
    Converts models or dicts to a stable JSON byte string.
    Keys are sorted, and bytes are converted to hex strings.
    """
    def default_encoder(o):
        if isinstance(o, bytes):
            return o.hex()
        raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

    # Assuming Pydantic v2
    if hasattr(obj, "model_dump"):
        data = obj.model_dump()
    elif hasattr(obj, "to_dict"):
        data = obj.to_dict()
    elif isinstance(obj, dict):
        data = obj
    else:
        raise ValueError(f"Cannot serialize object of type {type(obj)}")
        
    return json.dumps(
        data, 
        sort_keys=True, 
        separators=(',', ':'),
        default=default_encoder
    ).encode('utf-8')
