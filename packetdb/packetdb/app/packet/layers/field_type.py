

def get_type(field_name: str) -> str:
    field_def = {
        "ip.src": "ipv4",
        "ip.dst": "ipv4",
        "frame.timestamp": "timestamp",
        "eth.src": "mac",
        "eth.dst": "mac",
    }

    if field_def.get(field_name):
        return field_def[field_name]
    else:
        return "int"
