def resolve_status(f: callable, *args, **kwargs):
    content, status = f(*args, **kwargs)

    if status.value in range(200, 300):
        return content, status.value, None
    return None, status.value, content["message"]
