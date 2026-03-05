
def normalize_event(event_type : str) -> str:
    
    event = event_type.lower().replace("-", "_")
    
    if "login" in event and ("fail" in event or "error" in event):
        return "AUTH_LOGIN_FAILED"

    if "login" in event and "success" in event:
        return "AUTH_LOGIN_SUCCESS"
    
    
    return event_type.upper()