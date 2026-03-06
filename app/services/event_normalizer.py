
def normalize_event(event_type : str) -> str:
    
    event = (event_type or "").lower().replace("-", "_")
    
    if "login" in event and ("fail" in event or "error" in event):
        return "AUTH_LOGIN_FAILED"

    if "login" in event and "success" in event:
        return "AUTH_LOGIN_SUCCESS"
    
    if "password" in event and "change" in event:
        return "PASSWORD_CHANGE"
    
    if "system" in event and "error" in event:
        return "SYSTEM_ERROR"
    
    return (event_type or "").upper()