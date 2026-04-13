
EVENT_PATTERNS: list[tuple[str, set[str]]] = [

    ("AUTH_LOGIN_FAILED",       {"login", "fail"}),
    ("AUTH_LOGIN_FAILED",       {"login", "error"}),
    ("AUTH_LOGIN_FAILED",       {"auth", "fail"}),
    ("AUTH_LOGIN_FAILED",       {"signin", "fail"}),

    ("AUTH_LOGIN_SUCCESS",      {"login", "success"}),
    ("AUTH_LOGIN_SUCCESS",      {"login", "ok"}),
    ("AUTH_LOGIN_SUCCESS",      {"auth", "success"}),
    ("AUTH_LOGIN_SUCCESS",      {"signin", "success"}),

    ("AUTH_LOGOUT",             {"logout"}),
    ("AUTH_LOGOUT",             {"signout"}),
    ("AUTH_LOGOUT",             {"session", "end"}),

    ("AUTH_TOKEN_EXPIRED",      {"token", "expir"}),
    ("AUTH_TOKEN_EXPIRED",      {"token", "invalid"}),
    ("AUTH_TOKEN_EXPIRED",      {"jwt", "expir"}),

    ("PASSWORD_CHANGE",         {"password", "change"}),
    ("PASSWORD_CHANGE",         {"password", "update"}),
    ("PASSWORD_CHANGE",         {"passwd", "change"}),

    ("PASSWORD_RESET",          {"password", "reset"}),
    ("PASSWORD_RESET",          {"password", "forgot"}),
    ("PASSWORD_RESET",          {"passwd", "reset"}),

    ("USER_CREATED",            {"user", "creat"}),
    ("USER_CREATED",            {"user", "register"}),
    ("USER_CREATED",            {"signup"}),

    ("USER_DELETED",            {"user", "delet"}),
    ("USER_DELETED",            {"user", "remov"}),
    ("USER_DELETED",            {"account", "delet"}),

    ("USER_UPDATED",            {"user", "updat"}),
    ("USER_UPDATED",            {"profile", "updat"}),
    ("USER_UPDATED",            {"profile", "edit"}),

    ("ADMIN_DELETE_USER",       {"admin", "delet"}),
    ("ADMIN_DELETE_USER",       {"admin", "remov", "user"}),

    ("ADMIN_BAN_USER",          {"admin", "ban"}),
    ("ADMIN_BAN_USER",          {"admin", "suspend"}),
    ("ADMIN_BAN_USER",          {"admin", "block", "user"}),

    ("ADMIN_ROLE_CHANGE",       {"admin", "role"}),
    ("ADMIN_ROLE_CHANGE",       {"admin", "permission"}),
    ("ADMIN_ROLE_CHANGE",       {"admin", "privilege"}),

    ("ADMIN_EXPORT_DATA",       {"admin", "export"}),
    ("ADMIN_EXPORT_DATA",       {"admin", "download", "data"}),

    ("API_REQUEST",             {"api", "request"}),
    ("API_REQUEST",             {"http", "request"}),

    ("API_ERROR",               {"api", "error"}),
    ("API_ERROR",               {"http", "error"}),
    ("API_ERROR",               {"request", "fail"}),
    ("API_ERROR",               {"endpoint", "error"}),

    ("RATE_LIMIT_HIT",          {"rate", "limit"}),
    ("RATE_LIMIT_HIT",          {"throttl"}),

    ("RECORD_VIEW",             {"record", "view"}),
    ("RECORD_VIEW",             {"record", "access"}),
    ("RECORD_VIEW",             {"data", "view"}),

    ("FILE_DOWNLOAD",           {"file", "download"}),
    ("FILE_DOWNLOAD",           {"attachment", "download"}),

    ("DATA_ACCESS",             {"data", "access"}),
    ("DATA_ACCESS",             {"data", "fetch"}),
    ("DATA_ACCESS",             {"data", "read"}),

    ("SYSTEM_ERROR",            {"system", "error"}),
    ("SYSTEM_ERROR",            {"server", "error"}),
    ("SYSTEM_ERROR",            {"internal", "error"}),
    ("SYSTEM_ERROR",            {"unhandl", "exception"}),
    ("SYSTEM_ERROR",            {"crash"}),

    ("SERVICE_UNAVAILABLE",     {"service", "unavailabl"}),
    ("SERVICE_UNAVAILABLE",     {"service", "down"}),
    ("SERVICE_UNAVAILABLE",     {"503"}),

    ("DB_QUERY_SLOW",           {"db", "slow"}),
    ("DB_QUERY_SLOW",           {"database", "slow"}),
    ("DB_QUERY_SLOW",           {"query", "slow"}),
    ("DB_QUERY_SLOW",           {"query", "timeout"}),

    ("DB_CONNECTION_FAILED",    {"db", "connect", "fail"}),
    ("DB_CONNECTION_FAILED",    {"database", "connect", "fail"}),
    ("DB_CONNECTION_FAILED",    {"db", "connect", "error"}),
]


def _sanitize(event_type: str) -> str:
    return (
        (event_type or "")
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .replace(".", " ")
    )


def normalize_event(event_type: str) -> str:
    sanitized = _sanitize(event_type)

    for canonical, keywords in EVENT_PATTERNS:
        if all(kw in sanitized for kw in keywords):
            return canonical

    return (event_type or "").strip().upper().replace(" ", "_").replace("-", "_")