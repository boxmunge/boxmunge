"""HTML shell of the admin pages, and the passkey register and sign-in pages.

Pages carry no inline script or style (the CSP allows only same-origin
files): /static/admin.css styles them and /static/admin-passkey.js runs the
WebAuthn ceremonies. Every interpolated value is escaped.
"""

from html import escape

SCRIPT = "/static/admin-passkey.js"
RECOVERY = ("To replace the passkey, set a new STATS_SECRET through the deploy shell "
            "and redeploy; registration then reopens.")


def document(title: str, body: str, body_attrs: dict[str, str] | None = None,
             script: bool = False) -> str:
    attrs = "".join(f' {name}="{escape(value)}"' for name, value in (body_attrs or {}).items())
    tag = f'<script src="{SCRIPT}" defer></script>' if script else ""
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<meta name=\"robots\" content=\"noindex\"><title>{escape(title)}</title>"
        f"<link rel=\"stylesheet\" href=\"/static/admin.css\">{tag}</head>"
        f"<body{attrs}>{body}</body></html>")


def register() -> str:
    return document("Register the admin passkey", (
        "<h1>Register the admin passkey</h1>"
        "<p class=\"note\">Paste the registration code (the service's STATS_SECRET), then "
        "create a passkey when your browser asks. Only one passkey can be registered; "
        "after that this page is closed.</p>"
        "<form id=\"register\" method=\"post\" action=\"/v1/admin/register\">"
        "<label>Registration code<input type=\"password\" name=\"code\" "
        "autocomplete=\"off\" required></label>"
        "<button type=\"submit\">Create passkey</button></form>"
        "<p id=\"status\" role=\"status\"></p>"), {"data-page": "register"}, script=True)


def registration_closed() -> str:
    return document("Registration closed", (
        "<h1>Registration closed</h1>"
        "<p>An admin passkey is already registered. "
        "<a href=\"/v1/admin/login\">Sign in</a>.</p>"
        f"<p class=\"note\">{escape(RECOVERY)}</p>"))


def login(next_path: str) -> str:
    return document("Sign in", (
        "<h1>boxmunge version-check admin</h1>"
        "<button id=\"signin\" type=\"button\">Sign in with passkey</button>"
        "<p id=\"status\" role=\"status\"></p>"
        f"<p class=\"note\">Lost the passkey? {escape(RECOVERY)}</p>"),
        {"data-page": "login", "data-next": next_path}, script=True)


def no_passkey() -> str:
    return document("No passkey registered", (
        "<h1>No passkey registered</h1>"
        "<p><a href=\"/v1/admin/register\">Register the admin passkey</a> with the "
        "registration code (the service's STATS_SECRET).</p>"))
