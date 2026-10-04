"""Single-account implementation for demo_server.py, not a vendor checker."""

import argparse
import http.cookiejar
import json
from urllib.parse import urlsplit
import urllib.error
import urllib.request


def response(opener, request):
    try:
        stream = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        stream = error
    with stream:
        return json.loads(stream.read(4097))


def check(base, login, password):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    body = json.dumps({"login": login, "password": password}).encode("utf-8")
    signed_in = response(opener, urllib.request.Request(base + "/login", data=body,
                         headers={"Content-Type": "application/json"}, method="POST"))
    if signed_in.get("message") == "INVALID_PASSWORD":
        return "FAIL"
    token = signed_in.get("data", {}).get("opaque")
    if signed_in.get("message") != "SIGNED_IN" or not isinstance(token, str) or not token:
        return "ERROR"
    profile = response(opener, urllib.request.Request(base + "/profile",
                       headers={"Authorization": "Bearer " + token}))
    return "HIT" if profile.get("message") == "PROFILE_READY" and profile.get("plan") == "demo" else "ERROR"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    try:
        target = urlsplit(args.url)
        valid = (target.scheme == "http" and target.hostname in {"127.0.0.1", "localhost", "::1"}
                 and target.username is None and target.password is None and target.path in {"", "/"}
                 and not target.query and not target.fragment and target.port != 0)
    except ValueError:
        valid = False
    if not valid:
        parser.error("--url must be the loopback demo server origin")
    try:
        bucket = check(args.url.rstrip("/"), args.login, args.password)
    except (OSError, ValueError, AttributeError):
        bucket = "ERROR"
    print(json.dumps({"bucket": bucket, "source": "local-fixture"}))
    return 0 if bucket in {"HIT", "FAIL"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
