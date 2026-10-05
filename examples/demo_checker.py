"""Single-account implementation for demo_server.py, not a vendor checker."""

import argparse
import http.cookiejar
import json
import sys
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


class InputParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "invalid input; provide --stdin-json or loopback --url, --login, --password arguments\n")


def main():
    parser = InputParser(description=__doc__)
    parser.add_argument("--stdin-json", action="store_true", help="Read url/login/password from one JSON stdin object")
    parser.add_argument("--url")
    parser.add_argument("--login")
    parser.add_argument("--password")
    args = parser.parse_args()
    if args.stdin_json:
        if any(value is not None for value in (args.url, args.login, args.password)):
            parser.error("--stdin-json cannot be combined with credential arguments")
        try:
            raw = sys.stdin.buffer.read(1048577)
            if len(raw) > 1048576:
                raise ValueError("input exceeds byte limit")

            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("duplicate key")
                    result[key] = value
                return result

            data = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
            if (not isinstance(data, dict) or set(data) != {"url", "login", "password"}
                    or any(not isinstance(value, str) or "\x00" in value for value in data.values())):
                raise ValueError("invalid input shape")
            args.url, args.login, args.password = data["url"], data["login"], data["password"]
        except (OSError, UnicodeError, ValueError, RecursionError):
            print(json.dumps({"bucket": "BADFORMAT", "source": "local-fixture"}))
            return 2
    elif any(value is None for value in (args.url, args.login, args.password)):
        parser.error("provide --stdin-json or all of --url, --login and --password")
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
