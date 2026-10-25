#!/usr/bin/env python3
"""Low-impact CORS and security-header check for the authorized site root."""

import time
import urllib.error
import urllib.request


TARGET = "https://turbo-alshamal.com/"
TEST_ORIGIN = "https://cors-probe.invalid"
TIMEOUT_SECONDS = 10

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


OPENER = urllib.request.build_opener(NoRedirectHandler)


def request(method, headers):
    req = urllib.request.Request(TARGET, method=method, headers=headers)
    try:
        response = OPENER.open(req, timeout=TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        response = error
    except (TimeoutError, urllib.error.URLError, OSError) as error:
        print(f"{method}: request failed: {error}")
        return None, {}

    try:
        return response.code, response.headers
    finally:
        response.close()


def main():
    common_headers = {"User-Agent": "Authorized-Security-Check/1.0"}
    print(f"Checking only the public site root: {TARGET}")

    status, headers = request(
        "OPTIONS",
        {
            **common_headers,
            "Origin": TEST_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    if status is None:
        return 1

    print(f"\nOPTIONS status: {status}")
    for name in (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
    ):
        print(f"  {name}: {headers.get(name, '(not present)')}")

    if 300 <= status < 400:
        print("Redirect received; not following it to keep the check in scope.")
        return 0
    if status in (403, 429):
        print(f"Stopping because the server returned HTTP {status}; no retry performed.")
        return 0

    time.sleep(2)
    status, headers = request(
        "GET",
        {**common_headers, "Origin": TEST_ORIGIN},
    )
    if status is None:
        return 1

    print(f"\nGET status: {status}")
    print("Security headers:")
    for name in SECURITY_HEADERS:
        print(f"  {name}: {headers.get(name, '(not present)')}")

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == TEST_ORIGIN and allow_credentials == "true":
        print(
            "\nReview the CORS policy with the site owner. This response alone "
            "does not prove access to private account data."
        )
    else:
        print("\nNo credentialed origin reflection was observed on the site root.")

    if 300 <= status < 400:
        print("Redirect received; it was not followed.")
    elif status in (403, 429):
        print(f"Server returned HTTP {status}; no retry or evasion was attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
