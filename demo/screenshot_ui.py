#!/usr/bin/env python
"""
Screenshot the demo UI (light + dark) for visual verification.

Requires a headless browser. On a *shared* host, prefer a private env so you do
not upgrade system libraries other users link against:

    # Option A - container/venv with browser deps (no system changes)
    docker run --rm --network host -v $PWD:/w -w /w mcr.microsoft.com/playwright/python \
        python demo/screenshot_ui.py

    # Option B - this host (upgrades 8 shared libs; only with the owner's OK)
    sudo apt-get install -y libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 \
        libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
        libcairo2 libasound2 libatspi2.0-0 libnss3
    python -m playwright install chromium

Then, with the UI running (demo/app.py):
    python demo/screenshot_ui.py            # -> /tmp/ui_light.png, /tmp/ui_dark.png
"""

import sys

URL = "http://localhost:5001/"
OUT = {("light", "light"): "/tmp/ui_light.png", ("dark", "dark"): "/tmp/ui_dark.png"}


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed: pip install playwright && python -m playwright install chromium")
        return 1
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            print(f"browser launch failed (missing system libs?): {str(exc)[:200]}")
            return 1
        for (scheme, _), path in OUT.items():
            page = browser.new_page(viewport={"width": 1280, "height": 1400}, color_scheme=scheme)
            page.goto(URL, wait_until="networkidle")
            page.wait_for_timeout(1500)          # let the fetch + render settle
            page.screenshot(path=path, full_page=True)
            print(f"{scheme:5} -> {path} | tiles={page.locator('.tile').count()} "
                  f"bars={page.locator('.bar-row').count()} cards={page.locator('.card').count()} "
                  f"cases={page.locator('.case').count()}")
            page.close()
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
