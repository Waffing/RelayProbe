"""Optional browser acceptance. Install the Playwright Python package and Chromium first."""
import json
import os
import secrets
import struct
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from tests.conftest import executable

pw = pytest.importorskip("playwright.sync_api")


@pytest.fixture
def browser_services(tmp_path, relay):
    password = secrets.token_urlsafe(24)
    with executable(tmp_path / "browser-console", password=password) as (client, _, _):
        yield client, relay, password


def test_console_real_browser(browser_services, tmp_path):
    client, relay, password = browser_services
    secret = secrets.token_urlsafe(30)
    with pw.sync_playwright() as p:
        browser = p.chromium.launch(channel="chromium",headless=True)
        context = browser.new_context(viewport={"width":1440,"height":980},accept_downloads=True)
        page = context.new_page()
        errors, urls = [], []
        page.on("pageerror",lambda err:errors.append(str(err)))
        page.on("request",lambda req:urls.append(req.url))
        page.goto(str(client.base_url))
        page.locator("#auth[open]").wait_for()
        page.locator("#password").fill(password)
        page.locator("#auth button").click()
        pw.expect(page.locator(".pad")).to_have_count(40)
        assert page.locator("#start").is_disabled()
        assert page.locator("#activeCount").inner_text()=="20"
        screenshot_dir = os.environ.get("RELAY_PROBE_TEST_SCREENSHOTS")
        if screenshot_dir:
            page.screenshot(path=str(Path(screenshot_dir)/"workspace.png"))
        page.locator("#theme").click()
        assert page.locator("html").get_attribute("data-theme")=="light"
        if screenshot_dir:
            page.screenshot(path=str(Path(screenshot_dir)/"workspace-light.png"))
        page.locator("#theme").click()
        page.locator("[data-tab=settings]").click()
        for id_, val in (("priceModel","mock-model"),("priceIn","1"),("priceCached",".25"),("priceOut","2")):
            page.locator("#"+id_).fill(val)
        page.locator("#savePrice").click()
        page.locator("[data-tab=work]").click()
        page.locator("#channel").fill("模拟验收")
        page.locator("#base").fill(relay+"/fake_reasoning_zero")
        page.locator("#key").fill(secret)
        def fake_ip_response(route):
            assert "local_network_compat" not in route.request.post_data_json
            route.fulfill(status=400, json={
                "detail": "SSRF 检测到目标域名使用 Fake-IP。",
                "code": "local_network_compat",
            })
        page.route("**/api/models", fake_ip_response, times=1)
        page.locator("#getModels").click()
        pw.expect(page.locator("#networkHelp")).to_be_visible()
        page.locator("#useNetworkCompat").click()
        pw.expect(page.locator("#networkCompat")).to_be_checked()
        pw.expect(page.locator("#networkHelp")).to_be_hidden()
        assert page.locator("#key").input_value() == secret
        page.locator("#networkCompat").uncheck()
        page.locator("#connectionOptions summary").click()
        page.locator("#getModels").click()
        pw.expect(page.locator("#model")).to_have_value("mock-model")
        page.locator("[data-mode=stress]").click()
        for i in (37,38,39,2,30):
            page.locator(f"[data-pad='{i}']").click()
        assert page.locator("#activeCount").inner_text()=="2"
        page.locator("#start").click()
        page.wait_for_url("**/#report",timeout=60000)
        page.locator("#finding-2").wait_for()
        assert page.locator("#key").input_value()==""
        assert page.locator("#reportView .badge.bad").count()>0
        if screenshot_dir:
            page.screenshot(path=str(Path(screenshot_dir)/"report.png"))
        page.locator("#finding-2 summary").click()
        page.locator("#finding-2 [data-seq]").first.click()
        assert page.locator("#allRequests").get_attribute("open") is not None
        assert page.get_by_text("完整原始 usage",exact=True).count()>=1
        page.get_by_text("补填测后余额，重算实际有效倍率",exact=True).click()
        page.locator("#postBefore").fill("10")
        page.locator("#postAfter").fill("9.999")
        page.locator("#postAfter").blur()
        assert "×" in page.locator("#recalculated").inner_text()
        exports={}
        for fmt in ("json","csv","md","png"):
            with page.expect_download() as captured:
                page.locator(f"[data-format={fmt}]").click()
            dest=tmp_path/("report."+fmt)
            captured.value.save_as(dest)
            data=dest.read_bytes()
            assert secret.encode() not in data and password.encode() not in data
            if fmt=="png":
                assert data.startswith(b"\x89PNG") and struct.unpack(">II",data[16:24])[0]>=2000
            else:
                assert relay.encode() not in data
            exports[fmt]=dest
        report=json.loads(exports["json"].read_text("utf-8"))
        assert report["meta"]["base_url"]=="[已隐藏]"
        assert report["head"]["effective_multiplier"]>0 and report["requests"][0]["usage"]
        assert len(exports["csv"].read_text("utf-8-sig").splitlines())>len(report["requests"])
        assert "## 检测证据" in exports["md"].read_text("utf-8")
        page.locator("#retest").click()
        page.wait_for_url("**/#work")
        assert page.locator("#activeCount").inner_text()=="1" and page.locator("[data-pad='2']").get_attribute("aria-pressed")=="true"
        page.locator("#base").fill(relay+"/normal_responses")
        page.locator("#key").fill(secret)
        page.locator("#start").click()
        page.wait_for_url("**/#report",timeout=60000)
        page.locator("[data-tab=history]").click()
        page.locator("[data-compare]").nth(0).check()
        page.locator("[data-compare]").nth(1).check()
        assert page.locator("#comparison thead th").count()==3
        storage=page.evaluate("JSON.stringify(localStorage)")
        assert secret not in storage and password not in storage
        assert not context.cookies()
        assert all(urlsplit(u).netloc==urlsplit(str(client.base_url)).netloc for u in urls if u.startswith("http"))
        page.set_viewport_size({"width":390,"height":844})
        page.locator("[data-tab=work]").click()
        assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
        assert page.locator(".rail").evaluate("el => el.scrollWidth <= el.clientWidth")
        if screenshot_dir:
            page.locator("#base").fill("")
            page.locator("#channel").fill("")
            page.locator("#model").fill("")
            pw.expect(page.locator("#toast")).to_be_hidden(timeout=10000)
            page.screenshot(path=str(Path(screenshot_dir)/"mobile.png"))
        assert not errors
        context.close()
        browser.close()
