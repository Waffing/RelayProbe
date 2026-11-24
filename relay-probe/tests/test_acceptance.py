"""End-to-end acceptance via two real loopback HTTP servers and the console's SSE route."""
import asyncio
import hashlib
import json
import secrets
import time

import pytest

from app import config
from app.core import protocols, security
from app.core.tokenizer import count, input_count, padding
from app.main import runs
from tests.mock_relay import state as fixture_state

PRICES = {"input":1, "cached":.25, "output":2}  # Fixture's ledger, never a product default.


def target(services, scenario, **extra):
    return {"base_url":f"{services[1]}/{scenario}/v1/", "api_key":secrets.token_urlsafe(28),
            "model":"mock-model", **extra}


def read_stream(client, rid):
    events = []
    with client.stream("GET", f"/api/runs/{rid}/stream") as res:
        assert res.status_code == 200
        assert res.headers["cache-control"] == "no-cache"
        assert res.headers["connection"] == "keep-alive"
        assert res.headers["x-accel-buffering"] == "no"
        kind = ""
        for line in res.iter_lines():
            if line.startswith("event: "):
                kind = line[7:]
            elif line.startswith("data: "):
                events.append((kind,json.loads(line[6:])))
    assert events[-1][0] == "report"
    return events


def measure(services, scenario, ids, **options):
    client, _ = services
    spec = target(services,scenario,probe_ids=ids,**options)
    res = client.post("/api/runs",json=spec)
    assert res.status_code == 200, res.text
    created = res.json()
    assert created["estimate"]["requests_approx"] >= 1
    events = read_stream(client, created["run_id"])
    assert spec["api_key"] not in json.dumps(events)
    report = events[-1][1]
    assert runs[created["run_id"]].relay.key == ""
    assert not runs[created["run_id"]].relay.secrets
    assert report["totals"]["requests"] == len(report["requests"])
    seqs = {r["seq"] for r in report["requests"]}
    for f in report["findings"]:
        assert f["samples"] == len(f["evidence"]) and set(f["evidence"]) <= seqs
        assert f["strength"] in ("实测检出","疑似","未检出")
    return report


def finding(r, i):
    return next(f for f in r["findings"] if f["id"]==i)


def test_normal_all_40_real_time(services):
    r = measure(services,"normal_responses",list(range(1,41)),mode="full",expensive=[35,36,40],prices=PRICES,
                controls={"sustained_rpm":12})
    assert not r["meta"]["stop"]
    assert [f["id"] for f in r["findings"]] == list(range(1,41))
    assert r["head"]["score"] == 100 and r["head"]["score_coverage"] == 5
    assert r["totals"]["failed"] == 0 and r["totals"]["requests"] >= 140
    assert r["verdict"]["grade"] == "A", [(f["id"],f["summary"]) for f in r["findings"] if f["status"] not in ("通过","待对照确切指纹")]
    assert len(r["verdict"]["reasons"]) in (3,4,5)
    assert 0 < r["head"]["cache_rate"] < 1
    assert r["head"]["effective_multiplier"] == pytest.approx(1,abs=.00001)
    assert finding(r,15)["metrics"]["cache_effective_discount"] == pytest.approx(.75,abs=.0001)
    lv = finding(r,2)["metrics"]["levels"]
    assert lv["high"]["reasoning"] > lv["medium"]["reasoning"] > lv["low"]["reasoning"]
    assert all(finding(r,3)["metrics"]["checks"].values())
    assert 99_000 < finding(r,5)["metrics"]["document_tokens"] < 101_000
    assert finding(r,9)["metrics"]["timings"]
    assert finding(r,10)["metrics"]["checks"]["续接记忆"]
    assert finding(r,18)["metrics"]["warm_s"] < finding(r,18)["metrics"]["cold_s"]
    assert [x["interval_s"] for x in finding(r,19)["metrics"]["intervals"]] == [0,15,60]
    assert all(x["waited_s"]>=x["interval_s"]-.05 for x in finding(r,19)["metrics"]["intervals"])
    assert len(finding(r,24)["metrics"]["phases"]) == 3
    assert finding(r,27)["status"]=="待对照确切指纹"
    for i in (28,29,30,31,32,33,34,35,36):
        assert finding(r,i)["status"]=="通过"
    assert finding(r,36)["metrics"]["highest_verified"] >= 200_000
    assert [s["level"] for s in finding(r,39)["metrics"]["stages"]] == [1,5,10,20]
    assert finding(r,40)["metrics"]["elapsed_s"] >= 59.9
    assert finding(r,40)["metrics"]["success"] == 12


@pytest.mark.parametrize("status,falls",[(404,True),(405,True),(501,True),(400,True),(401,False),(403,False),(429,False),(500,False),(502,False)])
def test_auto_protocol(services,status,falls):
    r = measure(services,f"responses_{status}_chat_ok",[30])
    assert r["requests"][0]["status"]==status
    assert r["meta"]["protocol"]==("chat" if falls else "responses")
    if falls:
        assert r["requests"][1]["path"]=="/v1/chat/completions"
        assert finding(r,30)["status"]=="通过"
        assert "prompt_tokens" in r["requests"][-1]["usage"]
    else:
        assert len(r["requests"])==1 and f"HTTP {status}" in r["meta"]["stop"]
    assert not protocols.downgrade(400,"unrelated error")
    assert not protocols.downgrade(None,"not implemented")


def test_only_protocol_and_missing_fields(services):
    r = measure(services,"responses_404_chat_ok",[1],protocol="responses")
    assert len(r["requests"])==1
    r = measure(services,"normal_responses",[3,28,29,33],protocol="chat")
    assert all(row["path"]=="/v1/chat/completions" for row in r["requests"])
    assert finding(r,28)["status"]=="证据不足" and finding(r,28)["samples"]==0
    assert all(finding(r,i)["status"]=="通过" for i in (3,29,33))
    r = measure(services,"no_usage",[13,21,23])
    assert all(x["usage"] is None and x["counts"]["input"] is None for x in r["requests"])
    assert finding(r,13)["status"]=="证据不足"
    assert protocols.counts("responses",{"prompt_tokens":19})["input"] is None


@pytest.mark.parametrize("scenario,pid",[
    ("fake_cache_non128",7),("fake_cache_sticky",17),("fake_input_billing",11),("model_swap",23),("wrong_tokenizer",1)])
def test_hard_veto(services,scenario,pid):
    r = measure(services,scenario,[pid])
    f = finding(r,pid)
    assert r["verdict"]["grade"]=="D" and r["head"]["health"]=="红"
    assert f["hard"] and f["strength"]=="实测检出" and f["samples"]
    if pid==7:
        assert f["metrics"]["below1024"] and f["metrics"]["non128"]
    if pid==17:
        assert min(f["metrics"]["rates"])>.9
    if pid==11:
        assert all(x["reported_delta"]==0 for x in f["metrics"]["steps"])


@pytest.mark.parametrize("scenario,pid",[
    ("fake_reasoning_zero",2),("encrypted_strip",28),("encrypted_missing",28),("paper_cache",18),
    ("invisible",8),("inflated_output",13),("echo_tamper",30),("garbled_tools",29),
    ("lost_history",33),("bad_schema",3),("bad_tools",3),("role_drop",4),("waf",34),("rounded",14)])
def test_observable_anomalies(services,scenario,pid):
    r = measure(services,scenario,[pid])
    f = finding(r,pid)
    assert f["status"] in ("异常","需关注","证据不足")
    if pid==2: assert f["metrics"]["levels"]["high"]["reasoning"]==0 and r["head"]["health"]=="红"
    if scenario=="encrypted_strip": assert f["metrics"]["second_status"]==400
    if pid==18: assert f["strength"]=="疑似" and not f["hard"]
    if pid==8: assert f["metrics"]["hits"][0]["codepoint"]=="U+200B"


def test_cold_only_and_signature_evidence(services):
    r = measure(services,"fake_cache_sticky",[7,18,23,27])
    assert "冷启动异常命中" in finding(r,7)["summary"] and not finding(r,7)["hard"]
    assert finding(r,23)["samples"]==len(r["requests"]) and not any(row["probe"]==23 for row in r["requests"])
    assert finding(r,27)["summary"]=="待对照确切指纹"
    r = measure(services,"injected",[6,22])
    assert finding(r,6)["metrics"]["profile_delta"]==4233
    assert finding(r,6)["metrics"]["bare_delta"]==0
    assert finding(r,22)["strength"]=="疑似"
    assert r["head"]["health"]=="红"


def test_low_cache_only_remains_suspected(services):
    r=measure(services,"below_cache_threshold",[7])
    f=finding(r,7)
    assert f["metrics"]["below1024"] and not f["metrics"]["non128"]
    assert f["strength"]=="疑似" and not f["hard"] and r["verdict"]["grade"]!="D"


def test_bare_mode_keeps_explicit_cache_experiment(services):
    r=measure(services,"normal_responses",[6,16],bare=True)
    rows=[x for x in r["requests"] if x["probe"]==16]
    assert len(rows)==8 and all(not x["disguised"] for x in rows)
    assert len({x["body"]["prompt_cache_key"] for x in rows})==1
    bare=next(x for x in r["requests"] if x["label"]=="极简裸请求对照")
    assert "prompt_cache_key" not in bare["body"] and "tools" not in bare["body"]


def test_gradual_stress_and_stop(services):
    r=measure(services,"stress_429_at_10",[37,38,39,40],mode="stress",expensive=[40])
    stages=finding(r,39)["metrics"]["stages"]
    assert [x["level"] for x in stages]==[1,5,10]
    assert finding(r,38)["metrics"]["critical"]==10 and stages[-1]["statuses"].get("429",0)>0
    assert stages[1]["latency_p99"]>=stages[1]["latency_p50"]>0
    assert fixture_state["stress_429_at_10"]["peak"]==10
    assert not any(row["probe"]==40 for row in r["requests"])


def test_explicit_fifty_and_high_cost_switch(services):
    client,_ = services
    disabled = client.post("/api/runs",json=target(services,"normal_responses",probe_ids=[36]))
    assert disabled.status_code==422
    r=measure(services,"normal_responses",[39],mode="stress",allow_50=True)
    stages=finding(r,39)["metrics"]["stages"]
    assert [s["level"] for s in stages]==[1,5,10,20,50]
    assert stages[-1]["success"]==50


def test_cost_and_physical_fuses(services):
    for controls,price,expected in [({"max_requests":2},None,2),({"max_tokens":1},None,0),
                                    ({"budget_usd":.0005},PRICES,1)]:
        r=measure(services,"normal_responses",[1],controls=controls,prices=price)
        assert "熔断" in r["meta"]["stop"] and r["meta"]["partial"]
        assert len(r["requests"])==expected
    r=measure(services,"normal_responses",[37],controls={"max_requests":4})
    assert r["totals"]["sent"]==4 and r["totals"]["reserved"]==0 and r["meta"]["stop"]


def test_retest_randomness_and_raw_evidence(services):
    a=measure(services,"fake_reasoning_zero",[2,30])
    ids=[f["id"] for f in a["findings"] if f["status"] in ("异常","需关注")]
    b=measure(services,"normal_responses",ids)
    assert b["meta"]["selection"]==[2] and a["meta"]["salt"]!=b["meta"]["salt"]
    assert finding(a,2)["metrics"]["questions"][0]["question"]!=finding(b,2)["metrics"]["questions"][0]["question"]
    sample=b["requests"][1]
    assert all(k in sample for k in ("body","headers","response_headers","text","usage","events","chunks","phases"))
    assert sample["input_delta"]==0 and sample["headers"]["user-agent"].startswith("codex_")
    assert "origin" not in sample["headers"] and "referer" not in sample["headers"]


def test_abort_key_lifetime_errors_logs(services,caplog):
    client,_=services
    spec=target(services,"slow",probe_ids=[1])
    res=client.post("/api/runs",json=spec)
    rid=res.json()["run_id"]
    time.sleep(.09)
    start=time.monotonic()
    assert client.post(f"/api/runs/{rid}/abort",json={}).status_code==200
    assert time.monotonic()-start<1.5
    events=read_stream(client,rid)
    assert "手动中止" in events[-1][1]["meta"]["stop"]
    assert not runs[rid].relay.key and not runs[rid].spec.api_key.get_secret_value()
    assert spec["api_key"] not in json.dumps(events)
    secret=secrets.token_urlsafe(32)
    r=measure(services,"secret_echo",[1],name=secret,api_key=secret)
    assert secret not in json.dumps(r) and secret not in caplog.text
    invalid=client.post("/api/runs",json=target(services,"normal_responses",api_key=secret,model=""))
    assert invalid.status_code==422 and secret not in invalid.text
    timed=measure(services,"slow",[30],controls={"read_s":.05})
    assert len(timed["requests"])==1 and "读超时" in timed["meta"]["stop"]


def test_auth_capture_import_and_profiles(services,monkeypatch):
    client,_=services
    access=secrets.token_urlsafe(25)
    key=secrets.token_urlsafe(25)
    monkeypatch.setattr(config,"ACCESS_PASSWORD",access)
    for path in ("/api/config","/api/profiles","/api/runs/none/stream"):
        assert client.get(path).status_code==401
    for path in ("/api/models","/api/runs","/api/runs/none/abort","/api/capture/v1/responses"):
        assert client.post(path,json={}).status_code==401
    h={"Authorization":"Bearer "+access}
    assert client.get("/api/profiles",headers={"Authorization":access}).status_code==401
    arm=client.post("/api/capture/arm",json={},headers=h).json()
    headers={"Authorization":"Bearer "+arm["token"],"api-key":key,"x-echo":key,"user-agent":"fixture-cli","originator":"fixture"}
    body={"instructions":"本地抓包骨架","tools":[],"stream":True,"input":"私有工作区文字","api_key":key}
    cap=client.post("/api/capture/v1/responses",json=body,headers=headers)
    assert cap.status_code==200
    assert client.post("/api/capture/v1/responses",json=body,headers=headers).status_code==401
    allp=client.get("/api/profiles",headers=h).json()
    assert "response.completed" in cap.text
    p=next(x for x in allp if x["id"]==cap.headers["x-captured-profile-id"])
    assert p["source"]=="实机抓包复刻" and p["headers"]["user-agent"]=="fixture-cli"
    assert p["baseline_tokens"]==input_count(p["body"])
    disk=(config.DATA/"profiles.json").read_text("utf-8")
    assert all(x not in disk for x in (key,access,arm["token"],"私有工作区文字"))
    curl=f"""curl https://unused.example/v1/responses -H 'Authorization: Bearer {key}' -d '{{"instructions":"test","input":"secret user prompt"}}'"""
    imp=client.post("/api/profiles",json={"raw":curl},headers=h).json()
    assert imp["source"]=="原文导入" and key not in json.dumps(imp)
    assert client.delete("/api/profiles/"+imp["id"],headers=h).status_code==200
    assert client.delete("/api/profiles/"+p["id"],headers=h).status_code==200
    assert client.get("/api/config?token="+key,headers=h).status_code==400


def test_ssrf_models_and_tokenizer(services,monkeypatch):
    client,_=services
    spec=target(services,"normal_responses")
    model_data={k:spec[k] for k in ("base_url","api_key")}
    monkeypatch.setattr(config,"ALLOW_PRIVATE",False)
    for ip in ("127.0.0.2","::1","10.0.0.20","172.31.255.255","192.168.1.1","169.254.169.254","fc00::1","::ffff:127.0.0.1"):
        assert not security.allowed(ip)
    assert client.post("/api/models",json=model_data).status_code==400
    monkeypatch.setattr(config,"ALLOW_PRIVATE",True)
    assert client.post("/api/models",json=model_data).json()["models"]==["mock-model"]
    n=4096
    assert count(padding(n,"seed-a"))==count(padding(n,"seed-b"))==n
    assert padding(n,"seed-a")!=padding(n,"seed-b")
    cache=config.ROOT/"app/data/tokenizer/fb374d419588a4632f3f557e76b4b70aebbca790"
    assert hashlib.sha256(cache.read_bytes()).hexdigest()=="446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"


def test_no_price_manual_and_balance_unavailable(services):
    r=measure(services,"no_balance",[15,20])
    assert r["totals"]["cost"] is None and r["head"]["effective_multiplier"] is None
    assert finding(r,20)["metrics"]["basis"]=="假设比，待确认"
    assert finding(r,15)["status"]=="证据不足"
    assert r["meta"]["stop"]==""
    r=measure(services,"no_balance",[15,30],prices=PRICES,
              ledger={"kind":"balance","before":500000,"after":499000,"units_per_usd":500000})
    assert finding(r,15)["metrics"]["deduction_usd"]==pytest.approx(.002)
    assert r["head"]["effective_multiplier"]==pytest.approx(.002/r["totals"]["cost"])


def test_config_and_presets(services):
    client,_=services
    cfg=client.get("/api/config").json()
    assert len(cfg["probes"])==40 and all(not set(ids)&{35,36,40} for ids in cfg["modes"].values())
    assert cfg["controls"]["connect_s"]==15 and cfg["controls"]["read_s"]==60 and cfg["controls"]["heavy_s"]==150
    assert "connect-src 'self'" in client.get("/").headers["content-security-policy"]
