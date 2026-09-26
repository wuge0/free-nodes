#!/usr/bin/env python3
"""free-nodes: 抓取公共节点源 -> 起 mihomo 实测 -> 筛选活跃节点 -> 生成 clash.yaml
面向 GitHub Actions runner（海外直连），也可在任意 linux 上运行。
依赖: PyYAML (pip install pyyaml)
"""
import base64
import concurrent.futures
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "output")
WORK = "/tmp/harvest"
SECRET = "harvest-token"
MIHOMO_VER = "v1.19.31"
BIN = os.path.join(WORK, "mihomo")
API = ""                                  # 运行时确定（自动挑空闲端口）

def envn(k, d):
    v = os.environ.get(k)
    try:
        return int(v) if v else d
    except ValueError:
        return d


MAX_NODES, PER_SRC = envn("MAX_NODES", 3500), envn("PER_SRC", 1500)
FETCH_C, FETCH_T = envn("FETCH_C", 12), envn("FETCH_T", 25)
L1_C, L1_T = envn("L1_C", 64), envn("L1_T", 5000)          # L1 粗测：节点存活
L2_KEEP, L2_C, L2_T = envn("L2_KEEP", 60), envn("L2_C", 16), envn("L2_T", 8000)  # L2 精测：GitHub 可达
SMOKE = os.environ.get("SMOKE") or "http://www.gstatic.com/generate_204"
GH = os.environ.get("GH") or "https://api.github.com/zen"
LIMIT_SRC = envn("LIMIT_SRC", 0)          # >0 时只取该数量源，方便本地冒烟
AD = re.compile(r"https?://|剩余|流量|到期|官网|官址|公告|防失联|付费|重置|套餐|发布页|电报|频道", re.I)


def log(m):
    print(m, flush=True)


def free_port():
    """挑一个空闲端口，避免与宿主已有服务（如 sandbox-proxy 占 9090）冲突"""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def local(url, tmo=10, method=None, body=None):
    """访问本机 mihomo API —— 强制不走任何 HTTP 代理"""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body else None)
    if SECRET:
        req.add_header("Authorization", "Bearer " + SECRET)
    with op.open(req, timeout=tmo) as r:
        return json.loads(r.read() or b"{}")


def fetch(u):
    with urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "clash/1.0"}),
                                timeout=FETCH_T) as r:
        d = r.read()
        if (r.headers.get("Content-Encoding") or "").lower() == "gzip":
            d = gzip.decompress(d)
    return d.decode("utf-8", "replace")


def b64(s):
    s = re.sub(r"\s+", "", s)
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def qs(q):
    return dict(urllib.parse.parse_qsl(q, keep_blank_values=True))


def nm(host, port, frag, pfx):
    n = urllib.parse.unquote(frag or "").strip()
    return n or f"{pfx}-{host}:{port}"


def uri2p(s):
    """vmess/vless/ss/trojan/hysteria2/tuic URI -> clash 节点 dict；失败返回 None"""
    s = s.strip()
    if "://" not in s:
        return None
    sc, _, rest = s.partition("://")
    sc = sc.lower()
    try:
        if sc == "vmess":
            j = json.loads(b64(rest.split("#")[0]))
            host, port, uid = str(j.get("add") or ""), int(j.get("port") or 0), j.get("id")
            if not host or not (1 <= port <= 65535) or not uid:
                return None
            p = {"name": (j.get("ps") or f"vmess-{host}").strip(), "type": "vmess",
                 "server": host, "port": port, "uuid": uid,
                 "alterId": int(j.get("aid") or 0), "cipher": j.get("scy") or "auto"}
            if str(j.get("tls") or "").lower() == "tls":
                p["tls"] = True
                if j.get("sni") or j.get("host"):
                    p["servername"] = j.get("sni") or j.get("host")
            if (j.get("net") or "tcp") == "ws":
                p["network"] = "ws"
                w = {"path": j.get("path") or "/"}
                if j.get("host"):
                    w["headers"] = {"Host": j["host"]}
                p["ws-opts"] = w
            return p

        if sc == "ss":
            body, _, frag = rest.partition("#")
            if "?" in body:
                body, _, qp = body.partition("?")
                if qs(qp).get("plugin"):
                    return None
            if "@" in body:
                src, _, hostport = body.rpartition("@")
                try:
                    ui = b64(src)
                except Exception:
                    ui = urllib.parse.unquote(src)
                method, _, password = ui.partition(":")
            else:
                ui = b64(body)
                method, _, tail = ui.partition(":")
                password, _, hostport = tail.rpartition("@")
            host, _, port = hostport.partition(":")
            if not host or not port.isdigit() or not method or not password:
                return None
            return {"name": nm(host, port, frag, "ss"), "type": "ss", "server": host,
                    "port": int(port), "cipher": method, "password": password}

        if sc == "trojan":
            pw, _, tail = rest.rpartition("@")
            tail, _, frag = tail.partition("#")
            hostport, _, qp = tail.partition("?")
            host, _, port = hostport.partition(":")
            if not host or not port.isdigit() or not pw:
                return None
            q = qs(qp)
            p = {"name": nm(host, port, frag, "trojan"), "type": "trojan", "server": host,
                 "port": int(port), "password": urllib.parse.unquote(pw)}
            if q.get("sni"):
                p["sni"] = q["sni"]
            if q.get("fp"):
                p["client-fingerprint"] = q["fp"]
            if q.get("allowInsecure", "").lower() in ("1", "true"):
                p["skip-cert-verify"] = True
            if (q.get("type") or "tcp") == "ws":
                p["network"] = "ws"
                w = {"path": q.get("path") or "/"}
                if q.get("host"):
                    w["headers"] = {"Host": q["host"]}
                p["ws-opts"] = w
            elif q.get("type") == "grpc":
                p["network"] = "grpc"
                p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
            return p

        if sc == "vless":
            uid, _, tail = rest.partition("@")
            tail, _, frag = tail.partition("#")
            hostport, _, qp = tail.partition("?")
            host, _, port = hostport.partition(":")
            if not host or not port.isdigit() or not uid:
                return None
            q = qs(qp)
            p = {"name": nm(host, port, frag, "vless"), "type": "vless", "server": host,
                 "port": int(port), "uuid": uid, "udp": True}
            if (q.get("security") or "tls") in ("tls", "reality"):
                p["tls"] = True
                if q.get("sni"):
                    p["servername"] = q["sni"]
                if q.get("fp"):
                    p["client-fingerprint"] = q["fp"]
                if q.get("security") == "reality":
                    if not q.get("pbk"):
                        return None
                    p["reality-opts"] = {"public-key": q["pbk"]}
                    if q.get("sid"):
                        p["reality-opts"]["short-id"] = q["sid"]
            if q.get("flow"):
                p["flow"] = q["flow"]
            net = q.get("type") or "tcp"
            if net == "ws":
                p["network"] = "ws"
                w = {"path": urllib.parse.unquote(q.get("path") or "/")}
                if q.get("host"):
                    w["headers"] = {"Host": q["host"]}
                p["ws-opts"] = w
            elif net == "grpc":
                p["network"] = "grpc"
                p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
            return p

        if sc in ("hysteria2", "hy2"):
            pw, _, tail = rest.partition("@")
            tail, _, frag = tail.partition("#")
            hostport, _, qp = tail.partition("?")
            host, _, port = hostport.partition(":")
            if not host or not port.isdigit() or not pw:
                return None
            q = qs(qp)
            p = {"name": nm(host, port, frag, "hy2"), "type": "hysteria2", "server": host,
                 "port": int(port), "password": urllib.parse.unquote(pw)}
            if q.get("sni"):
                p["sni"] = q["sni"]
            if q.get("obfs"):
                p["obfs"] = q["obfs"]
            if q.get("obfs-password"):
                p["obfs-password"] = q["obfs-password"]
            if q.get("insecure", "").lower() in ("1", "true"):
                p["skip-cert-verify"] = True
            return p

        if sc == "tuic":
            ui, _, tail = rest.partition("@")
            uid, _, pwd = ui.partition(":")
            tail, _, frag = tail.partition("#")
            hostport, _, qp = tail.partition("?")
            host, _, port = hostport.partition(":")
            if not host or not port.isdigit() or not uid:
                return None
            q = qs(qp)
            p = {"name": nm(host, port, frag, "tuic"), "type": "tuic", "server": host,
                 "port": int(port), "uuid": urllib.parse.unquote(uid),
                 "password": urllib.parse.unquote(pwd or "")}
            if q.get("sni"):
                p["sni"] = q["sni"]
            if q.get("congestion_control"):
                p["congestion-controller"] = q["congestion_control"]
            return p
    except Exception:
        return None
    return None


def parse(text):
    """识别 clash yaml / URI 列表 / base64 三种形态"""
    text = text.strip()
    if not text:
        return []
    if re.search(r"(?m)^proxies\s*:", text):
        try:
            d = yaml.safe_load(text)
            if isinstance(d, dict):
                return [dict(x) for x in (d.get("proxies") or []) if isinstance(x, dict)]
        except Exception:
            return []
    if re.match(r"(?i)^(vmess|vless|ss|trojan|hysteria2|hy2|tuic)://", text):
        out = []
        for ln in text.splitlines():
            p = uri2p(ln)
            if p:
                out.append(p)
        return out
    try:
        dec = b64(text)
    except Exception:
        return []
    if not re.search(r"(?i)(vmess|vless|ss|trojan|hysteria2|hy2|tuic)://", dec):
        return []
    out = []
    for ln in dec.splitlines():
        p = uri2p(ln)
        if p:
            out.append(p)
    return out


def fp(p):
    c = {k: p.get(k) for k in ("type", "server", "port", "uuid", "password", "cipher", "flow") if k in p}
    if p.get("network"):
        c["net"] = p["network"]
    return json.dumps(c, sort_keys=True)


def ensure_mihomo():
    if os.path.exists(BIN):
        return BIN
    os.makedirs(WORK, exist_ok=True)
    url = (f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VER}/"
           f"mihomo-linux-amd64-v3-{MIHOMO_VER}.gz")
    log(f"下载 mihomo {MIHOMO_VER} ...")
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "harvest"}),
                                timeout=120) as r:
        with open(BIN, "wb") as f:
            f.write(gzip.decompress(r.read()))
    os.chmod(BIN, 0o755)
    return BIN


def start(nodes):
    global API
    port = free_port()
    API = f"http://127.0.0.1:{port}"
    cfg = {"mixed-port": free_port(), "mode": "global", "log-level": "warning",
           "external-controller": f"127.0.0.1:{port}", "secret": SECRET,
           "dns": {"enable": True, "nameserver": ["1.1.1.1", "8.8.8.8"]},
           "proxies": nodes,
           "proxy-groups": [{"name": "ALL", "type": "select", "proxies": [p["name"] for p in nodes]}]}
    os.makedirs(WORK, exist_ok=True)
    path = os.path.join(WORK, "probe.yaml")
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, width=4096)
    proc = subprocess.Popen([BIN, "-d", WORK, "-f", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        time.sleep(0.5)
        try:
            local(API + "/version", 2)
            return proc
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("mihomo 启动即退出")
    raise RuntimeError("mihomo API 未就绪")


def stop(proc):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def delay(n, url, tmo):
    p = "/proxies/" + urllib.parse.quote(n) + "/delay?url=" + urllib.parse.quote(url) + f"&timeout={tmo}"
    try:
        return n, local(API + p, tmo / 1000 + 5).get("delay")
    except Exception:
        return n, None


def probe_many(names, url, tmo, c):
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=c) as ex:
        for n, v in ex.map(lambda x: delay(x, url, tmo), names):
            out[n] = v
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    srcs = [l.strip() for l in open(os.path.join(HERE, "sources.txt"), encoding="utf-8")
            if l.strip() and not l.strip().startswith("#")]
    if LIMIT_SRC:
        srcs = srcs[:LIMIT_SRC]
    log(f"== free-nodes harvest ==\n源 {len(srcs)} 个  MAX={MAX_NODES} L1={SMOKE} L2={GH}")

    def one(u):
        try:
            return u, parse(fetch(u)), None
        except Exception as e:
            return u, [], str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_C) as ex:
        parsed = list(ex.map(one, srcs))
    ok = [u for u, it, e in parsed if not e]
    fail = [u for u, it, e in parsed if e]
    for u, it, e in parsed:
        log(f"  {'✓' if not e else '✗'} {u}  {len(it) if not e else e}")
    if not ok:
        log("所有源都失败")
        sys.exit(1)

    seen, fps, cands, adn = {}, set(), [], 0
    for u, items, e in parsed:
        for p in items[:PER_SRC]:
            if len(cands) >= MAX_NODES:
                break
            name = str(p.get("name") or "").strip()
            host = str(p.get("server") or "").strip()
            try:
                port = int(p.get("port") or 0)
            except Exception:
                continue
            if not name or not host or not (1 <= port <= 65535):
                continue
            if AD.search(name):
                adn += 1
                continue
            p = dict(p)
            if name in seen:
                seen[name] += 1
                p["name"] = f"{name} #{seen[name]}"
            else:
                seen[name] = 0
            f = fp(p)
            if f in fps:
                continue
            fps.add(f)
            cands.append(p)
    log(f"候选 {len(cands)} (过滤广告/非法 {adn})")
    if not cands:
        log("无有效候选节点")
        sys.exit(1)

    proc = start(cands)
    try:
        names = [p["name"] for p in cands]
        log(f"L1 测活跃 {len(names)} 个 (并发 {L1_C}, {SMOKE}) ...")
        l1 = probe_many(names, SMOKE, L1_T, L1_C)
        alive = {n: v for n, v in l1.items() if v is not None}
        log(f"  活跃 {len(alive)}/{len(names)}")
        if not alive:
            log("无活跃节点")
            sys.exit(1)

        l2_names = [n for n, _ in sorted(alive.items(), key=lambda x: x[1])[:L2_KEEP]]
        log(f"L2 测 GitHub 可达 ({len(l2_names)} 个) ...")
        l2 = probe_many(l2_names, GH, L2_T, L2_C)
        gh = {n: v for n, v in l2.items() if v is not None}
        log(f"  GitHub 可达 {len(gh)}")

        rank = {}
        for n, v in gh.items():
            rank[n] = v
        for n, v in sorted(alive.items(), key=lambda x: x[1]):
            rank.setdefault(n, 100000 + v)
        ordered = [n for n, _ in sorted(rank.items(), key=lambda x: x[1])]
        m = {p["name"]: p for p in cands}
        final = [m[n] for n in ordered]
        gh_names = [n for n, _ in sorted(gh.items(), key=lambda x: x[1])]
        gh_nodes = [m[n] for n in gh_names]

        def dump(path, nodes, extra_rules=None):
            fn = [p["name"] for p in nodes]
            with open(os.path.join(OUT, path), "w", encoding="utf-8") as f:
                yaml.safe_dump({
                    "proxies": nodes,
                    "proxy-groups": [
                        {"name": "🚀 节点选择", "type": "select",
                         "proxies": (["♻️ 自动选择"] if len(fn) > 1 else []) + fn},
                        {"name": "♻️ 自动选择", "type": "url-test", "url": SMOKE,
                         "interval": 300, "tolerance": 50, "proxies": fn},
                    ] if len(fn) > 1 else [
                        {"name": "🚀 节点选择", "type": "select", "proxies": fn}],
                    "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
                }, f, allow_unicode=True, sort_keys=False, width=4096)

        by = {}
        for p in final:
            by[p["type"]] = by.get(p["type"], 0) + 1
        dump("clash.yaml", final)
        dump("github.yaml", gh_nodes)

        with open(os.path.join(OUT, "status.json"), "w", encoding="utf-8") as f:
            json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "sources_ok": len(ok), "sources_fail": len(fail),
                       "candidates": len(cands), "alive": len(alive),
                       "github_ok": len(gh), "final": len(final), "by_protocol": by,
                       "top_github": [{"name": n, "delay": gh[n]} for n in gh_names[:20]]},
                      f, ensure_ascii=False, indent=1)
        log(f"已生成 output/clash.yaml: 活跃 {len(final)} 个 (GitHub 可达 {len(gh)}) 协议 {by}")
    finally:
        stop(proc)


if __name__ == "__main__":
    ensure_mihomo()
    main()
