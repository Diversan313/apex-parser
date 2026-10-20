"""Конвертация чужих форматов подписок в share-ссылки.

Clash/Mihomo YAML (блок proxies) и sing-box JSON (outbounds) — самые
распространённые форматы, которые отдают реальные подписки, но не
содержат ни одной share-ссылки. Оба сводятся к нашему диалекту URI
(vless/vmess/trojan/ss/hy2), который понимает link_to_xray_outbound.

Поля форматов сверены с документацией mihomo (Meta-Docs, config/proxies)
и sing-box (docs/configuration/outbound + shared/tls и v2ray-transport).
"""
from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any, Dict, List, Optional

try:
    import yaml
    # libyaml в 10-30 раз быстрее на мегабайтных файлах; wheels его bundlят
    _YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
except ImportError:
    yaml = None
    _YAML_LOADER = None

# типы, которые умеет тестировать наш стек; остальное из списка честно
# пропускаем (ssr/tuic/wireguard/http/socks и пр.)
_CLASH_TYPES = ("ss", "vmess", "vless", "trojan", "hysteria2")
_SINGBOX_TYPES = ("shadowsocks", "vmess", "vless", "trojan", "hysteria2")


def _as_int(v) -> Optional[int]:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if not 0 < n < 65536:
        return None
    return n


def _s(v) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _first(v) -> str:
    # Clash допускает и скаляр, и список (h2-opts.host, alpn)
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    return _s(v)


def _join_alpn(v) -> str:
    if isinstance(v, (list, tuple)):
        return ",".join(_s(x) for x in v if _s(x))
    return _s(v)


def _host_in_uri(host: str) -> str:
    # IPv6 без скобок ломает authority-часть URI
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _quote_name(name) -> str:
    return urllib.parse.quote(_s(name), safe="")


def _query(params: List[tuple]) -> str:
    pairs = [(k, v) for k, v in params if v not in ("", None)]
    return urllib.parse.urlencode(pairs) if pairs else ""


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _skip_cert_verify(p: dict) -> str:
    return "1" if p.get("skip-cert-verify") in (True, "true", "True") else ""


# ============================================================
# ОБЩИЕ ЧАСТИ: TLS и транспорт -> query-параметры нашего диалекта
# ============================================================

def _tls_params(security: str, sni: str, alpn: str, fp: str,
                allow_insecure: str, pbk: str = "", sid: str = "") -> List[tuple]:
    # security: "tls" | "reality" | "" (без TLS)
    params = []
    if security:
        params.append(("security", security))
        if sni:
            params.append(("sni", sni))
    if pbk:
        params.append(("pbk", pbk))
    if sid:
        params.append(("sid", sid))
    if fp:
        params.append(("fp", fp))
    if alpn:
        params.append(("alpn", alpn))
    if allow_insecure:
        params.append(("allowInsecure", allow_insecure))
    return params


def _clash_network_params(p: dict) -> Optional[List[tuple]]:
    """network из Clash-прокси -> type/host/path/serviceName.

    Возвращает None для транспортов, которые наш диалект не выражает
    (http-opts, xhttp) — такие записи честно пропускаем.
    """
    network = _s(p.get("network")).lower() or "tcp"
    params = [("type", "tcp")]

    if network == "ws":
        opts = p.get("ws-opts") or {}
        params = [
            ("type", "ws"),
            ("host", _first((opts.get("headers") or {}).get("Host"))),
            ("path", _s(opts.get("path")) or "/"),
        ]
    elif network == "grpc":
        opts = p.get("grpc-opts") or {}
        params = [
            ("type", "grpc"),
            ("serviceName", _s(opts.get("grpc-service-name"))),
        ]
    elif network == "h2":
        opts = p.get("h2-opts") or {}
        params = [
            ("type", "h2"),
            ("host", _first(opts.get("host"))),
            ("path", _s(opts.get("path")) or "/"),
        ]
    elif network in ("tcp", "none", ""):
        params = [("type", "tcp")]
    else:
        # http (network), xhttp и прочее экзотическое не маппится
        return None
    return params


def _singbox_transport_params(t: dict) -> Optional[List[tuple]]:
    ttype = _s(t.get("type")).lower()
    if ttype in ("", "tcp"):
        return [("type", "tcp")]
    if ttype == "ws":
        headers = t.get("headers") or {}
        return [
            ("type", "ws"),
            ("host", _first(headers.get("Host"))),
            ("path", _s(t.get("path")) or "/"),
        ]
    if ttype == "grpc":
        return [
            ("type", "grpc"),
            ("serviceName", _s(t.get("service_name"))),
        ]
    # sing-box "http" = HTTP/2 транспорт (= Xray h2)
    if ttype == "http":
        return [
            ("type", "h2"),
            ("host", _first(t.get("host"))),
            ("path", _s(t.get("path")) or "/"),
        ]
    # quic/httpupgrade нашим диалектом не выражаются
    return None


# ============================================================
# CLASH / MIHOMO
# ============================================================

def _clash_tls_parts(p: dict):
    """(security, sni, alpn, fp, allowInsecure, pbk, sid) из Clash-прокси."""
    sni = _s(p.get("servername")) or _s(p.get("sni"))
    alpn = _join_alpn(p.get("alpn"))
    fp = _s(p.get("client-fingerprint"))
    allow_insecure = _skip_cert_verify(p)

    reality = p.get("reality-opts") or {}
    pbk = _s(reality.get("public-key"))
    sid = _s(reality.get("short-id"))

    if pbk:
        # REALITY без fingerprint в Xray не работает; chrome — стандартный
        # дефолт экосистемы (v2rayN поступает так же)
        return "reality", sni, alpn, fp or "chrome", allow_insecure, pbk, sid
    if p.get("tls") in (True, "true", "True"):
        return "tls", sni, alpn, fp, allow_insecure, "", ""
    return "", sni, alpn, fp, allow_insecure, "", ""


def _clash_ss_plugin(p: dict) -> Optional[str]:
    """SIP003-плагин целиком; None — плагин нам незнаком, запись пропускаем."""
    plugin = _s(p.get("plugin"))
    if not plugin:
        return None
    opts = p.get("plugin-opts") or {}

    if plugin in ("obfs", "obfs-local", "simple-obfs"):
        mode = _s(opts.get("mode")) or "http"
        parts = [f"obfs={mode}"]
        if opts.get("host"):
            parts.append(f"obfs-host={_first(opts.get('host'))}")
        return "obfs-local;" + ";".join(parts)

    if plugin == "v2ray-plugin":
        parts = []
        mode = _s(opts.get("mode"))
        if mode:
            parts.append(f"mode={mode}")
        if opts.get("tls"):
            parts.append("tls")
        if opts.get("host"):
            parts.append(f"host={_first(opts.get('host'))}")
        if opts.get("path"):
            parts.append(f"path={_s(opts.get('path'))}")
        return "v2ray-plugin;" + ";".join(parts)

    # shadow-tls/restls/jls и прочее экзотическое — мимо
    return None


def clash_proxy_to_link(p: dict) -> Optional[str]:
    """Одна Clash-запись proxies -> share-ссылка (или None)."""
    if not isinstance(p, dict):
        return None
    ptype = _s(p.get("type")).lower()
    server = _s(p.get("server"))
    port = _as_int(p.get("port"))
    if ptype not in _CLASH_TYPES or not server or not port:
        return None

    name = p.get("name")
    host = _host_in_uri(server)

    if ptype == "vless":
        uuid_ = _s(p.get("uuid"))
        if not uuid_:
            return None
        net = _clash_network_params(p)
        if net is None:
            return None
        security, sni, alpn, fp, insecure, pbk, sid = _clash_tls_parts(p)
        q = _tls_params(security, sni, alpn, fp, insecure, pbk, sid)
        flow = _s(p.get("flow"))
        params = [
            ("encryption", "none"),
            *([("flow", flow)] if flow else []),
            *net,
            *q,
        ]
        query = _query(params)
        return f"vless://{uuid_}@{host}:{port}?{query}#{_quote_name(name)}" if query else \
               f"vless://{uuid_}@{host}:{port}#{_quote_name(name)}"

    if ptype == "vmess":
        uuid_ = _s(p.get("uuid"))
        if not uuid_:
            return None
        security, sni, alpn, fp, _insecure, pbk, _sid = _clash_tls_parts(p)
        # vmess-reality нашим b64-JSON диалектом не выражается
        if pbk:
            return None
        network = _s(p.get("network")).lower() or "tcp"
        payload = {
            "v": "2",
            "ps": _s(name),
            "add": server,
            "port": str(port),
            "id": uuid_,
            "aid": str(_as_int(p.get("alterId")) or 0),
            "scy": _s(p.get("cipher")) or "auto",
            "net": network,
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls" if security else "",
            "sni": sni,
            "alpn": alpn,
            "fp": fp,
        }
        if network == "ws":
            opts = p.get("ws-opts") or {}
            payload["host"] = _first((opts.get("headers") or {}).get("Host"))
            payload["path"] = _s(opts.get("path")) or "/"
        elif network == "grpc":
            opts = p.get("grpc-opts") or {}
            payload["path"] = _s(opts.get("grpc-service-name"))
        elif network == "h2":
            opts = p.get("h2-opts") or {}
            payload["host"] = _first(opts.get("host"))
            payload["path"] = _s(opts.get("path")) or "/"
        return "vmess://" + _b64(json.dumps(payload, ensure_ascii=False,
                                             separators=(",", ":")))

    if ptype == "trojan":
        password = _s(p.get("password"))
        if not password:
            return None
        net = _clash_network_params(p)
        if net is None:
            return None
        # trojan без reality-полей отдаёт tls+reality-набор; reality-opts для
        # trojan редки, но если заданы — считаем записью мимо нашего диалекта
        if _s((p.get("reality-opts") or {}).get("public-key")):
            return None
        # trojan = TLS всегда; sni в Clash-схеме trojan лежит в sni
        sni = _s(p.get("sni")) or _s(p.get("servername"))
        q = _tls_params(
            "tls", sni, _join_alpn(p.get("alpn")),
            _s(p.get("client-fingerprint")), _skip_cert_verify(p),
        )
        params = [*net, *q]
        query = _query(params)
        return f"trojan://{urllib.parse.quote(password, safe='')}@{host}:{port}?{query}#{_quote_name(name)}" \
            if query else \
            f"trojan://{urllib.parse.quote(password, safe='')}@{host}:{port}#{_quote_name(name)}"

    if ptype == "ss":
        method = _s(p.get("cipher"))
        password = _s(p.get("password"))
        if not method or not password:
            return None
        params = []
        plugin = _clash_ss_plugin(p)
        if plugin is None and _s(p.get("plugin")):
            return None  # незнакомый плагин не выкинем битой ссылкой
        if plugin:
            params.append(("plugin", plugin))
        query = _query(params)
        userinfo = _b64(f"{method}:{password}")
        base = f"ss://{userinfo}@{host}:{port}"
        return f"{base}?{query}#{_quote_name(name)}" if query else \
               f"{base}#{_quote_name(name)}"

    if ptype == "hysteria2":
        password = _s(p.get("password")) or _s(p.get("auth"))
        if not password:
            return None
        # port hopping: ports перекрывает port
        ports = _s(p.get("ports"))
        if ports:
            host_port = f"{host}:{port},{ports}"
        else:
            host_port = f"{host}:{port}"
        params = [
            ("sni", _s(p.get("sni"))),
            ("insecure", _skip_cert_verify(p)),
            ("obfs", _s(p.get("obfs"))),
            ("obfs-password", _s(p.get("obfs-password"))),
            ("up", _s(p.get("up")).replace(" ", "")),
            ("down", _s(p.get("down")).replace(" ", "")),
            # Clash fingerprint = sha256 серта, у нас это pinSHA256
            ("pinSHA256", _s(p.get("fingerprint")).replace(":", "")),
        ]
        query = _query(params)
        auth = urllib.parse.quote(password, safe="")
        return f"hysteria2://{auth}@{host_port}?{query}#{_quote_name(name)}" if query else \
               f"hysteria2://{auth}@{host_port}#{_quote_name(name)}"

    return None


# ============================================================
# SING-BOX
# ============================================================

def _singbox_tls_parts(tls: dict):
    tls = tls or {}
    sni = _s(tls.get("server_name"))
    alpn = _join_alpn(tls.get("alpn"))
    utls = tls.get("utls") or {}
    fp = _s(utls.get("fingerprint")) if utls.get("enabled") else ""
    insecure = "1" if tls.get("insecure") else ""
    reality = tls.get("reality") or {}
    pbk = _s(reality.get("public_key")) if reality.get("enabled") else ""
    sid = _first(reality.get("short_id")) if reality.get("enabled") else ""

    if pbk:
        return "reality", sni, alpn, fp or "chrome", insecure, pbk, sid
    if tls.get("enabled"):
        return "tls", sni, alpn, fp, insecure, "", ""
    return "", sni, alpn, fp, insecure, "", ""


def singbox_outbound_to_link(ob: dict) -> Optional[str]:
    """Один sing-box outbound -> share-ссылка (или None)."""
    if not isinstance(ob, dict):
        return None
    otype = _s(ob.get("type")).lower()
    server = _s(ob.get("server"))
    port = _as_int(ob.get("server_port"))
    # direct/block/dns/selector и пр. не имеют server — отсеиваются здесь же
    if otype not in _SINGBOX_TYPES or not server or not port:
        return None

    name = ob.get("tag")
    host = _host_in_uri(server)
    tls = ob.get("tls") or {}
    transport = ob.get("transport") or {}

    security, sni, alpn, fp, insecure, pbk, sid = _singbox_tls_parts(tls)
    net = _singbox_transport_params(transport)
    if net is None:
        return None

    if otype == "vless":
        uuid_ = _s(ob.get("uuid"))
        if not uuid_:
            return None
        q = _tls_params(security, sni, alpn, fp, insecure, pbk, sid)
        flow = _s(ob.get("flow"))
        params = [
            ("encryption", "none"),
            *([("flow", flow)] if flow else []),
            *net,
            *q,
        ]
        query = _query(params)
        return f"vless://{uuid_}@{host}:{port}?{query}#{_quote_name(name)}" if query else \
               f"vless://{uuid_}@{host}:{port}#{_quote_name(name)}"

    if otype == "vmess":
        uuid_ = _s(ob.get("uuid"))
        if not uuid_:
            return None
        if pbk:
            return None
        network = _s(transport.get("type")).lower() or "tcp"
        payload = {
            "v": "2",
            "ps": _s(name),
            "add": server,
            "port": str(port),
            "id": uuid_,
            "aid": "0",
            "scy": _s(ob.get("security")) or "auto",
            "net": network,
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls" if security else "",
            "sni": sni,
            "alpn": alpn,
            "fp": fp,
        }
        if network == "ws":
            headers = transport.get("headers") or {}
            payload["host"] = _first(headers.get("Host"))
            payload["path"] = _s(transport.get("path")) or "/"
        elif network == "grpc":
            payload["path"] = _s(transport.get("service_name"))
        elif network == "http":
            payload["net"] = "h2"
            payload["host"] = _first(transport.get("host"))
            payload["path"] = _s(transport.get("path")) or "/"
        return "vmess://" + _b64(json.dumps(payload, ensure_ascii=False,
                                             separators=(",", ":")))

    if otype == "trojan":
        password = _s(ob.get("password"))
        if not password:
            return None
        if pbk:
            return None
        # trojan = TLS всегда; без tls.enabled узел всё равно не рабочий
        q = _tls_params("tls", sni, alpn, fp, insecure)
        params = [*net, *q]
        query = _query(params)
        return f"trojan://{urllib.parse.quote(password, safe='')}@{host}:{port}?{query}#{_quote_name(name)}" \
            if query else \
            f"trojan://{urllib.parse.quote(password, safe='')}@{host}:{port}#{_quote_name(name)}"

    if otype == "shadowsocks":
        method = _s(ob.get("method"))
        password = _s(ob.get("password"))
        if not method or not password:
            return None
        params = []
        plugin = _s(ob.get("plugin"))
        if plugin:
            # plugin_opts в sing-box — строка "obfs=http;obfs-host=x"
            opts = _s(ob.get("plugin_opts"))
            if plugin not in ("obfs-local", "v2ray-plugin"):
                return None
            value = plugin + (";" + opts if opts else "")
            params.append(("plugin", value))
        query = _query(params)
        userinfo = _b64(f"{method}:{password}")
        base = f"ss://{userinfo}@{host}:{port}"
        return f"{base}?{query}#{_quote_name(name)}" if query else \
               f"{base}#{_quote_name(name)}"

    if otype == "hysteria2":
        password = _s(ob.get("password"))
        if not password:
            return None
        obfs = ob.get("obfs") or {}
        # server_ports: ["2080:3000"] -> формат hop-портов URI через дефис
        ranges = ",".join(
            _s(x).replace(":", "-") for x in (ob.get("server_ports") or [])
        )
        host_port = f"{host}:{port},{ranges}" if ranges else f"{host}:{port}"
        params = [
            ("sni", sni),
            ("insecure", insecure),
            ("obfs", _s(obfs.get("type"))),
            ("obfs-password", _s(obfs.get("password"))),
            ("up", str(_as_int(ob.get("up_mbps")) or "")),
            ("down", str(_as_int(ob.get("down_mbps")) or "")),
        ]
        query = _query(params)
        auth = urllib.parse.quote(password, safe="")
        return f"hysteria2://{auth}@{host_port}?{query}#{_quote_name(name)}" if query else \
               f"hysteria2://{auth}@{host_port}#{_quote_name(name)}"

    return None


# ============================================================
# ВХОДНЫЕ ТОЧКИ: текст подписки -> список share-ссылок
# ============================================================

def _dedup_links(links: List[str]) -> List[str]:
    out, seen = [], set()
    for link in links:
        key = link.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(link)
    return out


def foreign_yaml_to_links(text: str) -> List[str]:
    """Clash YAML (proxies:) либо sing-box в YAML-обёртке (outbounds:)."""
    if yaml is None or not text.strip():
        return []
    try:
        data = yaml.load(text, Loader=_YAML_LOADER)
    except Exception:
        return []

    links: List[str] = []

    def _proxies(node) -> None:
        if isinstance(node, dict):
            proxies = node.get("proxies")
            if isinstance(proxies, list):
                for item in proxies:
                    link = clash_proxy_to_link(item)
                    if link:
                        links.append(link)
            outbounds = node.get("outbounds")
            if isinstance(outbounds, list):
                for item in outbounds:
                    link = singbox_outbound_to_link(item)
                    if link:
                        links.append(link)
        elif isinstance(node, list):
            for item in node:
                link = clash_proxy_to_link(item) or singbox_outbound_to_link(item)
                if link:
                    links.append(link)

    _proxies(data)
    return _dedup_links(links)


def singbox_json_to_links(text: str) -> List[str]:
    """sing-box JSON (полный конфиг, голый список или один outbound)."""
    try:
        data = json.loads(text)
    except Exception:
        return []

    links: List[str] = []

    def _walk(node) -> None:
        if isinstance(node, dict):
            outbounds = node.get("outbounds")
            if isinstance(outbounds, list):
                for item in outbounds:
                    link = singbox_outbound_to_link(item)
                    if link:
                        links.append(link)
            else:
                link = singbox_outbound_to_link(node)
                if link:
                    links.append(link)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return _dedup_links(links)
