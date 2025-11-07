# time_sync_via_proxy.py
# Force Windows system proxy, fetch network time via HTTPS Date headers, set system time.
# Requires Administrator. Windows only.

import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit, urlencode
import random, string, time, sys
import winreg


# ---------------- Windows constants and structs ----------------
HINTERNET = W.HANDLE
LPWSTR = W.LPWSTR
LPCWSTR = W.LPCWSTR
LPVOID = W.LPVOID
DWORD = W.DWORD
BOOL = W.BOOL

WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3

WINHTTP_NO_REFERER = None
WINHTTP_DEFAULT_ACCEPT_TYPES = None
WINHTTP_FLAG_SECURE = 0x00800000

WINHTTP_OPTION_PROXY = 38
WINHTTP_QUERY_DATE = 9
WINHTTP_QUERY_STATUS_CODE = 19
WINHTTP_QUERY_FLAG_SYSTEMTIME = 0x40000000

WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002
WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

# Token privilege constants
SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x08

class SYSTEMTIME(C.Structure):
    _fields_ = [
        ("wYear", W.WORD), ("wMonth", W.WORD), ("wDayOfWeek", W.WORD), ("wDay", W.WORD),
        ("wHour", W.WORD), ("wMinute", W.WORD), ("wSecond", W.WORD), ("wMilliseconds", W.WORD),
    ]

class LUID(C.Structure):
    _fields_ = [("LowPart", DWORD), ("HighPart", C.c_long)]

class LUID_AND_ATTRIBUTES(C.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", DWORD)]

class TOKEN_PRIVILEGES(C.Structure):
    _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(C.Structure):
    _fields_ = [
        ("fAutoDetect", BOOL),
        ("lpszAutoConfigUrl", LPWSTR),
        ("lpszProxy", LPWSTR),
        ("lpszProxyBypass", LPWSTR),
    ]

class WINHTTP_AUTOPROXY_OPTIONS(C.Structure):
    _fields_ = [
        ("dwFlags", DWORD),
        ("dwAutoDetectFlags", DWORD),
        ("lpszAutoConfigUrl", LPCWSTR),
        ("lpvReserved", LPVOID),
        ("dwReserved", DWORD),
        ("fAutoLogonIfChallenged", BOOL),
    ]

class WINHTTP_PROXY_INFO(C.Structure):
    _fields_ = [
        ("dwAccessType", DWORD),
        ("lpszProxy", LPWSTR),
        ("lpszProxyBypass", LPWSTR),
    ]

# ---------------- DLLs ----------------
winhttp = C.WinDLL("winhttp", use_last_error=True)
kernel32 = C.WinDLL("kernel32", use_last_error=True)
advapi32 = C.WinDLL("advapi32", use_last_error=True)
shell32 = C.WinDLL("shell32", use_last_error=True)

# Prototypes
winhttp.WinHttpOpen.argtypes = [LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD]
winhttp.WinHttpOpen.restype = HINTERNET

winhttp.WinHttpCloseHandle.argtypes = [HINTERNET]
winhttp.WinHttpCloseHandle.restype = BOOL

winhttp.WinHttpConnect.argtypes = [HINTERNET, LPCWSTR, W.WORD, DWORD]
winhttp.WinHttpConnect.restype = HINTERNET

winhttp.WinHttpOpenRequest.argtypes = [HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPVOID, DWORD]
winhttp.WinHttpOpenRequest.restype = HINTERNET

winhttp.WinHttpSetOption.argtypes = [HINTERNET, DWORD, LPVOID, DWORD]
winhttp.WinHttpSetOption.restype = BOOL

winhttp.WinHttpSendRequest.argtypes = [HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD]
winhttp.WinHttpSendRequest.restype = BOOL

winhttp.WinHttpReceiveResponse.argtypes = [HINTERNET, LPVOID]
winhttp.WinHttpReceiveResponse.restype = BOOL

winhttp.WinHttpQueryHeaders.argtypes = [HINTERNET, DWORD, LPCWSTR, LPVOID, C.POINTER(DWORD), C.POINTER(DWORD)]
winhttp.WinHttpQueryHeaders.restype = BOOL

winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [C.POINTER(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG)]
winhttp.WinHttpGetIEProxyConfigForCurrentUser.restype = BOOL

winhttp.WinHttpGetProxyForUrl.argtypes = [HINTERNET, LPCWSTR, C.POINTER(WINHTTP_AUTOPROXY_OPTIONS), C.POINTER(WINHTTP_PROXY_INFO)]
winhttp.WinHttpGetProxyForUrl.restype = BOOL

advapi32.OpenProcessToken.argtypes = [W.HANDLE, DWORD, C.POINTER(W.HANDLE)]
advapi32.OpenProcessToken.restype = BOOL

advapi32.LookupPrivilegeValueW.argtypes = [LPCWSTR, LPCWSTR, C.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = BOOL

advapi32.AdjustTokenPrivileges.argtypes = [W.HANDLE, BOOL, C.POINTER(TOKEN_PRIVILEGES), DWORD, LPVOID, LPVOID]
advapi32.AdjustTokenPrivileges.restype = BOOL

kernel32.GetCurrentProcess.restype = W.HANDLE
kernel32.GetLastError.restype = DWORD
kernel32.SetSystemTime.argtypes = [C.POINTER(SYSTEMTIME)]
kernel32.SetSystemTime.restype = BOOL

# Optional higher precision
try:
    kernel32.GetSystemTimePreciseAsFileTime
    HAS_PRECISE = True
except AttributeError:
    HAS_PRECISE = False

def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False

def enable_settime_privilege():
    hToken = W.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, C.byref(hToken)):
        raise OSError("OpenProcessToken failed")
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeSystemtimePrivilege", C.byref(luid)):
        raise OSError("LookupPrivilegeValue failed")
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if not advapi32.AdjustTokenPrivileges(hToken, False, C.byref(tp), 0, None, None):
        raise OSError("AdjustTokenPrivileges failed")

def dt_to_systemtime(dt_utc: datetime) -> SYSTEMTIME:
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    dt_utc = dt_utc.astimezone(timezone.utc)
    st = SYSTEMTIME()
    st.wYear = dt_utc.year
    st.wMonth = dt_utc.month
    st.wDay = dt_utc.day
    st.wHour = dt_utc.hour
    st.wMinute = dt_utc.minute
    st.wSecond = dt_utc.second
    st.wMilliseconds = int(dt_utc.microsecond / 1000)
    return st

def median(lst):
    s = sorted(lst)
    n = len(s)
    if n == 0:
        return None
    if n % 2 == 1:
        return s[n//2]
    return (s[n//2 - 1] + s[n//2]) / 2

def now_utc() -> datetime:
    return datetime.utcnow().replace(tzinfo=timezone.utc)

def _random_buster():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))

def get_ie_proxy_config():
    cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    ok = winhttp.WinHttpGetIEProxyConfigForCurrentUser(C.byref(cfg))
    return ok, cfg

def get_proxy_from_inet_settings() -> str | None:
    """直接读取 Windows GUI（WinINET）代理配置"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        if enable != 1:
            return None
        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
        if not proxy_server:
            return None
        return proxy_server
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[WARN] read proxy from registry failed: {e}")
        return None


def get_proxy_for_url(hSession, url: str):
    """优先读取 WinHTTP；若无则直接读取 WinINET；最后 fallback 到 localhost"""
    ok_ie, cfg = get_ie_proxy_config()
    opts = WINHTTP_AUTOPROXY_OPTIONS()
    opts.fAutoLogonIfChallenged = True
    if ok_ie:
        if cfg.lpszAutoConfigUrl:
            opts.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL
            opts.lpszAutoConfigUrl = cfg.lpszAutoConfigUrl
        if cfg.fAutoDetect:
            opts.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT
            opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
    else:
        opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
        opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A

    pinfo = WINHTTP_PROXY_INFO()
    ok = winhttp.WinHttpGetProxyForUrl(hSession, url, C.byref(opts), C.byref(pinfo))

    if not ok or not pinfo.lpszProxy:
        # 尝试读取 GUI 系统代理（WinINET）
        reg_proxy = get_proxy_from_inet_settings()
        if reg_proxy:
            print(f"[INFO] Using proxy from Internet Settings: {reg_proxy}")
            pinfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY
            pinfo.lpszProxy = C.c_wchar_p(reg_proxy)
            pinfo.lpszProxyBypass = None
            return pinfo
        # fallback
        print("[WARN] No proxy detected, fallback to localhost:7890")
        pinfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY
        pinfo.lpszProxy = C.c_wchar_p("127.0.0.1:7890")
        pinfo.lpszProxyBypass = None
    return pinfo


def http_date_via_proxy(hSession, url: str, pinfo, timeout_ms=5000):
    # Parse URL (https only)
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise ValueError("HTTPS required")
    host = parts.hostname
    port = parts.port or 443
    path = parts.path or "/"
    qs = parts.query
    # Cache-buster to avoid stale proxies
    extra = urlencode({"_": _random_buster()})
    if qs:
        path_q = f"{path}?{qs}&{extra}"
    else:
        path_q = f"{path}?{extra}"

    # Connect and open request
    hConnect = winhttp.WinHttpConnect(hSession, host, port, 0)
    if not hConnect:
        raise OSError("WinHttpConnect failed")

    try:
        # Prefer HEAD. Some servers reject HEAD; fallback to GET.
        for verb in ("HEAD", "GET"):
            hReq = winhttp.WinHttpOpenRequest(
                hConnect,
                verb,
                path_q,
                "HTTP/1.1",
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE
            )
            if not hReq:
                continue
            try:
                if not winhttp.WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY, C.byref(pinfo), C.sizeof(pinfo)):
                    raise OSError("WinHttpSetOption(PROXY) failed")

                # Timeouts (resolve, connect, send, receive)
                for opt, val in [(2, timeout_ms), (3, timeout_ms), (4, timeout_ms), (5, timeout_ms)]:
                    # OPTION indices 2..5 are documented timeouts on WinHTTP handles
                    winhttp.WinHttpSetOption(hReq, opt, C.byref(DWORD(val)), C.sizeof(DWORD))

                # Minimal headers to avoid proxy caches
                hdr = "Cache-Control: no-cache\r\nPragma: no-cache\r\nConnection: keep-alive\r\n"
                t0 = now_utc()
                if not winhttp.WinHttpSendRequest(hReq, hdr, len(hdr), None, 0, 0, 0):
                    continue
                if not winhttp.WinHttpReceiveResponse(hReq, None):
                    continue
                t1 = now_utc()

                # Check status
                status_len = DWORD(0)
                winhttp.WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE, None, None, C.byref(status_len), None)
                buf = C.create_unicode_buffer(status_len.value // 2)
                if not winhttp.WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE, None, buf, C.byref(status_len), None):
                    continue
                status = int(buf.value.strip())

                # Query Date as SYSTEMTIME (UTC)
                st = SYSTEMTIME()
                st_size = DWORD(C.sizeof(st))
                if not winhttp.WinHttpQueryHeaders(hReq, WINHTTP_QUERY_DATE | WINHTTP_QUERY_FLAG_SYSTEMTIME, None, C.byref(st), C.byref(st_size), None):
                    continue

                server_dt = datetime(st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds * 1000, tzinfo=timezone.utc)

                # RTT mid-point correction
                # Map to mid-point between t0 and t1
                t_mid = t0 + (t1 - t0) / 2
                offset = (server_dt - t_mid).total_seconds()
                return server_dt, offset, status
            finally:
                winhttp.WinHttpCloseHandle(hReq)
        raise OSError("Failed to obtain Date header via proxy from all verbs")
    finally:
        winhttp.WinHttpCloseHandle(hConnect)

def estimate_offset_via_multiple(hSession, urls):
    offsets = []
    samples = []
    # Attach per-URL proxy
    pinfo = get_proxy_for_url(hSession, urls[0])
    for u in urls:
        try:
            dt, off, status = http_date_via_proxy(hSession, u, pinfo)
            offsets.append(off)
            samples.append((u, dt, off, status))
        except Exception as e:
            samples.append((u, None, None, f"error: {e}"))
    med = median(offsets) if offsets else None
    return med, samples

def set_system_time_by_offset(offset_sec: float):
    # Compute new UTC = current UTC + offset
    new_utc = now_utc() + timedelta(seconds=offset_sec)
    st = dt_to_systemtime(new_utc)
    if not kernel32.SetSystemTime(C.byref(st)):
        raise OSError(f"SetSystemTime failed with error {kernel32.GetLastError()}")

def main():
    if sys.platform != "win32":
        print("Windows only.")
        sys.exit(1)
    if not is_admin():
        print("Run this script as Administrator.")
        sys.exit(1)

    # Open WinHTTP session using default proxy space
    ua = "TimeSyncProxy/1.0"
    hSession = winhttp.WinHttpOpen(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, None, None, 0)
    if not hSession:
        print("WinHttpOpen failed")
        sys.exit(1)

    urls = [
        "https://www.google.com/generate_204",
        "https://www.microsoft.com/",
        "https://www.cloudflare.com/",
        "https://aka.ms/diag",  # usually fast CDN
    ]

    try:
        local_before = datetime.now().astimezone()
        utc_before = now_utc()

        med_off, samples = estimate_offset_via_multiple(hSession, urls)
        if med_off is None:
            print("No valid samples via proxy. Abort.")
            for u, dt, off, info in samples:
                print(f"  {u}: {info}")
            sys.exit(2)

        # Choose representative network time from the sample nearest to median
        best = min([s for s in samples if isinstance(s[2], (int, float))], key=lambda s: abs(s[2] - med_off))
        best_url, best_dt, best_off, best_status = best

        print("=== Before update ===")
        print(f"Local time: {local_before.isoformat()}")
        print(f"Local UTC:  {utc_before.isoformat()}")
        print(f"Network UTC (via {best_url} Date): {best_dt.isoformat()}")
        print(f"Estimated offset (Network - Local) [s]: {med_off:.3f}")
        print("Samples:")
        for u, dt, off, status in samples:
            print(f"  {u:<36} -> offset={off if off is not None else 'NA':>8}  status={status}")

        # Enable privilege and set system time
        enable_settime_privilege()
        set_system_time_by_offset(med_off)

        # Re-check
        time.sleep(0.5)
        utc_after = now_utc()
        med_off2, samples2 = estimate_offset_via_multiple(hSession, urls)
        print("\n=== After update ===")
        print(f"Local UTC now: {utc_after.isoformat()}")
        if med_off2 is None:
            print("Post-update check failed via proxy.")
        else:
            best2 = min([s for s in samples2 if isinstance(s[2], (int, float))], key=lambda s: abs(s[2] - med_off2))
            print(f"Network UTC sample: {best2[1].isoformat()}  from {best2[0]}")
            print(f"Residual offset [s]: {med_off2:.3f}")
    finally:
        winhttp.WinHttpCloseHandle(hSession)

if __name__ == "__main__":
    try:
        main()
        input()
    except Exception as e:
        print(f"[ERROR] {e}")
        input()
        sys.exit(1)
