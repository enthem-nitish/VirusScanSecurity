"""
VirusScan Security — APK Static Analyzer
Evidence-first Android APK analysis.

Design goals:
- Minimize false positives on normal/legitimate applications.
- Never treat an ordinary HTTPS URL, common TLD, camera, microphone,
  encryption, WebView, reflection, native code, or debug certificate as
  malware by itself.
- Require corroborating evidence before assigning a high risk score.
- Keep FUD/evasion analysis separate from malware verdicts.
- No demo/fallback findings are returned. Every finding comes from the APK.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Androguard compatibility
# ---------------------------------------------------------------------------

try:
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK
        ANDROGUARD_AVAILABLE = True
    except ImportError:
        APK = None
        ANDROGUARD_AVAILABLE = False


# ---------------------------------------------------------------------------
# Permission intelligence
# ---------------------------------------------------------------------------

# These are capabilities, not malware indicators. They are only useful when
# combined with evidence showing why the app requests them.
SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
}

# Capabilities with substantially higher abuse potential. These still do not
# mean "malware" without corroborating behavior.
HIGH_IMPACT_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
}

# Only combinations that represent a meaningful behavioral story are scored.
# INTERNET is intentionally not included because it is ubiquitous.
HIGH_RISK_PERMISSION_COMBOS = [
    (
        {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
         "android.permission.SEND_SMS"},
        "SMS interception and sending",
    ),
    (
        {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"},
        "SMS reading/interception",
    ),
    (
        {"android.permission.BIND_ACCESSIBILITY_SERVICE",
         "android.permission.SYSTEM_ALERT_WINDOW"},
        "Accessibility plus overlay control",
    ),
    (
        {"android.permission.BIND_DEVICE_ADMIN",
         "android.permission.RECEIVE_BOOT_COMPLETED"},
        "Device administration plus boot persistence",
    ),
    (
        {"android.permission.REQUEST_INSTALL_PACKAGES",
         "android.permission.RECEIVE_BOOT_COMPLETED"},
        "Package installation plus boot persistence",
    ),
    (
        {"android.permission.MANAGE_EXTERNAL_STORAGE",
         "android.permission.REQUEST_INSTALL_PACKAGES"},
        "Broad storage access plus package installation",
    ),
]


# ---------------------------------------------------------------------------
# Manifest / intent intelligence
# ---------------------------------------------------------------------------

SENSITIVE_INTENTS = {
    "android.provider.Telephony.SMS_RECEIVED": (
        "Receives incoming SMS broadcasts",
        "sms",
    ),
    "android.provider.Telephony.SMS_DELIVER": (
        "Receives SMS delivery broadcasts",
        "sms",
    ),
    "android.intent.action.NEW_OUTGOING_CALL": (
        "Observes outgoing calls",
        "call",
    ),
    "android.intent.action.PHONE_STATE": (
        "Observes phone state changes",
        "call",
    ),
    "android.intent.action.BOOT_COMPLETED": (
        "Starts after device boot",
        "persistence",
    ),
    "android.intent.action.LOCKED_BOOT_COMPLETED": (
        "Starts after locked boot",
        "persistence",
    ),
    "android.intent.action.PACKAGE_ADDED": (
        "Observes application installation events",
        "app_monitoring",
    ),
    "android.intent.action.PACKAGE_REPLACED": (
        "Observes application replacement/update events",
        "app_monitoring",
    ),
    "android.intent.action.USER_PRESENT": (
        "Observes device unlock",
        "device_state",
    ),
}


# ---------------------------------------------------------------------------
# API / bytecode intelligence
# ---------------------------------------------------------------------------

# API families are grouped by behavior. Common SDK APIs deliberately have
# weight zero because their presence is normal in legitimate applications.
API_PATTERNS: Dict[str, Dict[str, Any]] = {
    "sms_read": {
        "patterns": (
            "Landroid/content/ContentResolver;->query",
            "Landroid/provider/Telephony$Sms",
            "Landroid/telephony/SmsManager",
        ),
        "description": "SMS-related API usage",
        "weight": 4,
        "high_impact": True,
    },
    "command_execution": {
        "patterns": (
            "Ljava/lang/Runtime;->exec",
            "Ljava/lang/ProcessBuilder",
        ),
        "description": "OS/process command execution API",
        "weight": 10,
        "high_impact": True,
    },
    "dynamic_code_loading": {
        "patterns": (
            "Ldalvik/system/DexClassLoader",
            "Ldalvik/system/PathClassLoader",
        ),
        "description": "Dynamic class/DEX loading",
        "weight": 5,
        "high_impact": True,
    },
    "accessibility": {
        "patterns": (
            "Landroid/accessibilityservice/",
            "Landroid/view/accessibility/AccessibilityNodeInfo",
        ),
        "description": "Accessibility framework usage",
        "weight": 8,
        "high_impact": True,
    },
    "device_admin": {
        "patterns": (
            "Landroid/app/admin/DevicePolicyManager",
        ),
        "description": "Device administration API usage",
        "weight": 8,
        "high_impact": True,
    },
    "overlay": {
        "patterns": (
            "TYPE_APPLICATION_OVERLAY",
            "Landroid/view/WindowManager$LayoutParams;",
        ),
        "description": "Overlay/window management API usage",
        "weight": 5,
        "high_impact": True,
    },
    "installed_apps": {
        "patterns": (
            "Landroid/content/pm/PackageManager;->getInstalledPackages",
            "Landroid/content/pm/PackageManager;->getInstalledApplications",
        ),
        "description": "Installed application enumeration",
        "weight": 4,
        "high_impact": False,
    },
    "webview": {
        "patterns": (
            "Landroid/webkit/WebView;->loadUrl",
            "Landroid/webkit/WebView;->addJavascriptInterface",
        ),
        "description": "WebView/JavaScript bridge usage",
        "weight": 1,
        "high_impact": False,
    },
    "crypto": {
        "patterns": (
            "Ljavax/crypto/Cipher",
            "Ljava/security/MessageDigest",
            "Ljava/security/KeyStore",
        ),
        "description": "Cryptography/security API usage",
        "weight": 0,
        "high_impact": False,
    },
    "reflection": {
        "patterns": (
            "Ljava/lang/reflect/",
        ),
        "description": "Java reflection",
        "weight": 0,
        "high_impact": False,
    },
    "network": {
        "patterns": (
            "Ljava/net/HttpURLConnection",
            "Lokhttp3/",
            "Lretrofit2/",
            "Landroid/net/http/",
        ),
        "description": "Network library/API usage",
        "weight": 0,
        "high_impact": False,
    },
    "device_info": {
        "patterns": (
            "Landroid/os/Build;",
            "Landroid/provider/Settings$Secure;",
        ),
        "description": "Device/environment information access",
        "weight": 0,
        "high_impact": False,
    },
}


# Exact indicators that can support an evasion assessment. These are NOT
# automatically malware findings.
FUD_API_PATTERNS = {
    "Ldalvik/system/DexClassLoader": (
        "Dynamic DEX loading",
        8,
    ),
    "Ljava/lang/Runtime;->exec": (
        "Runtime command execution",
        10,
    ),
    "Ljava/lang/ProcessBuilder": (
        "Process creation",
        8,
    ),
    "Landroid/app/ActivityManager;->isDebuggerConnected": (
        "Debugger detection",
        7,
    ),
    "Landroid/os/Debug;->isDebuggerConnected": (
        "Debugger detection",
        7,
    ),
    "Landroid/os/Debug;->waitingForDebugger": (
        "Debugger waiting/detection",
        6,
    ),
    "Landroid/os/Debug;->getTracerPid": (
        "Tracer detection",
        7,
    ),
}


# ---------------------------------------------------------------------------
# String / file intelligence
# ---------------------------------------------------------------------------

# Deliberately conservative. Generic words such as "exec", "shell",
# "encrypt", "download", "payload", "hook", "inject", etc. are not useful
# enough by themselves and are therefore excluded from malware scoring.
HIGH_CONFIDENCE_SUSPICIOUS_STRINGS = {
    "c2server": "Possible command-and-control terminology",
    "command_and_control": "Possible command-and-control terminology",
    "keylogger": "Keylogging terminology",
    "rootkit": "Rootkit terminology",
    "backdoor": "Backdoor terminology",
    "trojan": "Trojan terminology",
    "frida-gadget": "Frida instrumentation component",
    "libfrida-gadget": "Frida instrumentation component",
    "magiskhide": "Root-hiding terminology",
    "rootcloak": "Root-hiding terminology",
}

FUD_STRING_PATTERNS = {
    "frida": ("Frida/instrumentation indicator", 7),
    "xposed": ("Xposed/hooking framework indicator", 6),
    "substrate": ("Substrate/hooking framework indicator", 6),
    "ptrace": ("Process tracing indicator", 7),
    "isdebuggerconnected": ("Debugger detection indicator", 6),
    "waitingfordebugger": ("Debugger detection indicator", 6),
    "ro.kernel.qemu": ("Emulator detection indicator", 5),
    "rootcloak": ("Root-hiding indicator", 7),
    "magiskhide": ("Root-hiding indicator", 7),
}

PACKER_MARKERS = {
    "libjiagu": "Jiagu-style protection marker",
    "libsecmain": "SecNeo-style protection marker",
    "libdexprotector": "DexProtector-style protection marker",
    "dexprotector": "DexProtector-style protection marker",
    "ijiami": "Ijiami-style protection marker",
    "bangcle": "Bangcle-style protection marker",
    "360jiagu": "360 Jiagu-style protection marker",
}

SUSPICIOUS_FILE_EXTENSIONS = {
    ".elf": "ELF/native executable payload",
    ".sh": "Shell script",
}


# ---------------------------------------------------------------------------
# Network intelligence
# ---------------------------------------------------------------------------

# These are infrastructure/reputation hints only. A domain being uncommon is
# NOT treated as malicious.
WELL_KNOWN_DOMAINS = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "android.com",
    "play.google.com",
    "firebaseio.com",
    "firebaseapp.com",
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "maven.org",
    "gradle.org",
    "cloudflare.com",
    "amazonaws.com",
    "windows.net",
    "microsoft.com",
    "apple.com",
    "w3.org",
    "schemas.android.com",
    "xmlpull.org",
    "apache.org",
    "squareup.com",
    "segment.io",
    "sentry.io",
    "bugsnag.com",
    "appsflyer.com",
    "adjust.com",
    "amplitude.com",
    "mixpanel.com",
    "branch.io",
}

SUSPICIOUS_URL_TOKENS = (
    "c2",
    "command",
    "control",
    "exfil",
    "steal",
    "grab",
    "keylog",
    "payload",
    "dropper",
    "loader",
)

CREDENTIAL_PATH_TOKENS = (
    "/password",
    "/credential",
    "/credentials",
    "/steal",
    "/exfil",
    "/keylog",
    "/c2/",
)

# These TLDs are NOT scored. They caused false positives in the previous
# analyzer because legitimate applications can use any modern TLD.
SUSPICIOUS_TLDS: Set[str] = set()


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

def _safe_lower(value: Any) -> str:
    return str(value or "").lower()


def _unique(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = repr(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def format_file_size(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def compute_sha256(filepath: str) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _is_private_or_local_ip(host: str) -> bool:
    try:
        parts = [int(x) for x in host.split(".")]
        if len(parts) != 4 or any(x < 0 or x > 255 for x in parts):
            return False
        a, b, c, d = parts
        return (
            a == 10
            or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 0
            or a == 169 and b == 254
        )
    except Exception:
        return False


def _domain_is_known(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in WELL_KNOWN_DOMAINS)


def _extract_strings_from_bytes(data: bytes, minimum_length: int = 4) -> List[str]:
    """
    Extract ASCII strings. This is intentionally independent of UTF-8 decoding
    because DEX/ELF/APK files are binary formats.
    """
    pattern = rb"[ -~]{%d,}" % minimum_length
    try:
        return [m.decode("utf-8", errors="ignore") for m in re.findall(pattern, data)]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# APK validation
# ---------------------------------------------------------------------------

def validate_apk(filepath: str) -> Tuple[bool, str]:
    if not filepath or not os.path.exists(filepath):
        return False, "File not found"

    if not filepath.lower().endswith(".apk"):
        return False, "File is not an APK"

    try:
        if not zipfile.is_zipfile(filepath):
            return False, "Invalid APK: not a valid ZIP archive"
    except Exception:
        return False, "Could not read APK archive"

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                return False, "Invalid APK: AndroidManifest.xml is missing"
            if not any(name.endswith(".dex") for name in names):
                return False, "Invalid APK: no DEX file was found"

            # Reject obviously broken ZIP entries before analysis.
            bad = zf.testzip()
            if bad:
                return False, f"Corrupted APK entry: {bad}"

    except zipfile.BadZipFile:
        return False, "Corrupted APK file"
    except Exception as exc:
        return False, f"APK archive could not be inspected: {exc}"

    return True, "Valid APK"


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def extract_metadata(apk: Any, filepath: str, original_filename: Optional[str] = None) -> Dict[str, Any]:
    size = os.path.getsize(filepath)

    def call(method: str, default: Any = "Unknown") -> Any:
        try:
            value = getattr(apk, method)()
            return value if value not in (None, "") else default
        except Exception:
            return default

    return {
        "filename": original_filename or os.path.basename(filepath),
        "package_name": call("get_package"),
        "version_name": call("get_androidversion_name"),
        "version_code": call("get_androidversion_code"),
        "min_sdk": call("get_min_sdk_version"),
        "target_sdk": call("get_target_sdk_version"),
        "file_size": size,
        "file_size_readable": format_file_size(size),
        "sha256": compute_sha256(filepath),
        "main_activity": call("get_main_activity"),
        "app_name": call("get_app_name"),
    }


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

def extract_permissions(apk: Any) -> Dict[str, Any]:
    try:
        all_perms = list(apk.get_permissions() or [])
    except Exception:
        all_perms = []

    try:
        declared = list(apk.get_declared_permissions() or [])
    except Exception:
        declared = []

    sensitive = []
    normal = []
    custom = []

    for permission in all_perms:
        short = permission.split(".")[-1]
        item = {
            "name": permission,
            "short_name": short,
            "risk": "sensitive" if permission in SENSITIVE_PERMISSIONS else "normal",
        }

        if permission in SENSITIVE_PERMISSIONS:
            sensitive.append(item)
        elif permission.startswith("android.permission."):
            normal.append(item)
        else:
            custom.append({
                "name": permission,
                "short_name": short,
                "risk": "custom",
            })

    perm_set = set(all_perms)
    combinations = []

    for required, description in HIGH_RISK_PERMISSION_COMBOS:
        if required.issubset(perm_set):
            combinations.append({
                "permissions": sorted(p.split(".")[-1] for p in required),
                "description": description,
            })

    return {
        "total": len(all_perms),
        "dangerous": sensitive,
        "dangerous_count": len(sensitive),
        "normal": normal,
        "normal_count": len(normal),
        "custom": custom,
        "custom_count": len(custom),
        "declared": declared,
        "suspicious_combinations": combinations,
        "all": [p.split(".")[-1] for p in all_perms],
    }


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

def _component_exported(apk: Any, component_type: str, name: str) -> bool:
    try:
        value = apk.get_attribute_value(component_type, "exported", name=name)
        return str(value).lower() == "true"
    except Exception:
        return False


def extract_components(apk: Any) -> Dict[str, Any]:
    def get(method: str) -> List[str]:
        try:
            return list(getattr(apk, method)() or [])
        except Exception:
            return []

    activities = get("get_activities")
    services = get("get_services")
    receivers = get("get_receivers")
    providers = get("get_providers")

    exported = []

    for name in activities:
        if _component_exported(apk, "activity", name):
            exported.append({"name": name.split(".")[-1], "type": "Activity"})

    for name in services:
        if _component_exported(apk, "service", name):
            exported.append({"name": name.split(".")[-1], "type": "Service"})

    for name in receivers:
        if _component_exported(apk, "receiver", name):
            exported.append({"name": name.split(".")[-1], "type": "Receiver"})

    for name in providers:
        if _component_exported(apk, "provider", name):
            exported.append({"name": name.split(".")[-1], "type": "Provider"})

    return {
        "activities": len(activities),
        "services": len(services),
        "receivers": len(receivers),
        "providers": len(providers),
        "total": len(activities) + len(services) + len(receivers) + len(providers),
        "exported": exported[:100],
        "exported_count": len(exported),
        "activity_names": [x.split(".")[-1] for x in activities[:50]],
        "service_names": [x.split(".")[-1] for x in services[:50]],
        "receiver_names": [x.split(".")[-1] for x in receivers[:50]],
        "provider_names": [x.split(".")[-1] for x in providers[:50]],
    }


# ---------------------------------------------------------------------------
# Intent filters
# ---------------------------------------------------------------------------

def _collect_intents_for_component(apk: Any, kind: str, names: List[str]) -> List[Dict[str, Any]]:
    findings = []

    for component in names:
        try:
            filters = apk.get_intent_filters(kind, component) or {}
            actions = filters.get("action", []) if isinstance(filters, dict) else []
            for action in actions:
                if action in SENSITIVE_INTENTS:
                    description, category = SENSITIVE_INTENTS[action]
                    findings.append({
                        "action": action,
                        "short_name": action.split(".")[-1],
                        "description": description,
                        "category": category,
                        "component": component.split(".")[-1],
                        "component_type": kind,
                    })
        except Exception:
            continue

    return findings


def extract_intents(apk: Any) -> Dict[str, Any]:
    def get(method: str) -> List[str]:
        try:
            return list(getattr(apk, method)() or [])
        except Exception:
            return []

    receivers = get("get_receivers")
    services = get("get_services")
    activities = get("get_activities")

    detected = []
    detected.extend(_collect_intents_for_component(apk, "receiver", receivers))
    detected.extend(_collect_intents_for_component(apk, "service", services))
    detected.extend(_collect_intents_for_component(apk, "activity", activities))

    # Deduplicate exact component/action pairs.
    unique = []
    seen = set()
    for item in detected:
        key = (item["action"], item["component"], item["component_type"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return {
        "total": len(unique),
        "suspicious": unique,
    }


# ---------------------------------------------------------------------------
# DEX/API analysis
# ---------------------------------------------------------------------------

def _read_dex_files(filepath: str) -> List[Tuple[str, bytes]]:
    dex_files = []
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".dex"):
                    try:
                        dex_files.append((name, zf.read(name)))
                    except Exception:
                        continue
    except Exception:
        pass
    return dex_files


def extract_api_indicators(filepath: str) -> Dict[str, Any]:
    hits = []

    for dex_name, data in _read_dex_files(filepath):
        for family, info in API_PATTERNS.items():
            matched = []
            for pattern in info["patterns"]:
                if pattern.encode("utf-8") in data:
                    matched.append(pattern)

            if matched:
                hits.append({
                    "family": family,
                    "indicator": family.replace("_", " ").title(),
                    "pattern": matched[0],
                    "patterns_found": matched,
                    "description": info["description"],
                    "source": dex_name,
                    "risk_weight": info["weight"],
                    "high_impact": info["high_impact"],
                })

    # One result per family, because repeated occurrences of the same API
    # family should not multiply risk.
    families = {}
    for item in hits:
        families.setdefault(item["family"], item)

    return {
        "total": len(families),
        "indicators": list(families.values()),
    }


# ---------------------------------------------------------------------------
# Network analysis
# ---------------------------------------------------------------------------

def extract_network_indicators(filepath: str) -> Dict[str, Any]:
    urls: Set[str] = set()
    domains: Set[str] = set()
    ips: Set[str] = set()

    url_pattern = re.compile(
        r"https?://[^\s<>'\"\\{}\[\]|^`]+",
        re.IGNORECASE,
    )
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    allowed_extensions = (
        ".dex", ".xml", ".json", ".js", ".html", ".txt",
        ".properties", ".smali", ".arsc",
    )

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            for name in zf.namelist():
                if not name.lower().endswith(allowed_extensions):
                    continue

                try:
                    data = zf.read(name).decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for match in url_pattern.finditer(data):
                    url = match.group().rstrip("/.,;:)")
                    try:
                        parsed = urlparse(url)
                        host = (parsed.hostname or "").lower().rstrip(".")
                        if parsed.scheme in ("http", "https") and host:
                            urls.add(url)
                            domains.add(host)
                    except Exception:
                        pass

                for match in ip_pattern.finditer(data):
                    ip = match.group()
                    try:
                        parts = [int(x) for x in ip.split(".")]
                        if len(parts) == 4 and all(0 <= x <= 255 for x in parts):
                            if not ip.startswith(("0.", "127.", "255.")):
                                ips.add(ip)
                    except Exception:
                        pass
    except Exception:
        pass

    suspicious_urls = []
    safe_or_common_urls = []
    url_signals = []

    for url in sorted(urls):
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        reasons = []
        signal_weight = 0

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""):
            if not _is_private_or_local_ip(host):
                reasons.append("public IP used directly as network host")
                signal_weight += 3

        # Do NOT flag uncommon TLDs, external domains, HTTPS, long subdomains,
        # analytics URLs, CDN URLs, or login URLs by themselves.
        path_query = ((parsed.path or "") + "?" + (parsed.query or "")).lower()

        if any(token in host for token in SUSPICIOUS_URL_TOKENS):
            reasons.append("host contains malware/C2-like terminology")
            signal_weight += 3

        if any(token in path_query for token in CREDENTIAL_PATH_TOKENS):
            reasons.append("path contains credential/exfiltration terminology")
            signal_weight += 3

        if parsed.scheme == "http" and not _domain_is_known(host):
            reasons.append("unencrypted HTTP endpoint")
            signal_weight += 1

        if reasons:
            suspicious_urls.append(url)
            url_signals.append({
                "url": url,
                "host": host,
                "known_platform": _domain_is_known(host),
                "reasons": reasons,
                "signal_weight": signal_weight,
            })
        else:
            safe_or_common_urls.append(url)

    return {
        "urls_total": len(urls),
        "domains_total": len(domains),
        "ips_total": len(ips),
        "urls": sorted(urls)[:200],
        "suspicious_urls": suspicious_urls[:100],
        "safe_urls": safe_or_common_urls[:100],
        "domains": sorted(domains)[:100],
        "ips": sorted(ips)[:100],
        "url_signals": url_signals[:100],
    }


# ---------------------------------------------------------------------------
# Resource/package analysis
# ---------------------------------------------------------------------------

def extract_resources(filepath: str) -> Dict[str, Any]:
    dex_files = []
    native_libs = []
    assets = []
    suspicious_files = []

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            for info in zf.infolist():
                name = info.filename
                lower = name.lower()

                if lower.endswith(".dex"):
                    dex_files.append({
                        "name": name,
                        "size": format_file_size(info.file_size),
                    })

                if lower.startswith("lib/") and lower.endswith(".so"):
                    native_libs.append({
                        "name": name,
                        "size": format_file_size(info.file_size),
                    })

                if lower.startswith("assets/"):
                    assets.append(name)

                for ext, reason in SUSPICIOUS_FILE_EXTENSIONS.items():
                    if lower.endswith(ext):
                        suspicious_files.append({
                            "name": name,
                            "size": format_file_size(info.file_size),
                            "reason": reason,
                        })
                        break

    except Exception:
        pass

    return {
        "dex_files": dex_files,
        "dex_count": len(dex_files),
        "native_libs": native_libs,
        "native_lib_count": len(native_libs),
        "assets_count": len(assets),
        "suspicious_files": suspicious_files[:100],
        "suspicious_count": len(suspicious_files),
    }


# ---------------------------------------------------------------------------
# Certificate analysis
# ---------------------------------------------------------------------------

def extract_certificate(apk: Any) -> Dict[str, Any]:
    result = {
        "present": False,
        "subject": "Unknown",
        "issuer": "Unknown",
        "serial_number": "Unknown",
        "algorithm": "Unknown",
        "valid_from": "Unknown",
        "valid_until": "Unknown",
        "sha256_fingerprint": "Unknown",
        "is_debug": False,
        "checks": [],
    }

    try:
        certs = list(apk.get_certificates() or [])
    except Exception as exc:
        result["checks"].append({
            "check": "Certificate extraction",
            "status": "fail",
            "message": str(exc),
        })
        return result

    if not certs:
        result["checks"].append({
            "check": "Certificate present",
            "status": "fail",
            "message": "No signing certificate could be extracted",
        })
        return result

    cert = certs[0]
    result["present"] = True

    try:
        result["subject"] = str(cert.subject.rfc4514_string())
    except Exception:
        try:
            result["subject"] = str(cert.subject)
        except Exception:
            pass

    try:
        result["issuer"] = str(cert.issuer.rfc4514_string())
    except Exception:
        try:
            result["issuer"] = str(cert.issuer)
        except Exception:
            pass

    try:
        result["serial_number"] = format(cert.serial_number, "X")
    except Exception:
        pass

    try:
        result["algorithm"] = cert.signature_algorithm_oid._name
    except Exception:
        try:
            result["algorithm"] = cert.signature_hash_algorithm.name
        except Exception:
            pass

    try:
        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
        result["valid_from"] = str(not_before)
        result["valid_until"] = str(not_after)
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives import hashes
        fp = cert.fingerprint(hashes.SHA256())
        result["sha256_fingerprint"] = ":".join(f"{b:02X}" for b in fp)
    except Exception:
        pass

    subject_lower = result["subject"].lower()
    result["is_debug"] = (
        "android debug" in subject_lower
        or "cn=androiddebugkey" in subject_lower
        or "androiddebugkey" in subject_lower
    )

    result["checks"].append({
        "check": "Certificate present",
        "status": "pass",
        "message": "APK is signed",
    })

    algo = result["algorithm"].lower()
    if "md5" in algo or "sha1" in algo:
        result["checks"].append({
            "check": "Signing algorithm",
            "status": "warn",
            "message": f"Weak/legacy signing algorithm: {result['algorithm']}",
        })
    else:
        result["checks"].append({
            "check": "Signing algorithm",
            "status": "pass",
            "message": result["algorithm"],
        })

    # Certificate validity is a verification signal, not malware evidence.
    try:
        now = datetime.now(timezone.utc)
        not_before = getattr(cert, "not_valid_before_utc", None)
        not_after = getattr(cert, "not_valid_after_utc", None)

        if not_before and now < not_before:
            result["checks"].append({
                "check": "Certificate validity",
                "status": "warn",
                "message": "Certificate is not yet valid",
            })
        elif not_after and now > not_after:
            result["checks"].append({
                "check": "Certificate validity",
                "status": "warn",
                "message": "Certificate has expired",
            })
        else:
            result["checks"].append({
                "check": "Certificate validity",
                "status": "pass",
                "message": "Certificate is currently within its validity period",
            })
    except Exception:
        pass

    if result["is_debug"]:
        result["checks"].append({
            "check": "Debug certificate",
            "status": "warn",
            "message": "Debug signing identity detected. This is not proof of malware.",
        })

    return result


# ---------------------------------------------------------------------------
# String analysis
# ---------------------------------------------------------------------------

def extract_suspicious_strings(filepath: str) -> Dict[str, Any]:
    found = []

    for dex_name, data in _read_dex_files(filepath):
        strings = _extract_strings_from_bytes(data, minimum_length=4)
        lowered = [(s.lower(), s) for s in strings]

        for marker, description in HIGH_CONFIDENCE_SUSPICIOUS_STRINGS.items():
            for low, original in lowered:
                if marker in low:
                    found.append({
                        "string": marker,
                        "matched_text": original[:160],
                        "description": description,
                        "source": dex_name,
                    })
                    break

    unique = []
    seen = set()

    for item in found:
        key = (item["string"], item["source"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return {
        "total": len(unique),
        "strings": unique[:100],
    }


# ---------------------------------------------------------------------------
# FUD/evasion analysis
# ---------------------------------------------------------------------------

def extract_fud_indicators(
    filepath: str,
    api_indicators: Optional[Dict[str, Any]] = None,
    suspicious_strings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    FUD is treated as an analysis category, never as an automatic malware
    verdict. Legitimate apps can use protectors, native code, reflection,
    encryption, anti-debugging, or dynamic loading.
    """
    findings = []
    categories: Set[str] = set()

    def add(kind: str, indicator: str, description: str, points: int, severity: str, evidence: Any = None):
        key = (kind, indicator)
        if any((x["kind"], x["indicator"]) == key for x in findings):
            return
        item = {
            "kind": kind,
            "indicator": indicator,
            "description": description,
            "points": points,
            "severity": severity,
        }
        if evidence:
            item["evidence"] = evidence
        findings.append(item)
        categories.add(kind)

    for item in (api_indicators or {}).get("indicators", []):
        pattern = item.get("pattern", "")
        if pattern in FUD_API_PATTERNS:
            desc, points = FUD_API_PATTERNS[pattern]
            add(
                "api_evasion",
                pattern,
                desc,
                points,
                "high" if points >= 8 else "medium",
                item.get("source"),
            )

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = zf.namelist()

            for name in names:
                lower_name = name.lower()
                for marker, description in PACKER_MARKERS.items():
                    if marker in lower_name:
                        add("packer", marker, description, 5, "medium", name)

            for name in names:
                if not name.endswith(".dex"):
                    continue

                try:
                    data = zf.read(name)
                    lower = data.lower()

                    for marker, (description, points) in FUD_STRING_PATTERNS.items():
                        if marker.encode("utf-8") in lower:
                            add(
                                "string_evasion",
                                marker,
                                description,
                                points,
                                "high" if points >= 7 else "medium",
                                name,
                            )

                    # Base64/high entropy are only reported as informational
                    # evidence. They are extremely common in legitimate apps.
                    text = data.decode("utf-8", errors="ignore")

                    b64_hits = re.findall(
                        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/])",
                        text,
                    )
                    if b64_hits:
                        add(
                            "encoding",
                            "long_base64_like_string",
                            f"{len(b64_hits)} long Base64-like string(s) found; could be encoded configuration/data.",
                            2,
                            "low",
                            name,
                        )

                except Exception:
                    continue

    except Exception:
        pass

    # Native code is common and is not a FUD finding on its own.
    native_count = 0
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            native_count = sum(
                1 for n in zf.namelist()
                if n.startswith("lib/") and n.endswith(".so")
            )
    except Exception:
        pass

    if native_count and len(findings) >= 2:
        add(
            "native_evasion",
            "native_code_with_evasion",
            f"{native_count} native library/libraries coexist with other evasion indicators.",
            3,
            "low",
        )

    score = min(100, sum(int(x["points"]) for x in findings))

    if score >= 30:
        classification = "HIGH"
    elif score >= 12:
        classification = "SUSPICIOUS"
    else:
        classification = "LOW"

    if len(categories) >= 3 and len(findings) >= 4:
        confidence = "HIGH"
    elif len(categories) >= 2 or len(findings) >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    if classification == "HIGH":
        verdict = (
            "Multiple evasion/obfuscation indicators were found. "
            "These techniques can complicate static analysis, but they are "
            "not by themselves proof of malware."
        )
    elif classification == "SUSPICIOUS":
        verdict = (
            "Some evasion/obfuscation indicators were found. "
            "Legitimate protected applications can produce similar signals."
        )
    else:
        verdict = "No strong evasion pattern was detected."

    return {
        "score": score,
        "classification": classification,
        "confidence": confidence,
        "finding_count": len(findings),
        "evidence_categories": sorted(categories),
        "verdict": verdict,
        "findings": findings[:100],
    }


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _has_api(result: Dict[str, Any], family: str) -> bool:
    return any(
        x.get("family") == family
        for x in result.get("api_indicators", {}).get("indicators", [])
    )


def _has_permission(result: Dict[str, Any], permission: str) -> bool:
    return any(
        x.get("name") == permission
        for x in result.get("permissions", {}).get("dangerous", [])
    )


def _intent_categories(result: Dict[str, Any]) -> Set[str]:
    return {
        x.get("category")
        for x in result.get("intents", {}).get("suspicious", [])
        if x.get("category")
    }


def calculate_risk_score(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Conservative evidence-based scoring.

    Important:
    - Sensitive permissions alone do not make an APK suspicious.
    - External URLs alone do not make an APK suspicious.
    - Uncommon TLDs are not scored.
    - Debug certificates are not malware indicators.
    - FUD alone cannot produce MALICIOUS.
    - High scores require multiple independent behavioral domains.
    """
    reasons = []
    score = 0.0
    domains: Set[str] = set()

    def add(
        title: str,
        description: str,
        points: float,
        severity: str,
        domain: str,
    ):
        nonlocal score
        if points <= 0:
            return
        score += points
        domains.add(domain)
        reasons.append({
            "title": title,
            "description": description,
            "severity": severity,
            "points": round(points),
            "domain": domain,
        })

    perms = result.get("permissions", {})
    perm_set = {
        x.get("name")
        for x in perms.get("dangerous", [])
        if x.get("name")
    }

    combos = perms.get("suspicious_combinations", [])
    api_families = {
        x.get("family")
        for x in result.get("api_indicators", {}).get("indicators", [])
    }
    intents = result.get("intents", {}).get("suspicious", [])
    intent_cats = _intent_categories(result)
    network = result.get("network_indicators", {})
    url_signals = network.get("url_signals", [])

    # ---- High-confidence behavior chains ---------------------------------
    # SMS theft chain: permission + API/intent.
    sms_capability = bool(
        perm_set
        & {
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
        }
    )
    sms_behavior = (
        "sms_read" in api_families
        or "sms" in intent_cats
    )

    if sms_capability and sms_behavior:
        add(
            "SMS capability is corroborated by code/manifest behavior",
            "The APK requests SMS access and also contains SMS-related API or broadcast behavior.",
            24,
            "high",
            "sms",
        )

    if (
        "android.permission.SEND_SMS" in perm_set
        and "android.permission.READ_SMS" in perm_set
        and "android.permission.RECEIVE_SMS" in perm_set
    ):
        add(
            "Full SMS read/receive/send capability",
            "The APK can read, receive, and send SMS. This is high impact when the application purpose does not clearly require it.",
            10,
            "high",
            "sms",
        )

    # Accessibility + overlay is much stronger than either alone.
    if (
        "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_set
        and (
            "accessibility" in api_families
            or "overlay" in api_families
        )
    ):
        add(
            "Accessibility capability is corroborated by code",
            "Accessibility access is supported by accessibility/overlay API usage.",
            22,
            "high",
            "accessibility",
        )

    # Device admin + persistence is a meaningful chain.
    if (
        "android.permission.BIND_DEVICE_ADMIN" in perm_set
        and (
            "device_admin" in api_families
            or "persistence" in intent_cats
        )
    ):
        add(
            "Device administration is corroborated by code or persistence",
            "The APK combines device-administrator capability with related API/persistence behavior.",
            22,
            "high",
            "device_admin",
        )

    # Installer capability + dynamic loading + network is another strong chain.
    if (
        "android.permission.REQUEST_INSTALL_PACKAGES" in perm_set
        and "dynamic_code_loading" in api_families
        and network.get("urls_total", 0) > 0
    ):
        add(
            "Package installation, dynamic loading, and network behavior",
            "The APK combines package-install capability with dynamic code loading and network communication.",
            20,
            "high",
            "dynamic_delivery",
        )

    # Command execution is only serious when it has additional corroboration.
    if "command_execution" in api_families:
        corroborating = (
            sms_capability
            or "accessibility" in api_families
            or "device_admin" in api_families
            or "dynamic_code_loading" in api_families
            or bool(url_signals)
        )
        if corroborating:
            add(
                "Command execution with corroborating behavior",
                "OS/process execution APIs are present together with another security-relevant behavior.",
                16,
                "high",
                "execution",
            )
        else:
            # Keep isolated Runtime.exec low because many legitimate apps use
            # it for diagnostics, media tools, device commands, etc.
            add(
                "Command execution API present",
                "An OS/process execution API was found, but no strong corroborating behavior was identified.",
                3,
                "low",
                "execution",
            )

    # ---- Permission combinations -----------------------------------------
    if combos:
        # A combination is evidence, but not proof. Do not score all common
        # camera/location combinations as malicious.
        meaningful = [
            c for c in combos
            if any(
                p in HIGH_IMPACT_PERMISSIONS
                for p in [
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.BIND_DEVICE_ADMIN",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                ]
            )
        ]
        if meaningful:
            add(
                "High-impact permission combination",
                f"{len(meaningful)} high-impact permission combination(s) were found.",
                min(12, 5 * len(meaningful)),
                "medium",
                "permissions",
            )

    # ---- Persistence ------------------------------------------------------
    if "persistence" in intent_cats:
        if (
            "android.permission.RECEIVE_BOOT_COMPLETED" in perm_set
            or len(intents) >= 2
        ):
            add(
                "Automatic/persistent startup behavior",
                "The manifest contains boot or related lifecycle behavior.",
                5,
                "medium",
                "persistence",
            )

    # ---- Network ----------------------------------------------------------
    # External network endpoints are normal. Only concrete signals receive
    # risk points.
    if url_signals:
        total_signal_weight = sum(
            int(x.get("signal_weight", 0)) for x in url_signals
        )
        if total_signal_weight >= 6:
            add(
                "Network endpoint with suspicious context",
                "One or more endpoints contain concrete C2/exfiltration/credential-related signals.",
                min(10, 3 + total_signal_weight),
                "medium",
                "network",
            )
        elif total_signal_weight >= 3:
            add(
                "Weak network anomaly",
                "A network endpoint has a limited static anomaly; this is not proof of malicious activity.",
                2,
                "low",
                "network",
            )

    # ---- Dynamic loading --------------------------------------------------
    if "dynamic_code_loading" in api_families:
        if (
            "command_execution" in api_families
            or bool(url_signals)
            or "android.permission.REQUEST_INSTALL_PACKAGES" in perm_set
        ):
            add(
                "Dynamic code loading with supporting evidence",
                "Dynamic loading is accompanied by another potentially risky capability.",
                12,
                "high",
                "dynamic_loading",
            )
        else:
            add(
                "Dynamic code loading API",
                "Dynamic loading can be legitimate; no additional strong risk signal was found.",
                2,
                "low",
                "dynamic_loading",
            )

    # ---- Strong suspicious strings ---------------------------------------
    string_count = result.get("suspicious_strings", {}).get("total", 0)
    if string_count:
        # Strings are weak evidence and never drive the verdict alone.
        add(
            "High-confidence suspicious terminology",
            f"{string_count} high-confidence security-related string family/families were found.",
            min(5, string_count),
            "low",
            "strings",
        )

    # ---- Package contents -------------------------------------------------
    resources = result.get("resources", {})
    suspicious_files = resources.get("suspicious_count", 0)
    if suspicious_files:
        # .sh/.elf are stronger than generic .dat/.bin markers.
        add(
            "Executable/script-like packaged content",
            f"{suspicious_files} executable/script-like file(s) were found in the APK.",
            min(6, suspicious_files * 2),
            "medium",
            "package",
        )

    # Native libraries are NOT scored by themselves.
    # Exported components are NOT scored by themselves.

    # ---- Certificate ------------------------------------------------------
    cert = result.get("certificate", {})

    if not cert.get("present"):
        # Verification issue, not malware evidence.
        reasons.append({
            "title": "Signing certificate could not be verified",
            "description": "The certificate could not be extracted. This lowers verification confidence but is not treated as malware evidence.",
            "severity": "info",
            "points": 0,
            "domain": "certificate",
        })
    elif cert.get("is_debug"):
        reasons.append({
            "title": "Debug certificate detected",
            "description": "The APK appears to use a debug signing identity. This is common during development and is not proof of malware.",
            "severity": "info",
            "points": 0,
            "domain": "certificate",
        })

    # ---- FUD/evasion ------------------------------------------------------
    fud = result.get("fud_analysis", {})
    fud_class = fud.get("classification", "LOW")
    fud_score = int(fud.get("score", 0) or 0)

    # FUD is a supporting signal only. Never turn an otherwise clean APK into
    # MALICIOUS just because it uses a protector, reflection, native code, etc.
    if fud_score >= 12:
        if (
            "command_execution" in api_families
            or "dynamic_code_loading" in api_families
            or "accessibility" in api_families
            or "device_admin" in api_families
        ):
            add(
                f"Evasion/obfuscation pattern: {fud_class}",
                fud.get("verdict", "Evasion indicators were detected."),
                min(8, fud_score // 4),
                "medium",
                "evasion",
            )
        else:
            reasons.append({
                "title": f"Evasion/obfuscation pattern: {fud_class}",
                "description": fud.get("verdict", "Evasion indicators were detected."),
                "severity": "info",
                "points": 0,
                "domain": "evasion",
            })

    # ---- Corroboration bonus ----------------------------------------------
    # Reward breadth only when at least one high-impact chain exists.
    high_impact_domains = {
        d for d in domains
        if d in {
            "sms",
            "accessibility",
            "device_admin",
            "dynamic_delivery",
            "execution",
            "network",
            "dynamic_loading",
            "persistence",
        }
    }

    if len(high_impact_domains) >= 3:
        add(
            "Cross-domain corroboration",
            f"Strong signals appear across {len(high_impact_domains)} independent behavioral domains.",
            8,
            "high",
            "corroboration",
        )
    elif len(high_impact_domains) >= 2:
        add(
            "Cross-domain corroboration",
            "Two independent security-relevant behavioral domains support the finding.",
            4,
            "medium",
            "corroboration",
        )

    score = int(round(min(100, max(0, score))))

    # Classification deliberately requires a lot more than a handful of
    # ordinary capabilities.
    high_domains = len(high_impact_domains)

    if score >= 60 and high_domains >= 2:
        classification = "MALICIOUS"
    elif score >= 30 and high_domains >= 1:
        classification = "SUSPICIOUS"
    elif score >= 18 and high_domains >= 2:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    # Strong FUD cannot override this gate.
    if fud_class in ("HIGH",) and high_domains == 0 and score < 30:
        classification = "SAFE"

    # Confidence describes evidence quality, not whether the APK is bad.
    if high_domains >= 3 or (high_domains >= 2 and score >= 45):
        confidence = "HIGH"
    elif high_domains >= 1 or score >= 18:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    if classification == "SAFE":
        verdict = (
            "No strong malicious behavior pattern was identified by static "
            "analysis. The APK may still contain unknown or runtime-only risks."
        )
    elif classification == "SUSPICIOUS":
        verdict = (
            "The APK contains multiple security-relevant signals that deserve "
            "review. The result is not proof of malware."
        )
    else:
        verdict = (
            "Multiple independent high-risk behaviors are corroborated. "
            "Treat this APK as potentially malicious until its source and "
            "behavior are verified."
        )

    return {
        "static_score": score,
        "classification": classification,
        "confidence": confidence,
        "evidence_domains": len(domains),
        "reasons": reasons[:100],
        "total_indicators": round(sum(
            r.get("points", 0) for r in reasons
        )),
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_apk(filepath: str, original_filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform real static APK analysis.

    No demo result is ever returned. If analysis cannot be performed, the
    function returns success=False with the actual error.
    """
    if not ANDROGUARD_AVAILABLE:
        return {
            "success": False,
            "error": "Androguard is not installed. Run: pip install androguard",
        }

    valid, message = validate_apk(filepath)
    if not valid:
        return {
            "success": False,
            "error": message,
        }

    try:
        apk = APK(filepath)
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to parse APK: {exc}",
        }

    try:
        result: Dict[str, Any] = {
            "success": True,
            "is_demo": False,
            "metadata": extract_metadata(apk, filepath, original_filename),
            "permissions": extract_permissions(apk),
            "components": extract_components(apk),
            "intents": extract_intents(apk),
            "api_indicators": extract_api_indicators(filepath),
            "network_indicators": extract_network_indicators(filepath),
            "resources": extract_resources(filepath),
            "certificate": extract_certificate(apk),
            "suspicious_strings": extract_suspicious_strings(filepath),
        }

        result["fud_analysis"] = extract_fud_indicators(
            filepath,
            result["api_indicators"],
            result["suspicious_strings"],
        )

        result["risk_analysis"] = calculate_risk_score(result)

        # Compatibility with existing UI/backend code that may look for a
        # combined_score object even when Gemini is unavailable.
        static_score = result["risk_analysis"]["static_score"]
        result["combined_score"] = {
            "final_score": static_score,
            "static_score": static_score,
            "gemini_score": None,
            "classification": result["risk_analysis"]["classification"],
            "ai_available": False,
            "method": "static_evidence_only",
        }

        return result

    except Exception as exc:
        return {
            "success": False,
            "error": f"Static analysis failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Optional AI-score combiner
# ---------------------------------------------------------------------------

def classify_score(score: float) -> str:
    """
    Compatibility helper for the existing Gemini module.

    AI is advisory. The deterministic static result should remain the
    authoritative baseline.
    """
    score = max(0, min(100, float(score)))

    if score >= 60:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def combine_scores(static_score: float, gemini_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Combine an AI opinion with static evidence without allowing AI to turn a
    clean static result into a high-confidence malware verdict by itself.

    The AI result is advisory only.
    """
    static_score = max(0, min(100, float(static_score)))

    if not gemini_result:
        return {
            "final_score": round(static_score),
            "static_score": round(static_score),
            "gemini_score": None,
            "classification": classify_score(static_score),
            "ai_available": False,
            "method": "static_evidence_only",
        }

    try:
        ai_score = max(
            0,
            min(100, float(gemini_result.get("risk_score", static_score))),
        )
    except Exception:
        ai_score = static_score

    disagreement = abs(static_score - ai_score)

    # Static evidence remains dominant. If AI strongly disagrees, reduce its
    # influence even further.
    if disagreement >= 35:
        final_score = round(static_score * 0.90 + ai_score * 0.10)
        weight = 0.10
    else:
        final_score = round(static_score * 0.80 + ai_score * 0.20)
        weight = 0.20

    final_score = max(0, min(100, final_score))

    return {
        "final_score": final_score,
        "static_score": round(static_score),
        "gemini_score": round(ai_score),
        "classification": classify_score(final_score),
        "ai_available": True,
        "ai_weight": weight,
        "score_disagreement": round(disagreement),
        "method": "evidence_first_ai_second_opinion",
    }


# ---------------------------------------------------------------------------
# Intentionally no DEMO_RESULT.
# ---------------------------------------------------------------------------
