import re
from functools import lru_cache

from .common import stable_id
from .endpoints import host_matches
from .privacy_models import PRECISE_CALL_SIGNALS, SENSITIVE_SIGNALS, call_signal

RULE_VERSION = "4"
CAPABILITIES = {
    "location": [
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
    ],
    "contacts": ["READ_CONTACTS"],
    "sms": ["READ_SMS", "RECEIVE_SMS"],
    "calls": ["READ_CALL_LOG"],
    "microphone": [
        "RECORD_AUDIO",
        "CAPTURE_AUDIO_OUTPUT",
        "CAPTURE_VOICE_COMMUNICATION_OUTPUT",
    ],
    "camera": ["CAMERA"],
    "screen": [
        "FOREGROUND_SERVICE_MEDIA_PROJECTION",
        "CAPTURE_VIDEO_OUTPUT",
        "CAPTURE_SECURE_VIDEO_OUTPUT",
    ],
    "installed_apps": ["QUERY_ALL_PACKAGES", "PACKAGE_USAGE_STATS"],
    "device_identity": ["READ_PHONE_STATE", "READ_PRIVILEGED_PHONE_STATE"],
    "files": [
        "MANAGE_EXTERNAL_STORAGE",
        "READ_EXTERNAL_STORAGE",
        "READ_MEDIA_IMAGES",
        "READ_MEDIA_VIDEO",
        "READ_MEDIA_AUDIO",
        "READ_MEDIA_VISUAL_USER_SELECTED",
    ],
    "calendar": ["READ_CALENDAR"],
    "accounts": ["GET_ACCOUNTS"],
}
SDK_RULES = [
    ("Umeng", "analytics", ["com/umeng/analytics/"], ["umeng.com", "umengcloud.com"]),
    ("AppsFlyer", "attribution", ["com/appsflyer/"], ["appsflyer.com"]),
    ("Adjust", "attribution", ["com/adjust/sdk/"], ["adjust.com"]),
    ("Meta", "social", ["com/facebook/"], ["facebook.com", "facebook.net"]),
    (
        "Firebase Analytics",
        "analytics",
        ["com/google/firebase/analytics/", "com/google/android/gms/measurement/"],
        ["app-measurement.com"],
    ),
    (
        "Firebase Crashlytics",
        "diagnostics",
        ["com/google/firebase/crashlytics/"],
        ["crashlytics.com"],
    ),
    ("Firebase Messaging", "push", ["com/google/firebase/messaging/"], []),
    ("ByteDance", "sdk", ["com/bytedance/"], []),
    ("Pangle", "advertising", ["com/bytedance/sdk/openadsdk/"], ["pangleglobal.com"]),
    ("Tencent", "sdk", ["com/tencent/"], []),
    ("Alibaba", "sdk", ["com/alibaba/"], []),
    ("Baidu", "sdk", ["com/baidu/"], []),
    ("Sogou", "sdk", ["com/sogou/"], []),
    ("iFlytek", "voice", ["com/iflytek/"], ["xfyun.cn"]),
    ("Sentry", "diagnostics", ["io/sentry/"], ["sentry.io"]),
    ("Mixpanel", "analytics", ["com/mixpanel/"], ["mixpanel.com"]),
    ("Amplitude", "analytics", ["com/amplitude/"], ["amplitude.com"]),
    ("OneSignal", "push", ["com/onesignal/"], ["onesignal.com"]),
    ("Bugly", "diagnostics", ["com/tencent/bugly/"], ["bugly.qq.com"]),
    ("GrowingIO", "analytics", ["com/growingio/"], ["growingio.com"]),
    ("Sensors", "analytics", ["com/sensorsdata/analytics/"], ["sensorsdata.cn"]),
    ("Getui", "push", ["com/igexin/"], ["getui.com"]),
    ("JPush", "push", ["cn/jpush/"], ["jpush.cn"]),
    ("MiPush", "push", ["com/xiaomi/push/"], []),
]
SIGNAL_PATTERNS = {
    "process_execution": r"(?:Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;|Runtime\s*\.\s*getRuntime|ProcessBuilder\s*\()",
    "dynamic_loading": r"(?:Ldalvik/system/(?:DexClassLoader|PathClassLoader);|DexClassLoader|PathClassLoader|loadLibrary)",
    "application_state": r"setApplicationEnabledSetting",
    "accessibility_settings": r"enabled_accessibility_services",
    "screen_capture": r"(?:MediaProjection|createScreenCaptureIntent)",
    "reflection": r"(?:Ljava/lang/Class;->forName|getDeclaredMethod|Class\.forName)",
    "cryptography": r"(?:Ljavax/crypto/Cipher;|Ljava/security/MessageDigest;|Cipher\.getInstance|MessageDigest)",
    "network_api": r"(?:Ljava/net/(?:URL|HttpURLConnection|URLConnection);|Lokhttp3/(?:Request|OkHttpClient|HttpUrl);|Lorg/chromium/net/|HttpURLConnection|OkHttpClient|openConnection)",
    "settings_write": r"(?:Landroid/provider/Settings\$(?:Global|Secure);->put|SystemProperties.*set|Settings\.(?:Global|Secure)\.put)",
    "sms_api": r"(?:SmsManager|sendTextMessage|content://sms)",
    "device_identifier": r"(?:getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getIccId|getSerial|ANDROID_ID|android_id|AdvertisingIdClient|AppSetIdClient|oaid|OpenDeviceIdentifier)",
    "identifier_field": r"(?i)(?:^|[^a-z0-9])(imei|imsi|iccid)(?:$|[^a-z0-9])",
    "sim_identifier": r"(?:getSimSerialNumber|getIccId)",
    "usage_stats": r"(?:UsageStats|UsageEvents|queryUsageStats|queryEvents|queryAndAggregateUsageStats)",
    "network_stats": r"(?:NetworkStats|TrafficStats|queryDetailsForUid|getUidRxBytes|getUidTxBytes)",
    "audio_capture": r"(?:AudioRecord|MediaRecorder|setAudioSource|startRecording)",
    "speech_recognition": r"(?:SpeechRecognizer|RecognitionListener|RecognizerIntent)",
    "application_fingerprint": r"(?:SigningInfo|getApkContentsSigners|getSigningCertificateHistory|GET_SIGNING_CERTIFICATES|signingInfo|Landroid/content/pm/PackageInfo;->(?:versionName:Ljava/lang/String;|versionCode:I)\Z)",
    "data_encoding": r"(?:Base64|GZIPOutputStream|Deflater|ByteArrayOutputStream)",
    "webview_bridge": r"addJavascriptInterface",
    "accessibility_service": r"AccessibilityService",
    "notification_listener": r"NotificationListenerService",
    "device_admin": r"DeviceAdminReceiver",
    "telemetry_event": r"(?:logEvent|trackEvent|captureEvent|captureException|reportEvent|recordEvent|sendEvent|onEvent|setUserId|setUserProperty)",
    "location_api": r"(?:Landroid/location/|FusedLocationProviderClient|getLastKnownLocation)",
    "contacts_api": r"(?:ContactsContract|content://com\.android\.contacts)",
    "installed_apps_api": r"(?:getInstalledPackages|getInstalledApplications|queryUsageStats)",
    "clipboard_api": r"(?:ClipboardManager|PrimaryClip)",
    "sensor_api": r"(?:Landroid/hardware/SensorManager;|SensorManager)",
    "diagnostic_field": r"(?i)(?:^|[^a-z0-9])(crash|stacktrace|stack_trace|session_id|device_id|advertising_id|event_name|screen_name|trace_id|oaid)(?:$|[^a-z0-9])",
}
SIGNALS = {name: re.compile(pattern) for name, pattern in SIGNAL_PATTERNS.items()}
SIGNAL_CACHE_ENTRIES = 8192
SIGNAL_CACHE_TEXT_LENGTH = 1024


def signal_decisions(value, level):
    precise = call_signal(value) if level == "E2" else None
    return tuple(
        name
        for name, pattern in SIGNALS.items()
        if (pattern.search(value) or name == precise)
        and not (level == "E2" and name in PRECISE_CALL_SIGNALS and name != precise)
    )


cached_signal_decisions = lru_cache(maxsize=SIGNAL_CACHE_ENTRIES)(signal_decisions)


def signal_matches(value, source, level="E1"):
    findings = []
    decisions = (
        cached_signal_decisions
        if len(value) <= SIGNAL_CACHE_TEXT_LENGTH
        else signal_decisions
    )
    for name in decisions(value, level):
        evidence = {**source, "excerpt": value[:2048]}
        evidence["id"] = stable_id("signal_evidence", name, source, value)
        findings.append(
            {
                "id": stable_id("signal", name, evidence["id"]),
                "type": name,
                "evidence_level": level,
                "evidence": [evidence],
            }
        )
    return findings


SDK_ENDPOINT_EVIDENCE_LIMIT = 3
RULE_BUDGET_INTERVAL = 256


def sdk_domain_matches(endpoints, budget=None):
    matches = {}
    for name, _, _, domains in SDK_RULES:
        if budget is not None:
            budget.check()
        selected = []
        for index, endpoint in enumerate(endpoints):
            if budget is not None and index % RULE_BUDGET_INTERVAL == 0:
                budget.check()
            if endpoint.get("host") and any(
                host_matches(endpoint["host"], domain) for domain in domains
            ):
                selected.append(endpoint)
                if len(selected) == SDK_ENDPOINT_EVIDENCE_LIMIT:
                    break
        matches[name] = selected
    return matches


def sdk_matches(types, endpoints, artifact, entry, domain_matches=None, budget=None):
    if domain_matches is None:
        domain_matches = sdk_domain_matches(endpoints, budget)
    results = []
    for name, purpose, prefixes, _ in SDK_RULES:
        evidence = []
        namespaces = tuple("L" + prefix for prefix in prefixes)
        for index, descriptor in enumerate(types):
            if budget is not None and index % RULE_BUDGET_INTERVAL == 0:
                budget.check()
            if descriptor.startswith(namespaces):
                item = {
                    "artifact": artifact,
                    "entry": entry,
                    "kind": "dex_type",
                    "type_index": index,
                    "excerpt": descriptor,
                }
                item["id"] = stable_id("sdk_type", name, artifact, entry, index)
                evidence.append(item)
                break
        matching_endpoints = domain_matches[name]
        for endpoint in matching_endpoints:
            evidence.extend(endpoint["evidence"][:1])
        if evidence:
            results.append(
                {
                    "id": stable_id("sdk", name, artifact, entry),
                    "name": name,
                    "purpose": purpose,
                    "evidence_level": "E1",
                    "match_basis": "namespace_and_domain"
                    if matching_endpoints
                    and any(item["kind"] == "dex_type" for item in evidence)
                    else "namespace"
                    if any(item["kind"] == "dex_type" for item in evidence)
                    else "domain_only",
                    "evidence": evidence,
                }
            )
    return results


def capabilities(permissions, signals):
    results = []
    for category, names in CAPABILITIES.items():
        matches = [
            item
            for item in permissions
            if item["name"].startswith("android.permission.")
            and item["name"].rsplit(".", 1)[-1] in names
        ]
        if matches:
            results.append(
                {
                    "type": category,
                    "evidence_level": "E0",
                    "permissions": [item["name"] for item in matches],
                    "meaning": "Declared access capability; actual use is unproven",
                }
            )
    levels = {}
    for signal in signals:
        name = signal["type"]
        if name in SENSITIVE_SIGNALS or name == "sensor_api":
            levels[name] = max(levels.get(name, "E0"), signal["evidence_level"])
    for name, level in sorted(levels.items()):
        results.append(
            {
                "type": name,
                "evidence_level": level,
                "meaning": "Static API or string evidence; availability and actual use are unproven",
            }
        )
    return results
