import re

from .common import stable_id
from .endpoints import host_matches

RULE_VERSION = "1"
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
    "screen": ["FOREGROUND_SERVICE_MEDIA_PROJECTION"],
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
    "device_identifier": r"(?:getDeviceId|getImei|getMeid|getSubscriberId|getSerial|ANDROID_ID|android_id|AdvertisingIdClient|AppSetIdClient|oaid|OpenDeviceIdentifier)",
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


def signal_matches(value, source, level="E1"):
    findings = []
    for name, pattern in SIGNALS.items():
        if pattern.search(value):
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


def sdk_matches(types, endpoints, artifact, entry):
    results = []
    for name, purpose, prefixes, domains in SDK_RULES:
        evidence = []
        namespaces = tuple("L" + prefix for prefix in prefixes)
        for index, descriptor in enumerate(types):
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
        matching_endpoints = [
            item
            for item in endpoints
            if item.get("host")
            and any(host_matches(item["host"], domain) for domain in domains)
        ]
        for endpoint in matching_endpoints[:3]:
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
    for name in sorted(
        {item["type"] for item in signals}
        & {"device_identifier", "clipboard_api", "sensor_api", "installed_apps_api"}
    ):
        results.append(
            {
                "type": name,
                "evidence_level": "E1",
                "meaning": "Static API or string evidence; availability and actual use are unproven",
            }
        )
    return results
