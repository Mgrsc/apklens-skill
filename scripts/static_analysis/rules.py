import re
from functools import lru_cache

from .common import stable_id
from .endpoints import assign_endpoint_roles, host_matches, service_reference
from .evidence import retain_evidence
from .privacy_models import PRECISE_CALL_SIGNALS, SENSITIVE_SIGNALS, call_signal

RULE_VERSION = "7"
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
    ("Meta", "sdk", ["com/facebook/"], ["facebook.com", "facebook.net"]),
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
    ("iFlytek", "sdk", ["com/iflytek/"], ["xfyun.cn"]),
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
    (
        "Fresco",
        "foundation",
        [
            "com/facebook/animated/",
            "com/facebook/animation/",
            "com/facebook/binaryresource/",
            "com/facebook/cache/",
            "com/facebook/datasource/",
            "com/facebook/drawee/",
            "com/facebook/fresco/",
            "com/facebook/imagepipeline/",
            "com/facebook/imageformat/",
            "com/facebook/imageutils/",
        ],
        [],
    ),
    ("React Native", "foundation", ["com/facebook/react/"], []),
    ("SoLoader", "foundation", ["com/facebook/soloader/"], []),
    ("Hermes", "foundation", ["com/facebook/hermes/"], []),
    ("Yoga", "foundation", ["com/facebook/yoga/"], []),
    ("fbjni", "foundation", ["com/facebook/jni/"], []),
    (
        "Facebook Core",
        "social",
        [
            "com/facebook/FacebookSdk;",
            "com/facebook/GraphRequest;",
            "com/facebook/AccessToken;",
        ],
        [],
    ),
    ("Facebook Login", "authentication", ["com/facebook/login/"], []),
    ("Facebook Share", "sharing", ["com/facebook/share/"], []),
    ("Facebook App Events", "analytics", ["com/facebook/appevents/"], []),
    ("Meta Audience Network", "advertising", ["com/facebook/ads/"], []),
    ("fastjson", "foundation", ["com/alibaba/fastjson/", "com/alibaba/fastjson2/"], []),
    ("ARouter", "foundation", ["com/alibaba/android/arouter/"], []),
    ("vlayout", "foundation", ["com/alibaba/android/vlayout/"], []),
    ("MMKV", "foundation", ["com/tencent/mmkv/"], []),
    ("WCDB", "foundation", ["com/tencent/wcdb/"], []),
    ("WeChat OpenSDK", "sharing", ["com/tencent/mm/opensdk/"], []),
    (
        "QQ Connect",
        "authentication",
        ["com/tencent/connect/", "com/tencent/tauth/"],
        [],
    ),
    ("Tinker", "foundation", ["com/tencent/tinker/"], []),
    ("ShadowHook", "foundation", ["com/bytedance/shadowhook/"], []),
    ("Douyin OpenSDK", "authentication", ["com/bytedance/sdk/open/aweme/"], []),
]
VENDOR_RULES = frozenset(
    {"Meta", "Tencent", "Alibaba", "ByteDance", "Baidu", "Sogou", "iFlytek"}
)
COMPONENT_VENDORS = {
    **dict.fromkeys(
        (
            "Fresco",
            "React Native",
            "SoLoader",
            "Hermes",
            "Yoga",
            "fbjni",
            "Facebook Core",
            "Facebook Login",
            "Facebook Share",
            "Facebook App Events",
            "Meta Audience Network",
        ),
        "Meta",
    ),
    **dict.fromkeys(("fastjson", "ARouter", "vlayout"), "Alibaba"),
    **dict.fromkeys(
        ("MMKV", "WCDB", "WeChat OpenSDK", "QQ Connect", "Tinker", "Bugly"), "Tencent"
    ),
    **dict.fromkeys(("ShadowHook", "Douyin OpenSDK", "Pangle"), "ByteDance"),
    **dict.fromkeys(
        ("Firebase Analytics", "Firebase Crashlytics", "Firebase Messaging"), "Google"
    ),
}
COMPONENT_NAMESPACES = {
    vendor: tuple(
        "L" + prefix
        for name, _, prefixes, _ in SDK_RULES
        if name not in VENDOR_RULES and COMPONENT_VENDORS.get(name, name) == vendor
        for prefix in prefixes
    )
    for vendor in VENDOR_RULES
}
SDK_NAMESPACE_PREFIX_LENGTH = min(
    len(prefix) + 1 for _, _, prefixes, _ in SDK_RULES for prefix in prefixes
)
SDK_NAMESPACE_RULES = {
    key: tuple(
        (name, tuple("L" + prefix for prefix in prefixes))
        for name, _, prefixes, _ in SDK_RULES
        if any(("L" + prefix).startswith(key) for prefix in prefixes)
    )
    for key in {
        ("L" + prefix)[:SDK_NAMESPACE_PREFIX_LENGTH]
        for _, _, prefixes, _ in SDK_RULES
        for prefix in prefixes
    }
}
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
    "telemetry_event": r"(?<![A-Za-z0-9_$])(?:logEvent|trackEvent|captureEvent|captureException|reportEvent|recordEvent|sendEvent|setUserId|setUserProperty)(?![A-Za-z0-9_$])|(?:com/umeng/analytics/MobclickAgent;->|com\.umeng\.analytics\.MobclickAgent\.)onEvent(?=\()",
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
TELEMETRY_INVOCATION = re.compile(
    r"^L[^;]+;->(?:logEvent|trackEvent|captureEvent|captureException|reportEvent|recordEvent|sendEvent|setUserId|setUserProperty)\(|^Lcom/umeng/analytics/MobclickAgent;->onEvent\("
)
LOCATION_INVOCATION = re.compile(
    r"^Landroid/location/LocationManager;->(?:getLastKnownLocation|getCurrentLocation|requestLocationUpdates|requestSingleUpdate)\(|^Landroid/location/Location;->(?:getLatitude|getLongitude|getAltitude|getAccuracy|getBearing|getSpeed)\(|^Lcom/google/android/gms/location/(?:FusedLocationProviderClient|FusedLocationProviderApi);->(?:getLastLocation|getCurrentLocation|requestLocationUpdates)\("
)
TELEMETRY_METHODS = {
    "com/google/firebase/analytics/FirebaseAnalytics": (
        "logEvent",
        "setUserId",
        "setUserProperty",
    ),
    "com/google/android/gms/measurement/AppMeasurement": (
        "logEvent",
        "setUserId",
        "setUserProperty",
    ),
    "com/umeng/analytics/MobclickAgent": ("onEvent", "onEventObject", "onEventValue"),
    "io/sentry/Sentry": ("captureEvent", "captureException"),
    "io/sentry/Hub": ("captureEvent", "captureException"),
    "io/sentry/IHub": ("captureEvent", "captureException"),
    "com/sensorsdata/analytics/android/sdk/SensorsDataAPI": (
        "track",
        "trackEvent",
        "setUserId",
    ),
    "com/mixpanel/android/mpmetrics/MixpanelAPI": ("track", "trackEvent"),
    "com/amplitude/api/AmplitudeClient": ("logEvent", "setUserId"),
    "com/amplitude/android/Amplitude": ("track", "setUserId"),
    "com/appsflyer/AppsFlyerLib": ("logEvent",),
    "com/adjust/sdk/Adjust": ("trackEvent",),
    "com/facebook/appevents/AppEventsLogger": ("logEvent", "setUserID"),
}
KNOWN_TELEMETRY_INVOCATION = re.compile(
    "|".join(
        r"(?:L"
        + re.escape(owner)
        + r";->|"
        + re.escape(owner.replace("/", "."))
        + r"\.)(?:"
        + "|".join(map(re.escape, methods))
        + r")\("
        for owner, methods in TELEMETRY_METHODS.items()
    )
)
SPEECH_INVOCATION = re.compile(
    r"^Landroid/speech/SpeechRecognizer;->(?:startListening\(Landroid/content/Intent;\)V|createSpeechRecognizer\(Landroid/content/Context;(?:Landroid/content/ComponentName;)?\)Landroid/speech/SpeechRecognizer;|createOnDeviceSpeechRecognizer\(Landroid/content/Context;\)Landroid/speech/SpeechRecognizer;|setRecognitionListener\(Landroid/speech/RecognitionListener;\)V)$"
)
SENSOR_INVOCATION = re.compile(
    r"^Landroid/hardware/SensorManager;->(?:registerListener\(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;I(?:I|Landroid/os/Handler;|ILandroid/os/Handler;)?\)Z|requestTriggerSensor\(Landroid/hardware/TriggerEventListener;Landroid/hardware/Sensor;\)Z|getDefaultSensor\(I(?:Z)?\)Landroid/hardware/Sensor;|getSensorList\(I\)Ljava/util/List;|getDynamicSensorList\(I\)Ljava/util/List;)$"
)
PRECISE_SIGNAL_CATEGORIES = PRECISE_CALL_SIGNALS | {"speech_recognition", "sensor_api"}


def signal_decisions(value, level):
    precise = call_signal(value) if level == "E2" else None
    if level == "E2" and SPEECH_INVOCATION.match(value):
        precise = "speech_recognition"
    if level == "E2" and SENSOR_INVOCATION.match(value):
        precise = "sensor_api"
    results = []
    for name, pattern in SIGNALS.items():
        known_event = name == "telemetry_event" and (
            KNOWN_TELEMETRY_INVOCATION.match(value)
            if level == "E2"
            else KNOWN_TELEMETRY_INVOCATION.search(value)
        )
        if not (pattern.search(value) or name == precise or known_event):
            continue
        if level == "E2" and name in PRECISE_SIGNAL_CATEGORIES and name != precise:
            continue
        if name == "telemetry_event" and not known_event:
            if level != "E2" or TELEMETRY_INVOCATION.match(value):
                results.append("event_dispatch")
            continue
        if (
            level == "E2"
            and name == "location_api"
            and not LOCATION_INVOCATION.match(value)
        ):
            continue
        results.append(name)
    return tuple(results)


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
        record = {
            "id": stable_id("signal", name, evidence["id"]),
            "type": name,
            "evidence_level": level,
            "evidence": [evidence],
        }
        if level == "E2" and name in {"sensor_api", "speech_recognition"}:
            method = value.split("->", 1)[1].split("(", 1)[0]
            record["operation"] = (
                "enumeration"
                if method.startswith("get")
                else "registration"
                if method
                in {
                    "registerListener",
                    "requestTriggerSensor",
                    "setRecognitionListener",
                }
                else "acquisition"
                if method == "startListening"
                else "setup"
            )
        findings.append(record)
    return findings


SDK_ENDPOINT_EVIDENCE_LIMIT = 3
RULE_BUDGET_INTERVAL = 256


def sdk_domain_matches(endpoints, budget=None):
    matches = {}
    for name, _, _, domains in SDK_RULES:
        if budget is not None:
            budget.check()
        selected = []
        if not domains:
            matches[name] = selected
            continue
        identities = set()
        for index, endpoint in enumerate(endpoints):
            if budget is not None and index % RULE_BUDGET_INTERVAL == 0:
                budget.check()
            if endpoint.get("host") and any(
                host_matches(endpoint["host"], domain) for domain in domains
            ):
                if endpoint["id"] in identities:
                    continue
                identities.add(endpoint["id"])
                assign_endpoint_roles(endpoint)
                if len(selected) < SDK_ENDPOINT_EVIDENCE_LIMIT:
                    selected.append(endpoint)
                elif service_reference(endpoint):
                    for selected_index, previous in enumerate(selected):
                        if not service_reference(previous):
                            selected[selected_index] = endpoint
                            break
        matches[name] = selected
    return matches


def sdk_matches(
    types,
    endpoints,
    artifact,
    entry,
    domain_matches=None,
    budget=None,
    *,
    defined_types=None,
    include_domains=True,
    max_evidence=20,
):
    if domain_matches is None:
        domain_matches = sdk_domain_matches(endpoints, budget)
    type_matches = {}
    for index, descriptor in enumerate(types):
        if budget is not None and index % RULE_BUDGET_INTERVAL == 0:
            budget.check()
        for name, namespaces in SDK_NAMESPACE_RULES.get(
            descriptor[:SDK_NAMESPACE_PREFIX_LENGTH], ()
        ):
            match = type_matches.get(name)
            definition = defined_types is not None and index in defined_types
            kind = "dex_class_definition" if definition else "dex_type_reference"
            if match is not None and (kind in match[2] or defined_types is None):
                continue
            if descriptor.startswith(namespaces):
                if name in VENDOR_RULES and descriptor.startswith(
                    COMPONENT_NAMESPACES.get(name, ())
                ):
                    continue
                item = {
                    "artifact": artifact,
                    "entry": entry,
                    "kind": kind,
                    "type_index": index,
                    "excerpt": descriptor,
                }
                if definition:
                    item["class_def_index"] = defined_types[index]
                item["id"] = stable_id("sdk_type", name, artifact, entry, index)
                match = type_matches.setdefault(name, [[], False, set()])
                match[1] |= retain_evidence(match[0], [item], max_evidence)
                match[2].add(kind)
    results = []
    for name, purpose, _, _ in SDK_RULES:
        evidence, evidence_truncated, _ = type_matches.get(name, ([], False, ()))
        if evidence:
            results.append(
                {
                    "id": stable_id("sdk", name, artifact, entry),
                    "name": name,
                    "vendor": COMPONENT_VENDORS.get(name, name),
                    "record_kind": "vendor_reference"
                    if name in VENDOR_RULES
                    else "component",
                    "purpose": purpose,
                    "evidence_level": "E1",
                    "evidence_truncated": evidence_truncated,
                    "match_basis": "namespace",
                    "meaning": "Static component or vendor reference; runtime enablement and data transmission are unproven",
                    "evidence": evidence,
                }
            )
        if include_domains and domain_matches[name]:
            domain_evidence = []
            domain_truncated = False
            roles = set()
            for endpoint in domain_matches[name]:
                assign_endpoint_roles(endpoint)
                roles.update(endpoint["roles"])
                domain_truncated |= retain_evidence(
                    domain_evidence, endpoint["evidence"][:1], max_evidence
                )
            results.append(
                {
                    "id": stable_id("sdk_domain", name, artifact),
                    "name": name,
                    "vendor": COMPONENT_VENDORS.get(name, name),
                    "record_kind": "service_reference",
                    "purpose": purpose,
                    "evidence_level": "E1",
                    "evidence_truncated": domain_truncated,
                    "match_basis": "domain_only",
                    "roles": sorted(roles),
                    "meaning": "Address reference only; code integration and actual network use are unproven",
                    "evidence": domain_evidence,
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
            and item.get("declaration") != "snapshot_only"
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
