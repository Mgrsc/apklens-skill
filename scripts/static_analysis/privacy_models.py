MODEL_VERSION = "5"
SOURCE_METHODS = {}

for owner, category, signatures in (
    (
        "Landroid/telephony/TelephonyManager;",
        "device_identifier",
        (
            "getDeviceId()Ljava/lang/String;",
            "getDeviceId(I)Ljava/lang/String;",
            "getImei()Ljava/lang/String;",
            "getImei(I)Ljava/lang/String;",
            "getMeid()Ljava/lang/String;",
            "getMeid(I)Ljava/lang/String;",
            "getSubscriberId()Ljava/lang/String;",
            "getSimSerialNumber()Ljava/lang/String;",
        ),
    ),
    (
        "Landroid/telephony/SubscriptionInfo;",
        "sim_identifier",
        ("getIccId()Ljava/lang/String;",),
    ),
    ("Landroid/os/Build;", "device_identifier", ("getSerial()Ljava/lang/String;",)),
    (
        "Landroid/content/pm/PackageManager;",
        "installed_apps_api",
        (
            "getInstalledPackages(I)Ljava/util/List;",
            "getInstalledApplications(I)Ljava/util/List;",
            "getInstalledPackages(Landroid/content/pm/PackageManager$PackageInfoFlags;)Ljava/util/List;",
            "getInstalledApplications(Landroid/content/pm/PackageManager$ApplicationInfoFlags;)Ljava/util/List;",
        ),
    ),
    (
        "Landroid/content/pm/PackageManager;",
        "application_fingerprint",
        (
            "getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
            "getPackageInfo(Ljava/lang/String;Landroid/content/pm/PackageManager$PackageInfoFlags;)Landroid/content/pm/PackageInfo;",
            "getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;",
        ),
    ),
    (
        "Landroid/app/usage/UsageStatsManager;",
        "usage_stats",
        (
            "queryUsageStats(IJJ)Ljava/util/List;",
            "queryEvents(JJ)Landroid/app/usage/UsageEvents;",
            "queryAndAggregateUsageStats(JJ)Ljava/util/Map;",
        ),
    ),
    (
        "Landroid/app/usage/NetworkStatsManager;",
        "network_stats",
        (
            "queryDetailsForUid(ILjava/lang/String;JJI)Landroid/app/usage/NetworkStats;",
            "querySummary(ILjava/lang/String;JJ)Landroid/app/usage/NetworkStats;",
            "queryDetails(ILjava/lang/String;JJ)Landroid/app/usage/NetworkStats;",
            "querySummaryForDevice(ILjava/lang/String;JJ)Landroid/app/usage/NetworkStats$Bucket;",
        ),
    ),
    (
        "Landroid/net/TrafficStats;",
        "network_stats",
        (
            "getUidRxBytes(I)J",
            "getUidTxBytes(I)J",
            "getTotalRxBytes()J",
            "getTotalTxBytes()J",
        ),
    ),
    (
        "Landroid/content/pm/SigningInfo;",
        "application_fingerprint",
        (
            "getApkContentsSigners()[Landroid/content/pm/Signature;",
            "getSigningCertificateHistory()[Landroid/content/pm/Signature;",
        ),
    ),
):
    for signature in signatures:
        SOURCE_METHODS[owner + "->" + signature] = category

AUDIO_READS = {
    "Landroid/media/AudioRecord;->read([BII)I",
    "Landroid/media/AudioRecord;->read([BIII)I",
    "Landroid/media/AudioRecord;->read([SII)I",
    "Landroid/media/AudioRecord;->read([SIII)I",
    "Landroid/media/AudioRecord;->read([FIII)I",
    "Landroid/media/AudioRecord;->read(Ljava/nio/ByteBuffer;I)I",
    "Landroid/media/AudioRecord;->read(Ljava/nio/ByteBuffer;II)I",
}
SCREEN_SURFACE = "Landroid/media/projection/MediaProjection;->createVirtualDisplay(Ljava/lang/String;IIIILandroid/view/Surface;Landroid/hardware/display/VirtualDisplay$Callback;Landroid/os/Handler;)Landroid/hardware/display/VirtualDisplay;"
TRANSFORMS = {
    "Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;",
    "Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;",
    "Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;",
    "Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;",
    "Landroid/util/Base64;->encode([BI)[B",
    "Ljava/util/Base64$Encoder;->encode([B)[B",
    "Ljava/util/Base64$Encoder;->encodeToString([B)Ljava/lang/String;",
    "Ljavax/crypto/Cipher;->doFinal([B)[B",
    "Ljavax/crypto/Cipher;->doFinal([BII)[B",
    "Ljavax/crypto/Cipher;->update([B)[B",
    "Ljava/security/MessageDigest;->digest([B)[B",
    "Ljava/lang/String;->getBytes()[B",
    "Ljava/lang/String;->getBytes(Ljava/lang/String;)[B",
    "Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B",
}
BOUNDARY_OWNERS = {
    "Ljava/lang/reflect/Method;": "reflection",
    "Ljava/lang/reflect/Constructor;": "reflection",
    "Ldalvik/system/DexClassLoader;": "dynamic_loading",
    "Ldalvik/system/PathClassLoader;": "dynamic_loading",
    "Landroid/os/IBinder;": "ipc",
    "Landroid/os/Binder;": "ipc",
    "Landroid/webkit/WebView;": "webview_or_script",
}
SENSITIVE_SIGNALS = frozenset(
    {
        "installed_apps_api",
        "application_fingerprint",
        "usage_stats",
        "network_stats",
        "device_identifier",
        "sim_identifier",
        "identifier_field",
        "screen_capture",
        "audio_capture",
        "speech_recognition",
        "location_api",
        "contacts_api",
        "sms_api",
        "clipboard_api",
    }
)
PRECISE_CALL_SIGNALS = frozenset(SOURCE_METHODS.values()) | {
    "audio_capture",
    "screen_capture",
    "identifier_field",
}


def call_signal(signature):
    if signature in SOURCE_METHODS:
        return SOURCE_METHODS[signature]
    if (
        signature in AUDIO_READS
        or signature == "Landroid/media/AudioRecord;->startRecording()V"
    ):
        return "audio_capture"
    if (
        signature == SCREEN_SURFACE
        or signature
        == "Landroid/media/projection/MediaProjectionManager;->createScreenCaptureIntent()Landroid/content/Intent;"
    ):
        return "screen_capture"
    return None


def invocation_roles(signature):
    roles = []
    source = call_signal(signature)
    if source:
        roles.append("source:" + source)
    owner = signature.split("->", 1)[0]
    if owner in {
        "Ljava/net/URL;",
        "Ljava/net/URLConnection;",
        "Ljava/net/HttpURLConnection;",
        "Ljava/net/Socket;",
        "Ljavax/net/ssl/HttpsURLConnection;",
        "Lokhttp3/Request;",
        "Lokhttp3/Request$Builder;",
        "Lokhttp3/RequestBody;",
        "Lokhttp3/OkHttpClient;",
        "Lokhttp3/Call;",
    }:
        roles.append("network")
    if signature in TRANSFORMS:
        roles.append("transform")
    return roles
