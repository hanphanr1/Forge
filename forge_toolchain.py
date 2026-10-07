from pathlib import Path
import glob
import os
import re
import shutil

from forge_core import ForgeError


TOOLS_ROOT = Path(__file__).resolve().parent / "tools"
TOOLS = {
    "adb": {
        "env": "FORGE_ADB", "command": "adb",
        "local": ("platform-tools/adb.exe", "platform-tools/adb"),
        "setup": "Install Android Platform Tools in FORGE/tools/platform-tools or set FORGE_ADB",
    },
    "jadx": {
        "env": "FORGE_JADX", "command": "jadx",
        "local": ("jadx/bin/jadx.bat", "jadx/bin/jadx"),
        "setup": "Install JADX in FORGE/tools/jadx with Java 17+ or set FORGE_JADX",
    },
    "frida": {
        "env": "FORGE_FRIDA", "command": "frida",
        "local": ("frida/Scripts/frida.exe", "frida/bin/frida"),
        "setup": "Install frida-tools in FORGE/tools/frida venv or set FORGE_FRIDA; Android also needs device-side setup",
    },
    "frida_apk": {
        "env": "FORGE_FRIDA_APK", "command": "frida-apk",
        "local": ("frida/Scripts/frida-apk.exe", "frida/bin/frida-apk"),
        "setup": "frida-apk ships with frida-tools; install it in FORGE/tools/frida venv or set FORGE_FRIDA_APK",
    },
    "r2": {
        "env": "FORGE_R2", "command": "r2",
        "local": ("radare2/bin/radare2.exe", "radare2/bin/r2.exe", "radare2/radare2.exe",
                  "radare2/r2.exe", "radare2/bin/r2"),
        "setup": "Install radare2 in FORGE/tools/radare2 or set FORGE_R2",
    },
    "java": {
        "env": "FORGE_JAVA", "command": "java", "local": (),
        "setup": "JADX needs a supported Java runtime on PATH; FORGE_JAVA selects an explicit java executable",
    },
    "apktool": {
        "env": "FORGE_APKTOOL", "command": "apktool",
        "local": ("apktool/apktool.bat", "apktool/apktool"),
        "setup": "Install apktool in FORGE/tools/apktool (apktool.jar plus a launcher) or set FORGE_APKTOOL",
    },
    "apksigner": {
        "env": "FORGE_APKSIGNER", "command": "apksigner",
        "local": ("build-tools/apksigner.bat", "build-tools/apksigner"),
        "sdk": ("build-tools/*/apksigner.bat", "build-tools/*/apksigner"),
        "setup": "Install Android build-tools in FORGE/tools/build-tools, set ANDROID_HOME/ANDROID_SDK_ROOT, or set FORGE_APKSIGNER",
    },
    "zipalign": {
        "env": "FORGE_ZIPALIGN", "command": "zipalign",
        "local": ("build-tools/zipalign.exe", "build-tools/zipalign"),
        "sdk": ("build-tools/*/zipalign.exe", "build-tools/*/zipalign"),
        "setup": "Install Android build-tools in FORGE/tools/build-tools, set ANDROID_HOME/ANDROID_SDK_ROOT, or set FORGE_ZIPALIGN",
    },
    "idevice_id": {
        "env": "FORGE_IDEVICE_ID", "command": "idevice_id", "local": (),
        "setup": "Install libimobiledevice so idevice_id is on PATH, or set FORGE_IDEVICE_ID to an explicit executable",
    },
    "idevicepair": {
        "env": "FORGE_IDEVICEPAIR", "command": "idevicepair", "local": (),
        "setup": "Install libimobiledevice so idevicepair is on PATH, or set FORGE_IDEVICEPAIR to an explicit executable",
    },
}


def _sdk_candidate(spec):
    # A caller-configured Android SDK build-tools directory is a normal installation,
    # never a bulk download: select the newest numeric version that exists.
    patterns = spec.get("sdk")
    if not patterns:
        return None
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(variable)
        if not root or not os.path.isdir(root):
            continue
        for pattern in (patterns if os.name == "nt" else tuple(reversed(patterns))):
            if pattern.endswith(".exe") and os.name != "nt":
                continue
            matches = [path for path in glob.glob(os.path.join(root, pattern)) if os.path.isfile(path)]
            if not matches:
                continue
            def version_key(path):
                parts = re.findall(r"\d+", os.path.basename(os.path.dirname(path)))
                return tuple(int(part) for part in (parts + ["0"] * 3)[:3])
            chosen = max(matches, key=version_key)
            if os.name == "nt" or os.access(chosen, os.X_OK):
                return chosen
    return None


def find_tool(name):
    if name not in TOOLS:
        raise ForgeError(f"Unknown tool: {name}")
    spec = TOOLS[name]
    override = os.environ.get(spec["env"])
    if override is not None:
        path = shutil.which(override) if override else None
        return {"available": path is not None, "path": path, "source": spec["env"], "setup": spec["setup"]}
    for relative in spec["local"]:
        candidate = TOOLS_ROOT / relative
        if os.name != "nt" and candidate.suffix.lower() in {".exe", ".bat", ".cmd"}:
            continue
        if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return {"available": True, "path": str(candidate.resolve()), "source": "FORGE/tools", "setup": spec["setup"]}
    sdk = _sdk_candidate(spec)
    if sdk:
        return {"available": True, "path": str(Path(sdk).resolve()), "source": "ANDROID SDK", "setup": spec["setup"]}
    path = shutil.which(spec["command"])
    return {"available": path is not None, "path": path, "source": "PATH", "setup": spec["setup"]}


def executable(name):
    result = find_tool(name)
    if not result["available"]:
        raise ForgeError(f"Missing {name} ({result['source']}): {result['setup']}")
    return result["path"]


def java_environment():
    environment = os.environ.copy()
    override = os.environ.get("FORGE_JAVA")
    if override is not None:
        java = Path(executable("java"))
        environment["JAVA_HOME"] = str(java.parent.parent)
        environment["PATH"] = str(java.parent) + os.pathsep + environment.get("PATH", "")
    options = environment.get("JAVA_OPTS", "") + " " + environment.get("JADX_OPTS", "")
    if not re.search(r"(?:^|\s)-Xmx\S+", options):
        environment["JADX_OPTS"] = (environment.get("JADX_OPTS", "") + " -Xmx2g").strip()
    return environment
