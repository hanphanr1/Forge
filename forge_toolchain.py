from pathlib import Path
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
}


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
