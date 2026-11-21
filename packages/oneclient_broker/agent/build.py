#!/usr/bin/env python3
"""Builds oneclient-agent.jar from src/ (Java 8) and src11/ (Java 11) with javac.

The jar is committed and embedded into the launcher with include_bytes!, so
building the launcher never needs a JDK. Entries are sorted and timestamped
1980-01-01 so the same sources always give the same bytes; CI rebuilds it and
fails if the committed jar is stale (`python build.py --check`).

Needs a JDK 11+ (it targets Java 8 bytecode with --release 8).
"""

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "src"
SRC11 = HERE / "src11"
JAR = HERE / "oneclient-agent.jar"

MANIFEST = (
    "Manifest-Version: 1.0\r\n"
    "Premain-Class: org.polyfrost.oneclient.agent.Agent\r\n"
    "Agent-Class: org.polyfrost.oneclient.agent.Agent\r\n"
    "Can-Retransform-Classes: true\r\n"
    "Can-Redefine-Classes: true\r\n"
    "\r\n"
)


def build() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "classes"
        sources = sorted(str(p) for p in SRC.rglob("*.java"))
        subprocess.run(
            ["javac", "--release", "8", "-Xlint:-options", "-g:source,lines",
             "-encoding", "UTF-8", "-d", str(out), *sources],
            check=True,
        )
        # Java 11+ only parts (java.net.http), stored as .class11 for
        # ModuleLoader so mod loaders scanning the class path skip them
        out11 = pathlib.Path(tmp) / "classes11"
        modern = sorted(str(p) for p in SRC11.rglob("*.java"))
        subprocess.run(
            ["javac", "--release", "11", "-g:source,lines", "-encoding", "UTF-8",
             "-cp", str(out), "-d", str(out11), *modern],
            check=True,
        )
        jar_path = pathlib.Path(tmp) / "agent.jar"
        stamp = (1980, 1, 1, 0, 0, 0)
        with zipfile.ZipFile(jar_path, "w", zipfile.ZIP_DEFLATED) as jar:
            def add(name: str, data: bytes) -> None:
                info = zipfile.ZipInfo(name, stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                jar.writestr(info, data)

            add("META-INF/MANIFEST.MF", MANIFEST.encode())
            for path in sorted(out.rglob("*.class")):
                add(path.relative_to(out).as_posix(), path.read_bytes())
            for path in sorted(out11.rglob("*.class")):
                add(path.relative_to(out11).as_posix() + "11", path.read_bytes())
        return jar_path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed jar is stale")
    args = parser.parse_args()

    if shutil.which("javac") is None:
        print("javac not found; install a JDK 11 or newer", file=sys.stderr)
        return 2

    built = build()
    if args.check:
        if not JAR.exists() or JAR.read_bytes() != built:
            print("oneclient-agent.jar is out of date; run agent/build.py", file=sys.stderr)
            return 1
        print("oneclient-agent.jar is up to date")
        return 0

    JAR.write_bytes(built)
    print(f"wrote {JAR} ({len(built)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
