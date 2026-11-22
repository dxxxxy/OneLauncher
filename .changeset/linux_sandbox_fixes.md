---
default: patch
---

# Stopping a sandboxed game on Linux now really stops it

Before, the stop button on Linux only closed the sandbox around the game, and the game kept running. Sandboxed games also can no longer see the other programs you run or their command lines. On systems where /etc/resolv.conf points outside /etc and /run, such as WSL, they can now go online.
