---
default: patch
---

# Stopping a sandboxed game on Linux now really stops it

Before, the stop button on Linux only closed the sandbox around the game, and the game kept running. Sandboxed games also can no longer see the other programs you run or their command lines. On systems where /etc/resolv.conf points outside /etc and /run, such as WSL, they can now go online. Under WSL, sandboxed games no longer crash on start because they couldn't find the display, and they can use the GPU and the sound server. Your saved login is no longer kept whole in the desktop keyring, so a game can't read it even on systems where bubblewrap is blocked, such as Ubuntu 24.04. The protection badge now says when your system blocks bubblewrap instead of telling you to install it.
