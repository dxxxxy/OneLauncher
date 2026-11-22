---
default: minor
---

# Sign-in tokens are now kept in your system keychain instead of a plain file

On Windows they are encrypted with your Windows account (DPAPI), on macOS they live in the Keychain, and on Linux in the Secret Service (GNOME Keyring or KWallet). Existing sign-ins move over automatically.
