#!/bin/sh
# Adaptive privilege-drop entrypoint.
#
# Goal: writes to the bind-mounted backend/cache + backend/history land with the
# SAME ownership as the host directory, with zero per-host config — no APP_UID
# build arg, no manual `chown` on the host. The container boots as root, figures
# out which UID/GID it should be, fixes ownership, then drops to that user.
#
# UID/GID resolution order:
#   1. Explicit PUID / PGID env vars (set in .env or compose) — wins if present.
#   2. Otherwise: adopt the owner of the bind-mounted cache dir (so the container
#      "becomes" whoever owns the host folder — the elegant default).
#   3. Fall back to 1000 if the dir can't be stat'd.
# A root-owned mount (UID 0, e.g. a fresh named volume) just runs as root.
set -e

CACHE_DIR=/app/backend/cache

resolve() {  # $1=env value  $2=stat fmt  -> echoes the chosen id
    if [ -n "$1" ]; then echo "$1"; else stat -c "$2" "$CACHE_DIR" 2>/dev/null || echo 1000; fi
}

TARGET_UID="$(resolve "$PUID" '%u')"
TARGET_GID="$(resolve "$PGID" '%g')"

# Fresh/root-owned mount → stay root, it can write anywhere. No drop needed.
if [ "$TARGET_UID" = "0" ]; then
    exec "$@"
fi

# Re-point the prebuilt 'app' user/group to the target ids (-o allows non-unique).
groupmod -o -g "$TARGET_GID" app 2>/dev/null || true
usermod  -o -u "$TARGET_UID" -g "$TARGET_GID" app 2>/dev/null || true

# Align ownership of every surface the app writes to: the two mounts + its home
# (uv cache lives under $HOME). .venv stays root-owned — read+exec is enough.
chown -R "$TARGET_UID:$TARGET_GID" \
    /app/backend/cache /app/backend/history /home/app 2>/dev/null || true

exec gosu "$TARGET_UID:$TARGET_GID" "$@"
