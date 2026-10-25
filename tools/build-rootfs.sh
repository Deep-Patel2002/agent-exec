#!/usr/bin/env bash
# Builds a minimal, operator-owned runtime from installed distro packages.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root to create the immutable runtime image' >&2; exit 1; }
target=${1:?usage: build-rootfs.sh ABSOLUTE_NEW_DIRECTORY}
[[ "$target" == /* && "$target" != / && ! -e "$target" ]] || { echo 'Target must be a new absolute directory' >&2; exit 1; }
mkdir -p "$target"/usr/bin "$target"/usr/lib "$target"/bin "$target"/etc "$target"/proc "$target"/dev "$target"/tmp "$target"/work "$target"/input
copy_binary() {
    local src=$1 dest=$2 dependency
    install -D -m 0555 "$src" "$target$dest"
    while IFS= read -r dependency; do
        [[ -f "$dependency" ]] && install -D -m 0555 "$dependency" "$target$dependency"
    done < <(ldd "$src" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}')
}
python=$(command -v python3)
stdlib=$(python3 -I -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
[[ "$stdlib" == /usr/lib/python3.* ]] || { echo 'Requires distro-provided Python under /usr/lib' >&2; exit 1; }
copy_binary "$python" /usr/bin/python3
copy_binary /bin/sh /bin/sh
cp -a "$stdlib" "$target/usr/lib/"
while IFS= read -r -d '' library; do
    while IFS= read -r dependency; do
        [[ -f "$dependency" ]] && install -D -m 0555 "$dependency" "$target$dependency"
    done < <(ldd "$library" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}')
done < <(find "$stdlib" -type f -name '*.so' -print0)
printf 'sandbox:x:0:0:Sandbox:/work:/bin/sh\n' > "$target/etc/passwd"
printf 'sandbox:x:0:\n' > "$target/etc/group"
printf 'passwd: files\ngroup: files\n' > "$target/etc/nsswitch.conf"
dpkg-query -W -f='${Package} ${Version}\n' python3-minimal libc6 libseccomp2 > "$target/.source-packages.txt"
(
    cd "$target"
    find . -type f ! -name .sha256-manifest -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > .sha256-manifest
)
chown -R root:root "$target"
chmod -R a-w "$target"
printf 'Created rootfs: %s\n' "$target"
