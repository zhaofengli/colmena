set -euo pipefail

destination=%DESTINATION%
tmp="${destination}.tmp"
user=%USER%
group=%GROUP%
permissions=%PERMISSIONS%
require_ownership=%REQUIRE_OWNERSHIP%

mkdir -p $(dirname "$destination")
touch "$tmp"

if [ -n "$require_ownership" ] || getent passwd "$user" >/dev/null && getent group "$group" >/dev/null; then
	chown "$user:$group" "$tmp"
else
	>&2 echo "User $user and/or group $group do not exist. Skipping chown."
fi

chmod "$permissions" "$tmp"
cat <&0 >$tmp
mv "$tmp" "$destination"
