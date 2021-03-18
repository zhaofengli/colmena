set -euo pipefail

destination=%DESTINATION%
tmp="${destination}.tmp"
user=%USER%
group=%GROUP%
permissions=%PERMISSIONS%

mkdir -p $(dirname "$destination")
touch "$tmp"

if getent passwd "$user" >/dev/null && getent group "$group" >/dev/null; then
	chown "$user:$group" "$tmp"
else
	>&2 echo "User $user and/or group $group do not exist. Skipping chown."
fi

chmod "$permissions" "$tmp"
cat <&0 >$tmp
mv "$tmp" "$destination"
