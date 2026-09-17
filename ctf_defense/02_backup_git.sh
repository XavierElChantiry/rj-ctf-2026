#!/usr/bin/env bash
# Snapshot critical directories two ways: a tar.gz off to the side (survives
# even if someone deletes the .git directory) and a git repo in place (fast
# diff/rollback). Safe to re-run any time — commits are no-ops if nothing
# changed, and re-running never touches the tar timestamp naming.
set -u
cd "$(dirname "$0")" && source ./config.sh

STAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE_DIR="$WORKDIR/backups"
mkdir -p "$ARCHIVE_DIR"

for dir in $BACKUP_DIRS; do
    [ -d "$dir" ] || { echo "skip $dir: does not exist"; continue; }

    name=$(echo "$dir" | tr '/' '_' | sed 's/^_//')
    tar czf "$ARCHIVE_DIR/${name}_${STAMP}.tar.gz" -C / "${dir#/}" 2>/dev/null \
        && echo "archived $dir -> $ARCHIVE_DIR/${name}_${STAMP}.tar.gz"

    if [ ! -d "$dir/.git" ]; then
        git init -q "$dir"
        # Competitors sometimes drop huge payloads/binaries in web roots —
        # cap what git tracks so a commit never hangs on a multi-GB file.
        find "$dir" -type f -size +50M > "$dir/.gitignore" 2>/dev/null || true
        (cd "$dir" && git add -A && git commit -q -m "baseline $STAMP") \
            && echo "git-initialized $dir"
    else
        (cd "$dir" && git add -A && git commit -q -m "snapshot $STAMP" >/dev/null 2>&1)
        if [ $? -eq 0 ]; then
            echo "snapshotted $dir (changes committed)"
        else
            echo "snapshotted $dir (no changes since last commit)"
        fi
    fi
done

cat > "$WORKDIR/rollback.sh" <<'EOF'
#!/usr/bin/env bash
# Usage: ./rollback.sh /etc            (revert one dir to its last commit)
#        ./rollback.sh /etc HEAD~3     (revert to an older snapshot)
set -eu
dir="$1"
ref="${2:-HEAD}"
cd "$dir"
git reset --hard "$ref"
git clean -fd
echo "reverted $dir to $ref"
EOF
chmod +x "$WORKDIR/rollback.sh"

echo
echo "rollback helper: $WORKDIR/rollback.sh <dir> [git-ref]"
