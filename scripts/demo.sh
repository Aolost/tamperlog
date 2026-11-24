#!/usr/bin/env bash
# Terminal demo: write a log, tamper with it three ways, watch each get caught.
# Usage: scripts/demo.sh [WORKDIR]   (WORKDIR defaults to a new mktemp dir)
set -u
TL="${TL:-$(pwd)/bin/tamperlog}"
work="${1:-$(mktemp -d)}"
mkdir -p "$work"
cd "$work" || exit 2
export TAMPERLOG_DIR=audit
seg=audit/segments/00000000000000000000.seg

# Print the command as typed, run it with the built binary, show the exit code.
run() {
	local shown="\$" a
	for a in "$@"; do [[ $a == *" "* ]] && a="\"$a\""; shown+=" $a"; done
	echo "$shown"
	shift
	"$TL" "$@"
	echo "[exit $?]"
	echo
}

run tamperlog init --key signing.pem
run tamperlog append "user=alice action=login"
run tamperlog append "user=alice action=sudo"
run tamperlog append "user=bob action=delete-db"
run tamperlog checkpoint -o witness.ck
run tamperlog verify --pubkey signing.pem.pub --against witness.ck
cp -a audit audit.good

echo "# 1. attacker flips one byte in the middle of the log"
echo "\$ printf X | dd of=$seg bs=1 seek=180 conv=notrunc"
printf 'X' | dd of="$seg" bs=1 seek=180 conv=notrunc status=none
run tamperlog verify --pubkey signing.pem.pub
cp -a audit.good/segments/. audit/segments/

echo "# 2. attacker deletes the last entry, cutting at an exact record boundary"
echo "\$ truncate -s -118 $seg"
truncate -s -118 "$seg"
run tamperlog verify --pubkey signing.pem.pub

echo "# 3. ...and also deletes the newest checkpoint. Locally the log now looks"
echo "#    perfect; only the witness checkpoint held elsewhere catches it."
echo "\$ rm audit/checkpoints/00000000000000000003.ck"
rm -f audit/checkpoints/00000000000000000003.ck
run tamperlog verify --pubkey signing.pem.pub
run tamperlog verify --pubkey signing.pem.pub --against witness.ck
