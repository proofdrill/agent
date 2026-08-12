#!/usr/bin/env bash
# End to end against MinIO, which is the point: the signer has to be checked by
# an implementation that is not ours. A test server we wrote would agree with our
# own mistakes — the same reason the control plane computes TOTP and Stripe's
# HMAC independently in its tests rather than calling its own code twice.
#
#   dev/verify-s3.sh                    (run from the repository root)
#
# From Git Bash on Windows, prefix it with `MSYS_NO_PATHCONV=1
# MSYS2_ARG_CONV_EXCL='*'`. MSYS rewrites anything that looks like an absolute
# path before docker sees it, so `--entrypoint /usr/local/bin/proofdrill` becomes
# a path under the Git installation and every container exits 127 with a message
# about a file on the host — which reads like a broken image and is not one.
#
# Everything it creates is removed on the way out, including on failure.
set -uo pipefail

NETWORK=proofdrill-verify
VOLUME=proofdrill-fixtures
MINIO=proofdrill-minio
IMAGE=proofdrill-agent:verify
KEY=proofdrilltest
SECRET=proofdrilltestsecret
FAILURES=0

say()  { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
note() { printf '     %s\n' "$1"; }

expect() {
  local what="$1" wanted="$2" got="$3"
  if [ "$wanted" = "$got" ]; then
    printf '  [pass] %s (exit %s)\n' "$what" "$got"
  else
    printf '  [FAIL] %s: expected exit %s, got %s\n' "$what" "$wanted" "$got"
    FAILURES=$((FAILURES + 1))
  fi
}

# Output is captured and then searched, never piped into grep. With `pipefail`
# set, the exit status of `producer | grep` is the producer's whenever it is
# non-zero — so every check on a command that is SUPPOSED to fail would read the
# wrong status and report a pass or a failure at random.
says() {
  local what="$1" needle="$2" haystack="$3"
  if printf '%s' "$haystack" | grep -q -- "$needle"; then
    printf '  [pass] %s\n' "$what"
  else
    printf '  [FAIL] %s: nothing in the output matched "%s"\n' "$what" "$needle"
    printf '%s\n' "$haystack" | sed 's/^/         | /' | head -6
    FAILURES=$((FAILURES + 1))
  fi
}

cleanup() {
  docker rm -f "$MINIO" >/dev/null 2>&1
  docker volume rm -f "$VOLUME" >/dev/null 2>&1
  docker network rm "$NETWORK" >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

agent() {
  docker run --rm --network "$NETWORK" \
    --cap-drop=ALL --security-opt=no-new-privileges --memory=1g \
    -e PROOFDRILL_S3_ACCESS_KEY_ID="$1" \
    -e PROOFDRILL_S3_SECRET_ACCESS_KEY="$2" \
    --entrypoint /usr/local/bin/proofdrill \
    "$IMAGE" "${@:3}"
}

# ---------------------------------------------------------------------------
say "bringing up MinIO and putting a real artefact in it"
# ---------------------------------------------------------------------------
cleanup
docker network create "$NETWORK" >/dev/null
docker volume create "$VOLUME" >/dev/null

docker run -d --name "$MINIO" --network "$NETWORK" \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadminsecret \
  minio/minio server /data >/dev/null

# Docker creates a fresh named volume owned by root, so it is handed over first.
# The fixture itself is then made by the ordinary unprivileged user — which is
# not tidiness: initdb refuses to run as root, and that refusal is the same
# property this whole image is built on.
docker run --rm --user root -v "$VOLUME":/out --entrypoint chown "$IMAGE" 10001:10001 /out
docker run --rm -v "$VOLUME":/out --entrypoint /usr/local/bin/make-fixture.sh \
  "$IMAGE" /out/db-2026-08-11.dump /out/globals-2026-08-11.sql

# mc retries until MinIO answers, so no sleep is needed and none is guessed at.
docker run --rm --network "$NETWORK" -v "$VOLUME":/in --entrypoint sh minio/mc -c "
  set -e
  until mc alias set m http://$MINIO:9000 minioadmin minioadminsecret >/dev/null 2>&1; do sleep 1; done
  mc mb -p m/backups >/dev/null
  mc cp /in/db-2026-08-11.dump m/backups/nightly/db-2026-08-11.dump >/dev/null
  mc cp /in/globals-2026-08-11.sql m/backups/nightly/globals-2026-08-11.sql >/dev/null
  mc cp /in/db-2026-08-11.dump 'm/backups/nightly/notes and spaces.txt' >/dev/null
  mc admin user add m $KEY $SECRET >/dev/null
  mc admin policy attach m readwrite --user $KEY >/dev/null
  echo 'uploaded, and a limited user exists'
"

# ---------------------------------------------------------------------------
say "1. doctor against real storage — it downloads nothing"
# ---------------------------------------------------------------------------
agent "$KEY" "$SECRET" doctor \
  --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
  --s3-prefix nightly/ --s3-pattern 'db-*.dump' --rpo-window-hours 99999
expect "doctor reports ready" 0 "$?"

# ---------------------------------------------------------------------------
say "2. the diagnoses that are the reason doctor exists"
# ---------------------------------------------------------------------------
says "an empty prefix is not reported as a missing backup" "NOT evidence that the backups are missing" \
  "$(agent "$KEY" "$SECRET" doctor \
      --s3-endpoint "http://$MINIO:9000" --s3-bucket backups --s3-prefix wrong-place/ 2>&1)"

says "a pattern that matches nothing names what is there instead" "none matches" \
  "$(agent "$KEY" "$SECRET" doctor \
      --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
      --s3-prefix nightly/ --s3-pattern 'nothing-*.dump' 2>&1)"

says "a wrong access key is named as such" "InvalidAccessKeyId" \
  "$(agent wrong-key "$SECRET" doctor --s3-endpoint "http://$MINIO:9000" --s3-bucket backups 2>&1)"

says "a wrong secret is named as such" "SignatureDoesNotMatch" \
  "$(agent "$KEY" wrong-secret doctor --s3-endpoint "http://$MINIO:9000" --s3-bucket backups 2>&1)"

says "a bucket that does not exist is named" "bucket" \
  "$(agent "$KEY" "$SECRET" doctor --s3-endpoint "http://$MINIO:9000" --s3-bucket no-such-bucket 2>&1)"

# ---------------------------------------------------------------------------
say "3. a signature MinIO accepts for a key with a space in it"
# ---------------------------------------------------------------------------
# The canonical path is where a signer goes wrong, and MinIO is the independent
# judge of whether ours is right.
says "an object whose name contains spaces is listed and read" "can also be read" \
  "$(agent "$KEY" "$SECRET" doctor \
      --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
      --s3-prefix nightly/ --s3-pattern '*spaces.txt' 2>&1)"

# ---------------------------------------------------------------------------
say "4. a full drill, fetched from the bucket"
# ---------------------------------------------------------------------------
agent "$KEY" "$SECRET" drill \
  --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
  --s3-prefix nightly/ --s3-pattern 'db-*.dump' --rpo-window-hours 99999
expect "the drill fetches, restores and passes" 0 "$?"

# ---------------------------------------------------------------------------
say "5. the second artefact, fetched from the same bucket"
# ---------------------------------------------------------------------------
# The globals path that `--globals-file` cannot exercise: two objects, one
# listing, and a pattern of its own. The unit suite reads the file and the
# container suite applies it; only this proves the agent finds it.
says "doctor finds the globals artefact without downloading it" "globals_artefact_found" \
  "$(agent "$KEY" "$SECRET" doctor \
      --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
      --s3-prefix nightly/ --s3-pattern 'db-*.dump' \
      --s3-globals-pattern 'globals-*.sql' --rpo-window-hours 99999 2>&1)"

# A globals pattern matching nothing is NOT READY, and the sentence has to keep
# it separate from the backup: it means level 3's role question cannot be
# answered, not that the backup is in doubt.
says "a globals pattern that matches nothing is a diagnosis, not a verdict on the backup" \
  "says nothing about the backup itself" \
  "$(agent "$KEY" "$SECRET" doctor \
      --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
      --s3-prefix nightly/ --s3-pattern 'db-*.dump' \
      --s3-globals-pattern 'no-such-globals-*.sql' --rpo-window-hours 99999 2>&1)"

WITH_GLOBALS="$(agent "$KEY" "$SECRET" drill \
  --s3-endpoint "http://$MINIO:9000" --s3-bucket backups \
  --s3-prefix nightly/ --s3-pattern 'db-*.dump' \
  --s3-globals-pattern 'globals-*.sql' --rpo-window-hours 99999 --json 2>&1)"
expect "a drill fetches both artefacts and passes" 0 "$?"

says "the report names the globals artefact it fetched" "globals-2026-08-11.sql" "$WITH_GLOBALS"
says "and the roles came back as the globals declare them" \
  '"key": "roles_present_with_their_attributes",' "$WITH_GLOBALS"
says "so the role the policy names is asked about at all" \
  '"key": "no_role_is_exempt_from_a_policy_that_names_it",' "$WITH_GLOBALS"

# ---------------------------------------------------------------------------
say "6. credentials are refused on the command line"
# ---------------------------------------------------------------------------
says "a secret passed as an argument is refused, with the reason" "readable by every process" \
  "$(agent "$KEY" "$SECRET" doctor --s3-endpoint "http://$MINIO:9000" \
      --s3-bucket backups --s3-secret-access-key hunter2 2>&1)"

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
  printf 'S3 VERIFICATION PASSED\n'
  exit 0
fi
printf 'S3 VERIFICATION FAILED: %s check(s)\n' "$FAILURES"
exit 1
