#!/usr/bin/env bash


INPUT="$1"
TESTSSL="./testssl.sh/testssl.sh"

if [ -z "$INPUT" ]; then
  echo "Usage: $0 <input_csv_file>" >&2
  exit 1
fi

[ ! -r "$INPUT" ] && exit 1

awk -F',' '{ sub(/\r$/, "", $2); if ($2 ~ /\.ch$/) print $2 }' "$INPUT" \
| tac \
| while read -r domain; do

  output=$(
    "$TESTSSL" \
      --quiet \
      --color 0 \
      --warnings off \
      --rc4 \
      --protocols \
      --cipher-per-proto \
      --ip one \
      --socket-timeout 3 \
      --openssl-timeout 3 \
      "$domain" 2>&1
  )
  rc=$?

  if [ $rc -ne 0 ] || echo "$output" | grep -qi "Fatal error"; then
    echo "$domain : ERR"
    continue
  fi

  rc4=$(
    echo "$output" \
    | sed -nE 's/.*VULNERABLE.*: (.*)$/\1/p' \
    | tr '\n' ' '
  )

  tls_weak=$(
    echo "$output" \
    | grep -E '^\s*(SSLv[23]|TLS\s+1(\.0|\.1)?)\s+offered'
  )

  nonfs=$(
    echo "$output" \
    | grep -E '\b(TLS|SSL)_[^\s]+$' \
    | grep -vE 'ECDHE|DHE'
  )

  if [ -z "$rc4" ] && [ -z "$tls_weak" ] && [ -z "$nonfs" ]; then
    echo "$domain : OK"
    continue
  fi

  echo "$domain : BAD"

  [ -n "$rc4" ] && { echo "RC4:"; echo "$rc4"; }
  [ -n "$tls_weak" ] && { echo "Protocols:"; echo "$tls_weak"; }
  [ -n "$nonfs" ] && { echo "Non Forward Secrecy ciphers:"; echo "$nonfs"; }

  echo
done

