#!/bin/bash
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#
# Writes the binary seeds of the targets whose input is a standard encoding: LDAP's BER
# (fuzz_ber, fuzz_filter) and WebAuthn's CBOR (fuzz_webauthn), into lugh/fuzz/corpus/<target>/.
# The seeds are committed; this says how each was made. Lengths are computed, never counted.
#
#   lugh/fuzz/seeds.sh

set -eu
corpus=$(cd "$(dirname "$0")" && pwd)/corpus

hex() { printf '%s' "$1" | xxd -p | tr -d '\n'; }
bytes() { printf '%s' $(( ${#1} / 2 )); }

# BER: a tag, a short or long length, the content (all hex).
tlv() {
    local tag=$1 content=$2 n
    n=$(bytes "$content")
    if [ "$n" -lt 128 ]; then
        printf '%s%02x%s' "$tag" "$n" "$content"
    else
        printf '%s82%04x%s' "$tag" "$n" "$content"
    fi
}
octets() { tlv "$1" "$(hex "$2")"; }
integer() { tlv 02 "$(printf '%02x' "$1")"; }
enumerated() { tlv 0a "$(printf '%02x' "$1")"; }
message() { tlv 30 "$(integer "$1")$2$3"; }

# CBOR: a major type's head for a count or length, then the content.
chead() {
    local major=$1 n=$2
    if [ "$n" -lt 24 ]; then
        printf '%02x' $(( major * 32 + n ))
    elif [ "$n" -lt 256 ]; then
        printf '%02x%02x' $(( major * 32 + 24 )) "$n"
    else
        printf '%02x%04x' $(( major * 32 + 25 )) "$n"
    fi
}
cbytes() { printf '%s%s' "$(chead 2 "$(bytes "$1")")" "$1"; }
ctext() { printf '%s%s' "$(chead 3 ${#1})" "$(hex "$1")"; }

write() {
    mkdir -p "$corpus/$1"
    printf '%s' "$3" | xxd -r -p > "$corpus/$1/$2"
}

# ------------------------------------------------------------------- LDAP

uid_alice=$(tlv a3 "$(octets 04 uid)$(octets 04 alice)")
present=$(octets 87 objectClass)
substring=$(tlv a4 "$(octets 04 uid)$(tlv 30 "$(octets 80 al)$(octets 82 ce)")")
at_least=$(tlv a5 "$(octets 04 uidNumber)$(octets 04 1000)")
member=$(tlv a3 "$(octets 04 memberOf)$(octets 04 cn=staff,ou=groups,dc=example,dc=com)")

write filter equality "$uid_alice"
write filter and "$(tlv a0 "$uid_alice$present")"
write filter or-not "$(tlv a1 "$(tlv a2 "$uid_alice")$member")"
write filter substring "$substring"
write filter greater-or-equal "$at_least"

search() {
    tlv 63 "$(octets 04 dc=example,dc=com)$(enumerated 2)$(enumerated 0)$(integer 0)$(integer 0)$(tlv 01 00)$1$(tlv 30 "$(octets 04 cn)$(octets 04 uid)")"
}
paged=$(tlv a0 "$(tlv 30 "$(octets 04 1.2.840.113556.1.4.319)$(tlv 04 "$(tlv 30 "$(integer 100)$(tlv 04 "")")")")")
password_modify=$(tlv 30 "$(octets 80 uid=alice,ou=people,dc=example,dc=com)$(octets 81 old-password)$(octets 82 new-password)")

write ber bind-anonymous "$(message 1 "$(tlv 60 "$(integer 3)$(tlv 04 "")$(tlv 80 "")")" "")"
write ber bind-simple "$(message 1 "$(tlv 60 "$(integer 3)$(octets 04 uid=alice,ou=people,dc=example,dc=com)$(octets 80 secret)")" "")"
write ber search "$(message 2 "$(search "$(tlv a0 "$uid_alice$present")")" "")"
write ber search-paged "$(message 3 "$(search "$substring")" "$paged")"
write ber password-modify "$(message 4 "$(tlv 77 "$(octets 80 1.3.6.1.4.1.4203.1.11.1)$(tlv 81 "$password_modify")")" "")"
write ber unbind "$(message 5 "$(tlv 42 "")" "")"

# --------------------------------------------------------------- WebAuthn

# P-256's generator as the key: a point on the curve, so the COSE key is one public_key() accepts.
x=6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
y=4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
es256="a5010203262001$(printf 21)$(cbytes "$x")$(printf 22)$(cbytes "$y")"
# An RSA key of 2048 bits: n with its top bit set, e = 65537.
n="c1$(printf 'a5%.0s' $(seq 1 254))01"
rs256="a4010303390100$(printf 20)$(cbytes "$n")$(printf 21)$(cbytes 010001)"

rp_id_hash=$(printf '%s' localhost | openssl dgst -sha256 -hex | tr -d '\n' | rev | cut -c1-64 | rev)
aaguid=00000000000000000000000000000000
credential_id=000102030405060708090a0b0c0d0e0f
auth_data() { printf '%s45%s%s%04x%s%s' "$rp_id_hash" 00000001 "$aaguid" $(( ${#credential_id} / 2 )) "$credential_id" "$1"; }
attestation() { printf 'a3%s%s%sa0%s%s' "$(ctext fmt)" "$(ctext none)" "$(ctext attStmt)" "$(ctext authData)" "$(cbytes "$(auth_data "$1")")"; }

write webauthn cose-es256 "$es256"
write webauthn cose-rs256 "$rs256"
write webauthn attestation-none-es256 "$(attestation "$es256")"
write webauthn attestation-none-rs256 "$(attestation "$rs256")"
write webauthn authenticator-data-assertion "$(printf '%s05%s' "$rp_id_hash" 00000007)"
write webauthn authenticator-data-registration "$(auth_data "$es256")"
# An ES256 signature in DER: r with a leading zero (its top bit set), s without.
write webauthn signature-der "3045022100$(printf 'f1%.0s' $(seq 1 32))0220$(printf '1e%.0s' $(seq 1 32))"
write webauthn nested "$(printf '82a1%s%s83010203' "$(ctext k)" "$(cbytes 00ff)")"
