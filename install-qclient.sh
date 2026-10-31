#!/bin/bash

# Install script for Quilibrium client

# This is intended to be run via url:
# curl -sSL https://raw.githubusercontent.com/QuilibriumNetwork/ceremonyclient/refs/heads/develop/install-qclient.sh | sudo bash
#
# The release is verified before anything is installed: the binary must
# match its SHA3-256 digest file, a quorum of the release signatories (the
# keys qclient and the node check) must have signed that file with Ed448,
# and its signed label must name the file this script asked for, so a
# release signed for another version or platform is refused. File names
# are built here from a validated version; no name from the release server
# becomes a path. Needs curl and OpenSSL 1.1.1 or later.
#
# Options:
#   --dry-run          download and verify the release in a temporary
#                      directory and report what would be installed;
#                      installs nothing and needs no root
#   --allow-downgrade  install even when /usr/local/bin/qclient links a
#                      newer release

set -euo pipefail
umask 022

BASE_URL="https://releases.quilibrium.com"
INSTALL_ROOT="/var/quilibrium/bin/qclient"
SYMLINK="/usr/local/bin/qclient"

# Ed448 public keys (hex) of the release signatories: .dgst.sig.N is signed
# by key N. Keep in sync with crates/quil-config/src/signatories.rs.
SIGNATORIES=(
    b1214da7f355f5a9edb7bcc23d403bdf789f070cca10db2b4cadc22f2d837afb650944853e35d5f42ef3c4105b802b144b4077d5d3253e4100
    de4cfe7083104bfe32f0d4082fa0200464d8b10804a811653eedda376efcad64dd222f0f0ceb0b8ae58abe830d7a7e3f3b2d79d691318daa00
    540237a35e124882d6b64e7bb5718273fa338e553f772b77fe90570e45303762b34131bdcb6c0b9f2cf9e393d9c7e0f546eeab0bcbbd881680
    fbe4166e37f93f90d2ebf06305315ae11b37e501d09596f8bde11ba9d343034fbca80f252205aa2f582a512a72ad293df371baa582da072900
    4160572e493e1bf15c44e055b11bf75230c76c7d2c67b48066770ab03dfd5ed34c97b9a431ec18578c83a0df9250b8362c38068650e8b01400
    45170b626884b85d61ae109f2aa9b0e1ecc18b181508431ea6308f3869f2adae49da9799a0a594eaa4ef3ad492518fb1729decd44169d40d00
    92cd8ee5362f3ae274a75ab9471024dbc144bff441ed8af7d19750ac512ff51e40e7f7b01e4f96b6345dd58878565948c3eb52c53f250b5080
    001a4cbfce5d9aeb7e20665b0d236721b228a32f0baee62ffa77f45b82ecaf577e8a38b7ef91fcf7d2d2d2b504f085461398d30b24abb1d700
    65b835071731c6e785bb2d107c7d85d8a537d79c435c3f42bb2f87027f93f858d7b37c598cef267a5db46e345f7a6f81969b465686657d1e00
    b6df0ebab6ea20cc2eb718db5873c07bb50cf239a16bb6306bbe0f24280664f99f732c4049b8eda1226067e70ffb81958834d486942a122100
    3e087771c36098cb2d371711fd882d309b4caebbd06ded3077a975231344f027ad31c7069e76ba5070451d8eb5abf29bfeb34fcdf9ba906480
    57be2861faf0fffcbfd122c85c77010dce8f213030905781b85b6f345d912c7b5ace17797d9810899dfb8d13e7c8369595740725ab3dd5bd00
    61628beef8f6964466fd078d6a2b90a397ab0777a14b9728227fd19f36752f9451b1a8d780740a0b9a8ce3df5f89ca7b9ff17de9274a270980
    9ab76d775487c85c8e5aa0c5b3f961772967899a14644651031ae5f98ac197bee3f8880492c4fdba268716fc4b7c38ffcac370b663ac10b600
    c0d2d47d6309572a055abf593de26a8c980be04df9672ed40939f93b51806be53f6e58f330ff348592350783d24109fa7db8bf7e61c9a8b780
    6e2872f73c4868c4286bef7bfe2f5479a41c42f4e07505efa4883c7950c740252e0eea78eef10c584b19b1dcda01f7767d3135d07c33244100
    0ca6f5a9d7f86c1111be5edf31e26979918aa4fa3daae6de1120e05c2a09bdb8d2feeb084286a3347e06ced25530358cbc74c204d2a1753a00
)
# Valid signatures a release needs: ((n - 4) / 2) + ((n - 4) % 2), 7 of 17.
QUORUM=$(((${#SIGNATORIES[@]} - 4) / 2 + (${#SIGNATORIES[@]} - 4) % 2))
# DER prefix of an Ed448 SubjectPublicKeyInfo (RFC 8410); the key follows.
ED448_SPKI_PREFIX="3043300506032b6571033a00"

# Private download directory, removed on exit.
STAGE=""

die() {
    echo "Error: $*" >&2
    exit 1
}

cleanup() {
    if [ -n "$STAGE" ]; then
        rm -rf -- "${STAGE:?}"
    fi
}

fetch() {
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 "$@"
}

# Function to detect OS and architecture
detect_os_arch() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case $os in
        linux | darwin) ;;
        *) die "Unsupported OS: $os" ;;
    esac
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64 | arm64) arch="arm64" ;;
        *) die "Unsupported architecture: $arch" ;;
    esac
    echo "$os-$arch"
}

# A release version: two to five dot-separated decimal parts, such as
# 2.1.0.25.
is_release_version() {
    [[ "$1" =~ ^[0-9]{1,18}(\.[0-9]{1,18}){1,4}$ ]]
}

# Compare two release versions numerically; prints -1, 0 or 1.
compare_versions() {
    local IFS=.
    local -a a b
    read -r -a a <<<"$1"
    read -r -a b <<<"$2"
    local i x y n=${#a[@]}
    if [ ${#b[@]} -gt "$n" ]; then n=${#b[@]}; fi
    for ((i = 0; i < n; i++)); do
        x=$((10#${a[i]:-0}))
        y=$((10#${b[i]:-0}))
        if [ "$x" -lt "$y" ]; then
            echo -1
            return
        elif [ "$x" -gt "$y" ]; then
            echo 1
            return
        fi
    done
    echo 0
}

# The version of the first qclient-<version>-<os>-<arch> entry of the
# release list.
latest_version() {
    local os_arch=$1 list line version
    list=$(fetch "$BASE_URL/qclient-release") || die "Failed to fetch the release list"
    while IFS= read -r line; do
        line=${line%$'\r'}
        [[ "$line" == qclient-*-"$os_arch" ]] || continue
        version=${line#qclient-}
        version=${version%-"$os_arch"}
        is_release_version "$version" ||
            die "Invalid release version in the release list: $(printf '%q' "$version")"
        echo "$version"
        return
    done <<<"$list"
    die "No qclient release for $os_arch in the release list"
}

# The version of the qclient release that $SYMLINK links, if any.
linked_version() {
    local target name version
    target=$(readlink "$SYMLINK" 2>/dev/null) || return 0
    name=${target##*/}
    [[ "$name" == qclient-* ]] || return 0
    version=${name#qclient-}
    version=${version%%-*}
    if is_release_version "$version"; then
        echo "$version"
    fi
}

hex_to_file() {
    printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')" >"$2"
}

# Whether $3 is a valid Ed448 signature of file $2 by hex public key $1.
ed448_verify() {
    local key="$STAGE/.signatory.der"
    hex_to_file "$ED448_SPKI_PREFIX$1" "$key"
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$key" -rawin \
        -in "$2" -sigfile "$3" >/dev/null 2>&1
}

# The checksum a .dgst file states, as qclient reads it: the first 64
# characters of its second field, in lowercase hex.
dgst_checksum() {
    local hex=""
    read -r _ hex _ <"$1" || true
    hex=${hex:0:64}
    [[ "$hex" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
    printf '%s\n' "$hex" | tr 'A-F' 'a-f'
}

# Whether .dgst file $1 is the digest of release file $2: its signed label,
# as `openssl sha3-256` writes it, is "SHA3-256($2)=".
dgst_names() {
    local label=""
    read -r label _ <"$1" || true
    [ "$label" = "SHA3-256($2)=" ]
}

check_tools() {
    command -v curl >/dev/null || die "curl is required"
    command -v openssl >/dev/null || die "OpenSSL 1.1.1 or later is required"
    openssl dgst -sha3-256 -r /dev/null >/dev/null 2>&1 ||
        die "OpenSSL 1.1.1 or later is required (SHA3-256)"
    hex_to_file "$ED448_SPKI_PREFIX${SIGNATORIES[0]}" "$STAGE/.signatory.der"
    openssl pkey -pubin -inform DER -in "$STAGE/.signatory.der" -noout >/dev/null 2>&1 ||
        die "OpenSSL 1.1.1 or later is required (Ed448)"
}

# Download release file $1 and its digest and signature files into $STAGE
# under locally built names. Absent signature files are skipped; present
# ones must verify.
download_release() {
    local base=$1 i
    echo "Downloading $base..."
    fetch -o "$STAGE/$base" "$BASE_URL/$base" || die "Failed to download $BASE_URL/$base"
    fetch -o "$STAGE/$base.dgst" "$BASE_URL/$base.dgst" ||
        die "Failed to download $BASE_URL/$base.dgst"
    for ((i = 1; i <= ${#SIGNATORIES[@]}; i++)); do
        if ! fetch -o "$STAGE/$base.dgst.sig.$i" "$BASE_URL/$base.dgst.sig.$i" 2>/dev/null; then
            rm -f -- "${STAGE:?}/${base:?}.dgst.sig.${i:?}"
        fi
    done
}

# Verify the downloaded release $1 in $STAGE: the binary matches the
# digest file, every present signature is valid, they reach the quorum, and
# the signed label names $1.
verify_release() {
    local base=$1 claimed actual i valid=0
    claimed=$(dgst_checksum "$STAGE/$base.dgst") || {
        echo "Error: invalid digest file $base.dgst" >&2
        return 1
    }
    actual=$(openssl dgst -sha3-256 -r "$STAGE/$base" | cut -d' ' -f1 | tr 'A-F' 'a-f')
    if [ -z "$actual" ] || [ "$claimed" != "$actual" ]; then
        echo "Error: $base does not match its digest" >&2
        return 1
    fi
    for ((i = 1; i <= ${#SIGNATORIES[@]}; i++)); do
        [ -f "$STAGE/$base.dgst.sig.$i" ] || continue
        if ! ed448_verify "${SIGNATORIES[i - 1]}" "$STAGE/$base.dgst" \
            "$STAGE/$base.dgst.sig.$i"; then
            echo "Error: signature $i of $base.dgst failed verification" >&2
            return 1
        fi
        valid=$((valid + 1))
    done
    if [ "$valid" -lt "$QUORUM" ]; then
        echo "Error: signature quorum not met ($valid/$QUORUM)" >&2
        return 1
    fi
    if ! dgst_names "$STAGE/$base.dgst" "$base"; then
        echo "Error: $base.dgst is signed for another release file" >&2
        return 1
    fi
    echo "Signature quorum met ($valid valid)"
}

# Rename $1 to $2 (same file system). $2 must not be a directory; a symlink
# there is replaced, not followed.
place() {
    if [ -L "$2" ]; then
        rm -f -- "${2:?}"
    elif [ -d "$2" ]; then
        die "$2 is a directory"
    fi
    mv -f -- "$1" "$2"
}

# Move the verified release file $2 and its digest and signature files from
# $STAGE into directory $1: signatures and digest file first, then the
# binary.
install_release() {
    local dir=$1 base=$2 i
    if [ -L "$dir" ] || { [ -e "$dir" ] && [ ! -d "$dir" ]; }; then
        die "$dir is not a directory"
    fi
    mkdir -p -- "$dir"
    for ((i = 1; i <= ${#SIGNATORIES[@]}; i++)); do
        if [ -f "$STAGE/$base.dgst.sig.$i" ]; then
            place "$STAGE/$base.dgst.sig.$i" "$dir/$base.dgst.sig.$i"
        else
            # Keep only the signature set that verified.
            rm -f -- "${dir:?}/${base:?}.dgst.sig.${i:?}"
        fi
    done
    place "$STAGE/$base.dgst" "$dir/$base.dgst"
    chmod 0755 "$STAGE/$base"
    place "$STAGE/$base" "$dir/$base"
}

main() {
    local dry_run=false allow_downgrade=false os_arch version base dir linked
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                echo "[DRY RUN] enabled"
                ;;
            --allow-downgrade) allow_downgrade=true ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done

    # Check if the script is run with sudo privileges
    if [ "$dry_run" = false ] && [ "$EUID" -ne 0 ]; then
        die "This script must be run as root (use sudo) to install the Quilibrium client to /var/quilibrium/ directory"
    fi

    trap cleanup EXIT
    if [ "$dry_run" = true ]; then
        STAGE=$(mktemp -d)
    else
        mkdir -p -- "$INSTALL_ROOT"
        # Beside the install directory, so verified files move by rename.
        STAGE=$(mktemp -d "$INSTALL_ROOT/.install-XXXXXX")
    fi
    check_tools

    echo "Detecting OS and architecture..."
    os_arch=$(detect_os_arch)
    echo "Detected OS and architecture: $os_arch"

    version=$(latest_version "$os_arch")
    echo "Latest release version: $version"

    linked=$(linked_version)
    if [ -n "$linked" ] && [ "$(compare_versions "$version" "$linked")" -lt 0 ]; then
        if [ "$allow_downgrade" = false ]; then
            die "Refusing to downgrade from $linked to $version; pass --allow-downgrade to install an older release on purpose"
        fi
        echo "Downgrading from $linked to $version (--allow-downgrade)"
    fi

    base="qclient-$version-$os_arch"
    dir="$INSTALL_ROOT/$version"
    download_release "$base"
    verify_release "$base" || die "Release verification failed; nothing was installed"

    if [ "$dry_run" = true ]; then
        echo "[DRY RUN] Verified $base; would install it to $dir"
        echo "[DRY RUN] Symlink to be created: $SYMLINK -> $dir/$base"
        return
    fi

    install_release "$dir" "$base"
    if [ -d "$SYMLINK" ] && [ ! -L "$SYMLINK" ]; then
        die "$SYMLINK is a directory"
    fi
    ln -sfn -- "$dir/$base" "$SYMLINK"
    echo "Symlink created to the latest version: $SYMLINK -> $dir/$base"

    echo "Installation complete. You can now start the Quilibrium client with the following command:"
    echo "qclient --version"
}

main "$@"
