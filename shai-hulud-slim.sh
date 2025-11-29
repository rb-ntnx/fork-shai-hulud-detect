#!/bin/bash

# Shai-Hulud NPM Package Scanner (Slim Version)
# Only checks package.json and lockfiles for compromised packages
# Usage: ./shai-hulud-slim.sh <directory_to_scan>

set -eo pipefail

# Global temp directory for file-based storage
TEMP_DIR=""

# Global variables for risk tracking
high_risk=0
medium_risk=0

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function: create_temp_dir
create_temp_dir() {
    local temp_base="${TMPDIR:-${TMP:-${TEMP:-/tmp}}}"

    if command -v mktemp >/dev/null 2>&1; then
        TEMP_DIR=$(mktemp -d -t shai-hulud-slim-XXXXXX 2>/dev/null || true) || \
        TEMP_DIR=$(mktemp -d 2>/dev/null || true) || \
        TEMP_DIR="$temp_base/shai-hulud-slim-$$-$(date +%s)"
    else
        TEMP_DIR="$temp_base/shai-hulud-slim-$$-$(date +%s)"
    fi

    mkdir -p "$TEMP_DIR" || {
        echo "Error: Cannot create temporary directory"
        exit 1
    }

    touch "$TEMP_DIR/compromised_found.txt"
    touch "$TEMP_DIR/suspicious_found.txt"
    touch "$TEMP_DIR/lockfile_safe_versions.txt"
    touch "$TEMP_DIR/namespace_warnings.txt"
    touch "$TEMP_DIR/integrity_issues.txt"
    touch "$TEMP_DIR/suspicious_hooks.txt"
}

# Function: cleanup_temp_files
cleanup_temp_files() {
    local exit_code=$?
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    exit $exit_code
}

trap cleanup_temp_files EXIT INT TERM

# Function: print_status
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function: usage
usage() {
    echo "Usage: $0 <directory_to_scan>"
    echo
    echo "Slim version - only checks package.json and lockfiles for compromised packages"
    exit 1
}

# Function: load_compromised_packages
load_compromised_packages() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local packages_file="$script_dir/compromised-packages.txt"

    COMPROMISED_PACKAGES=()

    if [[ -f "$packages_file" ]]; then
        while IFS= read -r line; do
            line="${line%$'\r'}"
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue

            if [[ "$line" =~ ^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                COMPROMISED_PACKAGES+=("$line")
            fi
        done < "$packages_file"

        print_status "$BLUE" "📦 Loaded ${#COMPROMISED_PACKAGES[@]} compromised packages"
    else
        print_status "$RED" "Error: $packages_file not found"
        exit 1
    fi
}

# Compromised namespaces
COMPROMISED_NAMESPACES=(
    "@crowdstrike" "@art-ws" "@ngx" "@ctrl" "@nativescript-community"
    "@ahmedhfarag" "@operato" "@teselagen" "@things-factory" "@hestjs"
    "@nstudio" "@basic-ui-components-stc" "@nexe" "@thangved" "@tnf-dev"
    "@ui-ux-gang" "@yoobic"
)

# Function: semverParseInto
semverParseInto() {
    local RE='[^0-9]*\([0-9]*\)[.]\([0-9]*\)[.]\([0-9]*\)\([0-9A-Za-z-]*\)'
    printf -v "$2" '%s' "$(echo $1 | sed -e "s/$RE/\1/")"
    printf -v "$3" '%s' "$(echo $1 | sed -e "s/$RE/\2/")"
    printf -v "$4" '%s' "$(echo $1 | sed -e "s/$RE/\3/")"
    printf -v "$5" '%s' "$(echo $1 | sed -e "s/$RE/\4/")"
}

# Function: semver_match
semver_match() {
    local test_subject=$1
    local test_pattern=$2

    [[ "*" == "${test_pattern}" ]] && return 0

    local subject_major=0 subject_minor=0 subject_patch=0 subject_special=0
    semverParseInto ${test_subject} subject_major subject_minor subject_patch subject_special

    while IFS= read -r pattern; do
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        [[ "*" == "${pattern}" ]] && return 0

        local pattern_major=0 pattern_minor=0 pattern_patch=0 pattern_special=0

        case "${pattern}" in
            ^*)
                semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}" == "${pattern_major}" ]] || continue
                [[ "${subject_minor}" -ge "${pattern_minor}" ]] || continue
                if [[ "${subject_minor}" == "${pattern_minor}" ]]; then
                    [[ "${subject_patch}" -ge "${pattern_patch}" ]] || continue
                fi
                return 0
                ;;
            ~*)
                semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}" == "${pattern_major}" ]] || continue
                [[ "${subject_minor}" == "${pattern_minor}" ]] || continue
                [[ "${subject_patch}" -ge "${pattern_patch}" ]] || continue
                return 0
                ;;
            *[xX]*)
                local pattern_parts subject_parts
                IFS='.' read -ra pattern_parts <<< "${pattern}"
                IFS='.' read -ra subject_parts <<< "${test_subject}"

                for i in 0 1 2; do
                    if [[ ${i} -lt ${#pattern_parts[@]} && ${i} -lt ${#subject_parts[@]} ]]; then
                        local pattern_part="${pattern_parts[i]}"
                        local subject_part="${subject_parts[i]}"

                        [[ "${pattern_part}" == "x" || "${pattern_part}" == "X" ]] && continue

                        pattern_part=$(echo "${pattern_part}" | sed 's/[^0-9].*//')
                        subject_part=$(echo "${subject_part}" | sed 's/[^0-9].*//')

                        [[ "${subject_part}" != "${pattern_part}" ]] && continue 2
                    fi
                done
                return 0
                ;;
            *)
                semverParseInto ${pattern} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}" -eq "${pattern_major}" ]] || continue
                [[ "${subject_minor}" -eq "${pattern_minor}" ]] || continue
                [[ "${subject_patch}" -eq "${pattern_patch}" ]] || continue
                [[ "${subject_special}" == "${pattern_special}" ]] || continue
                return 0
                ;;
        esac
    done < <(echo "${test_pattern}" | sed 's/||/\n/g')

    return 1
}

# Function: transform_pnpm_yaml
transform_pnpm_yaml() {
    declare -a path
    packages_file=$1

    echo -e "{"
    echo -e "  \"packages\": {"

    depth=0
    while IFS= read -r line; do
        sep="${line%%[^ ]*}"
        currentdepth="${#sep}"

        line=${line##*( )}
        line=${line%%*( )}
        line=${line%%#*}
        line=${line%%*( )}

        [[ "${line:0:1}" == '#' || "${#line}" == 0 ]] && continue

        key=${line%%:*}
        key=${key%%*( )}
        val=${line#*:}
        val=${val##*( )}

        path[$currentdepth]=$key

        [ "${path[0]}" != "packages" ] && continue
        [ "${currentdepth}" != "2" ] && continue

        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        key="${key#"${key%%[!\']*}"}"
        key="${key%"${key##*[!\']}"}"

        name=${key%\@*}
        name=${name%*( )}
        version=${key##*@}
        version=${version##*( )}

        echo "    \"${name}\": {"
        echo "      \"version\": \"${version}\""
        echo "    },"
    done < "$packages_file"

    echo "  }"
    echo "}"
}

# Function: get_lockfile_version
get_lockfile_version() {
    local package_name="$1"
    local package_dir="$2"
    local scan_boundary="$3"
    local current_dir="$package_dir"

    while [[ "$current_dir" != "/" && "$current_dir" != "." && -n "$current_dir" ]]; do
        [[ ! "$current_dir/" =~ ^"$scan_boundary"/ && "$current_dir" != "$scan_boundary" ]] && break

        # Check package-lock.json (supports both v1 and v2/v3 formats)
        if [[ -f "$current_dir/package-lock.json" ]]; then
            local found_version
            # Try lockfile v2/v3 format first (node_modules/package)
            found_version=$(awk -v pkg="node_modules/$package_name" '
                $0 ~ "\"" pkg "\":" { in_block=1; brace_count=1 }
                in_block && /\{/ && !($0 ~ "\"" pkg "\":") { brace_count++ }
                in_block && /\}/ {
                    brace_count--
                    if (brace_count <= 0) { in_block=0 }
                }
                in_block && /\s*"version":/ {
                    split($0, parts, "\"")
                    for (i in parts) {
                        if (parts[i] ~ /^[0-9]/) {
                            print parts[i]
                            exit
                        }
                    }
                }
            ' "$current_dir/package-lock.json" 2>/dev/null || true)

            # If not found, try lockfile v1 format (direct package name under dependencies)
            if [[ -z "$found_version" ]]; then
                found_version=$(awk -v pkg="\"$package_name\"" '
                    $0 ~ pkg ":" { in_block=1; brace_count=1; next }
                    in_block && /\{/ { brace_count++ }
                    in_block && /\}/ {
                        brace_count--
                        if (brace_count <= 0) { in_block=0 }
                    }
                    in_block && /\s*"version":/ {
                        split($0, parts, "\"")
                        for (i in parts) {
                            if (parts[i] ~ /^[0-9]/) {
                                print parts[i]
                                exit
                            }
                        }
                    }
                ' "$current_dir/package-lock.json" 2>/dev/null || true)
            fi

            [[ -n "$found_version" ]] && echo "$found_version" && return
        fi

        # Check yarn.lock
        if [[ -f "$current_dir/yarn.lock" ]]; then
            local found_version
            found_version=$(grep "^\"\\?$package_name@" "$current_dir/yarn.lock" 2>/dev/null | head -1 | sed 's/.*@\([^"]*\).*/\1/' 2>/dev/null || true)
            [[ -n "$found_version" ]] && echo "$found_version" && return
        fi

        # Check pnpm-lock.yaml
        if [[ -f "$current_dir/pnpm-lock.yaml" ]]; then
            local temp_lockfile
            temp_lockfile=$(mktemp "${TMPDIR:-/tmp}/pnpm-parse.XXXXXXXX")

            transform_pnpm_yaml "$current_dir/pnpm-lock.yaml" > "$temp_lockfile" 2>/dev/null

            local found_version
            found_version=$(awk -v pkg="$package_name" '
                $0 ~ "\"" pkg "\"" { in_block=1; brace_count=1 }
                in_block && /\{/ && !($0 ~ "\"" pkg "\"") { brace_count++ }
                in_block && /\}/ {
                    brace_count--
                    if (brace_count <= 0) { in_block=0 }
                }
                in_block && /\s*"version":/ {
                    gsub(/.*"version":\s*"/, "")
                    gsub(/".*/, "")
                    print $0
                    exit
                }
            ' "$temp_lockfile" 2>/dev/null || true)

            rm -f "$temp_lockfile"
            [[ -n "$found_version" ]] && echo "$found_version" && return
        fi

        current_dir=$(dirname "$current_dir")
    done

    echo ""
}

# Function: check_packages
check_packages() {
    local scan_dir=$1

    # Count total package.json files first (excluding node_modules, .git, and build directories)
    local total_files=0
    while IFS= read -r -d '' file; do
        total_files=$((total_files + 1))
    done < <(find "$scan_dir" -name "package.json" -type f \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.cache/*" \
        -not -path "*/.next/*" \
        -not -path "*/.nuxt/*" \
        -not -path "*/temp/*" \
        -not -path "*/.temp/*" \
        -not -path "*/.vscode/*" \
        -not -path "*/.idea/*" \
        -not -path "*/out/*" \
        -not -path "*/.turbo/*" \
        -not -path "*/logs/*" \
        -not -path "*/.logs/*" \
        -print0 2>/dev/null || true)
    
    print_status "$BLUE" "🔍 Checking $total_files package.json file(s)..."
    
    local current_file=0
    while IFS= read -r -d '' package_file; do
        current_file=$((current_file + 1))
        echo -ne "\r   Processing package.json $current_file/$total_files..."
        [[ ! -r "${package_file}" ]] && continue
        
        while IFS=: read -r package_name package_version; do
            package_version=$(echo "${package_version}" | cut -d'"' -f2)
            package_name=$(echo "${package_name}" | cut -d'"' -f2)
            
            for malicious_info in "${COMPROMISED_PACKAGES[@]}"; do
                local malicious_name="${malicious_info%:*}"
                local malicious_version="${malicious_info#*:}"
                
                [[ "${package_name}" != "${malicious_name}" ]] && continue
                
                if [[ "${package_version}" == "${malicious_version}" ]]; then
                    echo "$package_file:$package_name@$package_version (exact version match)" >> "$TEMP_DIR/compromised_found.txt"
                elif semver_match "${malicious_version}" "${package_version}"; then
                    local package_dir=$(dirname "$package_file")
                    local actual_version=$(get_lockfile_version "$package_name" "$package_dir" "$scan_dir")
                    
                    if [[ -n "$actual_version" ]]; then
                        if [[ "$actual_version" == "$malicious_version" ]]; then
                            echo "$package_file:$package_name@$package_version → locked to $actual_version (COMPROMISED)" >> "$TEMP_DIR/compromised_found.txt"
                        else
                            echo "$package_file:$package_name@$package_version (locked to $actual_version - safe)" >> "$TEMP_DIR/lockfile_safe_versions.txt"
                        fi
                    else
                        echo "$package_file:$package_name@$package_version (no lockfile found to verify)" >> "$TEMP_DIR/suspicious_found.txt"
                    fi
                fi
            done
        done < <(awk '/"dependencies":|"devDependencies":/{flag=1;next}/}/{flag=0}flag' "${package_file}")
        
        # Check namespaces
        for namespace in "${COMPROMISED_NAMESPACES[@]}"; do
            if grep -q "\"$namespace/" "$package_file" 2>/dev/null; then
                echo "$package_file:Contains packages from compromised namespace: $namespace" >> "$TEMP_DIR/namespace_warnings.txt"
            fi
        done
    done < <(find "$scan_dir" -name "package.json" -type f \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.cache/*" \
        -not -path "*/.next/*" \
        -not -path "*/.nuxt/*" \
        -not -path "*/temp/*" \
        -not -path "*/.temp/*" \
        -not -path "*/.vscode/*" \
        -not -path "*/.idea/*" \
        -not -path "*/out/*" \
        -not -path "*/.turbo/*" \
        -not -path "*/logs/*" \
        -not -path "*/.logs/*" \
        -print0 2>/dev/null || true)
    
    # Clear progress line
    if [[ $total_files -gt 0 ]]; then
        echo -e "\r\033[K   ✓ Processed $total_files package.json file(s)"
    fi
}

# Function: check_lockfiles
check_lockfiles() {
    local scan_dir=$1
    
    # Count total lockfiles first (excluding node_modules, .git, and build directories)
    local total_files=0
    while IFS= read -r -d '' file; do
        total_files=$((total_files + 1))
    done < <(find "$scan_dir" \( -name "pnpm-lock.yaml" -o -name "yarn.lock" -o -name "package-lock.json" \) \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.cache/*" \
        -not -path "*/.next/*" \
        -not -path "*/.nuxt/*" \
        -not -path "*/temp/*" \
        -not -path "*/.temp/*" \
        -not -path "*/.vscode/*" \
        -not -path "*/.idea/*" \
        -not -path "*/out/*" \
        -not -path "*/.turbo/*" \
        -not -path "*/logs/*" \
        -not -path "*/.logs/*" \
        -print0 2>/dev/null || true)
    
    print_status "$BLUE" "🔍 Checking $total_files lockfile(s)..."
    
    local current_file=0
    while IFS= read -r -d '' lockfile; do
        current_file=$((current_file + 1))
        echo -ne "\r   Processing lockfile $current_file/$total_files ($(basename "$lockfile"))..."
        [[ ! -r "$lockfile" ]] && continue
        
        org_file="$lockfile"
        if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
            lockfile=$(mktemp "${TMPDIR:-/tmp}/lockfile.XXXXXXXX")
            transform_pnpm_yaml "$org_file" > "$lockfile"
        fi
        
        for package_info in "${COMPROMISED_PACKAGES[@]}"; do
            local package_name="${package_info%:*}"
            local malicious_version="${package_info#*:}"
            local found_version=""
            
            if grep -q "\"node_modules/$package_name\"" "$lockfile" 2>/dev/null; then
                found_version=$(awk -v pkg="node_modules/$package_name" '
                    $0 ~ "\"" pkg "\"" { in_block=1; brace_count=1 }
                    in_block && /\{/ && !($0 ~ "\"" pkg "\"") { brace_count++ }
                    in_block && /\}/ {
                        brace_count--
                        if (brace_count <= 0) { in_block=0 }
                    }
                    in_block && /\s*"version":/ {
                        gsub(/.*"version"[ \t]*:[ \t]*"/, "", $0)
                        gsub(/".*/, "", $0)
                        print $0
                        exit
                    }
                ' "$lockfile" 2>/dev/null || true) || true
            elif grep -q "\"$package_name\".*:.*\"[0-9]" "$lockfile" 2>/dev/null; then
                found_version=$(grep "\"$package_name\".*:.*\"[0-9]" "$lockfile" 2>/dev/null | head -1 | awk -F':' '{
                    gsub(/.*"/, "", $2)
                    gsub(/".*/, "", $2)
                    print $2
                }' 2>/dev/null || true) || true
            fi
            
            if [[ -n "$found_version" && "$found_version" == "$malicious_version" ]]; then
                echo "$org_file:$package_name@$malicious_version" >> "$TEMP_DIR/integrity_issues.txt"
            fi
        done
        
        [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]] && rm -f "$lockfile"
    done < <(find "$scan_dir" \( -name "pnpm-lock.yaml" -o -name "yarn.lock" -o -name "package-lock.json" \) \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.cache/*" \
        -not -path "*/.next/*" \
        -not -path "*/.nuxt/*" \
        -not -path "*/temp/*" \
        -not -path "*/.temp/*" \
        -not -path "*/.vscode/*" \
        -not -path "*/.idea/*" \
        -not -path "*/out/*" \
        -not -path "*/.turbo/*" \
        -not -path "*/logs/*" \
        -not -path "*/.logs/*" \
        -print0 2>/dev/null || true)
    
    # Clear progress line
    if [[ $total_files -gt 0 ]]; then
        echo -e "\r\033[K   ✓ Processed $total_files lockfile(s)"
    fi
}

# Function: check_install_hooks
check_install_hooks() {
    local scan_dir=$1
    
    print_status "$BLUE" "🔍 Checking for suspicious install hooks..."
    
    local hooks_checked=0
    while IFS= read -r -d '' package_file; do
        [[ ! -r "$package_file" ]] && continue
        
        # Check for preinstall hooks
        if grep -q "\"preinstall\"" "$package_file" 2>/dev/null; then
            local preinstall_cmd
            preinstall_cmd=$(grep "\"preinstall\"" "$package_file" 2>/dev/null | sed 's/.*"preinstall"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' 2>/dev/null || true)
            
            # Check for known malicious files (November 2025 Bun attack)
            if [[ -n "$preinstall_cmd" ]] && ([[ "$preinstall_cmd" == *"setup_bun.js"* ]] || [[ "$preinstall_cmd" == *"bun_environment.js"* ]]); then
                echo "$package_file:CRITICAL preinstall - Bun attack file detected: $preinstall_cmd" >> "$TEMP_DIR/suspicious_hooks.txt"
                hooks_checked=$((hooks_checked + 1))
            # Check for other suspicious patterns
            elif [[ -n "$preinstall_cmd" ]] && ([[ "$preinstall_cmd" == *"curl"* ]] || [[ "$preinstall_cmd" == *"wget"* ]] || [[ "$preinstall_cmd" == *"node -e"* ]] || [[ "$preinstall_cmd" == *"eval"* ]]); then
                echo "$package_file:Suspicious preinstall: $preinstall_cmd" >> "$TEMP_DIR/suspicious_hooks.txt"
                hooks_checked=$((hooks_checked + 1))
            fi
        fi
        
        # Check for postinstall hooks
        if grep -q "\"postinstall\"" "$package_file" 2>/dev/null; then
            local postinstall_cmd
            postinstall_cmd=$(grep "\"postinstall\"" "$package_file" 2>/dev/null | sed 's/.*"postinstall"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' 2>/dev/null || true)
            
            # Check for known malicious files (November 2025 Bun attack)
            if [[ -n "$postinstall_cmd" ]] && ([[ "$postinstall_cmd" == *"setup_bun.js"* ]] || [[ "$postinstall_cmd" == *"bun_environment.js"* ]]); then
                echo "$package_file:CRITICAL postinstall - Bun attack file detected: $postinstall_cmd" >> "$TEMP_DIR/suspicious_hooks.txt"
                hooks_checked=$((hooks_checked + 1))
            # Check for other suspicious patterns
            elif [[ -n "$postinstall_cmd" ]] && ([[ "$postinstall_cmd" == *"curl"* ]] || [[ "$postinstall_cmd" == *"wget"* ]] || [[ "$postinstall_cmd" == *"node -e"* ]] || [[ "$postinstall_cmd" == *"eval"* ]]); then
                echo "$package_file:Suspicious postinstall: $postinstall_cmd" >> "$TEMP_DIR/suspicious_hooks.txt"
                hooks_checked=$((hooks_checked + 1))
            fi
        fi
        
        # Check for install hook
        if grep -q "\"install\"" "$package_file" 2>/dev/null; then
            local install_cmd
            install_cmd=$(grep "\"install\"" "$package_file" 2>/dev/null | sed 's/.*"install"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' 2>/dev/null || true)
            
            # Check for known malicious files (November 2025 Bun attack)
            if [[ -n "$install_cmd" ]] && ([[ "$install_cmd" == *"setup_bun.js"* ]] || [[ "$install_cmd" == *"bun_environment.js"* ]]); then
                echo "$package_file:CRITICAL install - Bun attack file detected: $install_cmd" >> "$TEMP_DIR/suspicious_hooks.txt"
                hooks_checked=$((hooks_checked + 1))
            # Check for other suspicious patterns
            elif [[ -n "$install_cmd" ]] && ([[ "$install_cmd" == *"curl"* ]] || [[ "$install_cmd" == *"wget"* ]] || [[ "$install_cmd" == *"node -e"* ]] || [[ "$install_cmd" == *"eval"* ]]); then
                echo "$package_file:Suspicious install: $install_cmd" >> "$TEMP_DIR/suspicious_hooks.txt"
                hooks_checked=$((hooks_checked + 1))
            fi
        fi
    done < <(find "$scan_dir" -name "package.json" -type f \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.cache/*" \
        -not -path "*/.next/*" \
        -not -path "*/.nuxt/*" \
        -not -path "*/temp/*" \
        -not -path "*/.temp/*" \
        -not -path "*/.vscode/*" \
        -not -path "*/.idea/*" \
        -not -path "*/out/*" \
        -not -path "*/.turbo/*" \
        -not -path "*/logs/*" \
        -not -path "*/.logs/*" \
        -print0 2>/dev/null || true)
    
    if [[ $hooks_checked -gt 0 ]]; then
        echo "   ✓ Found $hooks_checked suspicious hook(s)"
    fi
}

# Function: generate_report
generate_report() {
    echo
    print_status "$BLUE" "=============================================="
    print_status "$BLUE" "   SHAI-HULUD PACKAGE SCAN REPORT (SLIM)"
    print_status "$BLUE" "=============================================="
    echo
    
    high_risk=0
    medium_risk=0
    
    # Compromised packages in package.json
    if [[ -s "$TEMP_DIR/compromised_found.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Compromised packages in package.json:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/compromised_found.txt"
        echo
    fi
    
    # Compromised packages in lockfiles
    if [[ -s "$TEMP_DIR/integrity_issues.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Compromised packages in lockfiles:"
        while IFS= read -r entry; do
            local file_path="${entry%%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/integrity_issues.txt"
        echo
    fi
    
    # Suspicious packages (version ranges)
    if [[ -s "$TEMP_DIR/suspicious_found.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious package versions (may match compromised):"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/suspicious_found.txt"
        echo -e "   ${YELLOW}NOTE: These packages use version ranges that could match compromised versions.${NC}"
        echo -e "   ${YELLOW}No lockfile was found to verify the actual installed version.${NC}"
        echo -e "   ${YELLOW}Run 'npm install' (or equivalent) to generate a lockfile and re-scan.${NC}"
        echo
    fi
    
    # Safe lockfile versions
    if [[ -s "$TEMP_DIR/lockfile_safe_versions.txt" ]]; then
        print_status "$BLUE" "ℹ️  INFO: Packages with safe lockfile versions:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
        done < "$TEMP_DIR/lockfile_safe_versions.txt"
        echo
    fi
    
    # Suspicious install hooks
    if [[ -s "$TEMP_DIR/suspicious_hooks.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Suspicious install hooks detected:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local hook_info="${entry#*:}"
            echo "   - Hook: $hook_info"
            echo "     Found in: $file_path"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/suspicious_hooks.txt"
        echo -e "   ${YELLOW}NOTE: Install hooks can execute arbitrary code during package installation.${NC}"
        echo
    fi
    
    # Namespace warnings
    if [[ -s "$TEMP_DIR/namespace_warnings.txt" ]]; then
        print_status "$YELLOW" "⚠️  WARNING: Compromised namespaces detected:"
        while IFS= read -r entry; do
            echo "   - $entry"
        done < "$TEMP_DIR/namespace_warnings.txt"
        echo
    fi
    
    # Summary
    print_status "$BLUE" "=============================================="
    local total_issues=$((high_risk + medium_risk))
    
    if [[ $total_issues -eq 0 ]]; then
        print_status "$GREEN" "✅ No compromised packages detected"
    else
        print_status "$RED" "🔍 SUMMARY:"
        print_status "$RED" "   High Risk: $high_risk"
        print_status "$YELLOW" "   Medium Risk: $medium_risk"
        print_status "$BLUE" "   Total Issues: $total_issues"
    fi
    print_status "$BLUE" "=============================================="
}

# Main function
main() {
    local scan_dir=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                usage
                ;;
            *)
                if [[ -z "$scan_dir" ]]; then
                    scan_dir="$1"
                else
                    echo "Too many arguments"
                    usage
                fi
                ;;
        esac
        shift
    done
    
    [[ -z "$scan_dir" ]] && usage
    [[ ! -d "$scan_dir" ]] && print_status "$RED" "Error: Directory '$scan_dir' does not exist." && exit 1
    
    scan_dir=$(cd "$scan_dir" && pwd) || {
        print_status "$RED" "Error: Unable to access directory '$scan_dir'"
        exit 1
    }
    
    load_compromised_packages
    create_temp_dir
    
    print_status "$GREEN" "Starting slim package scan..."
    print_status "$BLUE" "Scanning: $scan_dir"
    echo
    
    check_packages "$scan_dir"
    check_lockfiles "$scan_dir"
    check_install_hooks "$scan_dir"
    
    generate_report
    
    # Exit codes
    [[ $high_risk -gt 0 ]] && exit 1
    [[ $medium_risk -gt 0 ]] && exit 2
    exit 0
}

main "$@"

