#!/bin/sh
# ==============================================================================
# Phylax Service Manager TDD Test Suite (`scripts/tests/phylax_service_tdd.sh`)
# One Job Principle (OJP): Rigorous verification of universal service lifecycle
# Tiers:
#   Tier 1: POSIX Shell Portability & Syntax Verification (zero bashisms)
#   Tier 2: Distro-Agnostic Init Template Generation (systemd, OpenRC, SysVinit)
#   Tier 3: Environment Discovery & Init System Detection
#   Tier 4: Action Router & Gating (install, reset, uninstall, status)
#   Tier 5: Configuration & Binary Resolution
# ==============================================================================
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
SERVICE_SCRIPT="${REPO_ROOT}/scripts/phylax-service.sh"

TESTS_PASSED=0
TESTS_FAILED=0

# Formatting
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_BOLD="\033[1m"
    C_GREEN="\033[0;32m"
    C_RED="\033[0;31m"
    C_BLUE="\033[0;34m"
    C_RESET="\033[0m"
else
    C_BOLD=""
    C_GREEN=""
    C_RED=""
    C_BLUE=""
    C_RESET=""
fi

assert_eq() {
    _actual="$1"
    _expected="$2"
    _msg="$3"
    if [ "${_actual}" = "${_expected}" ]; then
        printf "  %b✔ [TDD:PASS]%b %s\n" "${C_GREEN}" "${C_RESET}" "${_msg}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        printf "  %b✖ [TDD:FAIL]%b %s\n" "${C_RED}" "${C_RESET}" "${_msg}"
        printf "    Expected: '%s'\n" "${_expected}"
        printf "    Actual:   '%s'\n" "${_actual}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_contains() {
    _haystack="$1"
    _needle="$2"
    _msg="$3"
    case "${_haystack}" in
        *"${_needle}"*)
            printf "  %b✔ [TDD:PASS]%b %s\n" "${C_GREEN}" "${C_RESET}" "${_msg}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            ;;
        *)
            printf "  %b✖ [TDD:FAIL]%b %s\n" "${C_RED}" "${C_RESET}" "${_msg}"
            printf "    Substring '%s' not found in text\n" "${_needle}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            ;;
    esac
}

assert_not_contains() {
    _haystack="$1"
    _needle="$2"
    _msg="$3"
    case "${_haystack}" in
        *"${_needle}"*)
            printf "  %b✖ [TDD:FAIL]%b %s\n" "${C_RED}" "${C_RESET}" "${_msg}"
            printf "    Forbidden substring '%s' was found!\n" "${_needle}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            ;;
        *)
            printf "  %b✔ [TDD:PASS]%b %s\n" "${C_GREEN}" "${C_RESET}" "${_msg}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            ;;
    esac
}

printf "\n%b====================================================================%b\n" "${C_BOLD}${C_BLUE}" "${C_RESET}"
printf "%b🧪 Phylax Universal Service Manager TDD Test Suite%b\n" "${C_BOLD}${C_BLUE}" "${C_RESET}"
printf "%b   Target: %s%b\n" "${C_BLUE}" "${SERVICE_SCRIPT}" "${C_RESET}"
printf "%b====================================================================%b\n\n" "${C_BOLD}${C_BLUE}" "${C_RESET}"

# ------------------------------------------------------------------------------
# TIER 1: POSIX Shell Portability & Bashism Inspection
# ------------------------------------------------------------------------------
printf "%b[TIER 1] POSIX Shell Portability & Syntax%b\n" "${C_BOLD}" "${C_RESET}"

# 1.1 Script exists and is executable
assert_eq "$([ -x "${SERVICE_SCRIPT}" ] && echo "yes" || echo "no")" "yes" "Service manager script exists and is executable"

# 1.2 Syntax verification under standard sh
_syntax_check=$(sh -n "${SERVICE_SCRIPT}" 2>&1 || echo "syntax_error")
assert_eq "${_syntax_check}" "" "Script passes strict POSIX syntax check (sh -n)"

# 1.3 Check for non-portable bashisms
_content=$(cat "${SERVICE_SCRIPT}")
assert_not_contains "${_content}" "[[ " "Script contains no non-portable double brackets [[ ]]"
assert_not_contains "${_content}" "function " "Script contains no bash-specific 'function' keyword"
assert_not_contains "${_content}" "echo -e" "Script avoids non-portable 'echo -e' (uses printf)"
assert_not_contains "${_content}" "source " "Script avoids bash-specific 'source' keyword"

# ------------------------------------------------------------------------------
# TIER 2: Distro-Agnostic Service Template Generation
# ------------------------------------------------------------------------------
printf "\n%b[TIER 2] Distro-Agnostic Service Template Generation%b\n" "${C_BOLD}" "${C_RESET}"

# Source internal functions by mocking execution
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

# Mock values
MOCK_BIN="/usr/local/bin/phylax"
MOCK_CFG="/etc/phylax/phylax.toml"
MOCK_USER="phylax"

# 2.1 Test systemd unit generation
_systemd_out=$(
    PHYLAX_SOURCE_ONLY=1 . "${SERVICE_SCRIPT}"
    generate_systemd_unit "${MOCK_BIN}" "${MOCK_CFG}" "${MOCK_USER}"
)

assert_contains "${_systemd_out}" "ExecStart=${MOCK_BIN} serve --config ${MOCK_CFG}" "systemd unit sets exact ExecStart command"
assert_contains "${_systemd_out}" "User=${MOCK_USER}" "systemd unit sets dedicated security user"
assert_contains "${_systemd_out}" "ProtectSystem=strict" "systemd unit enables strict system protection"
assert_contains "${_systemd_out}" "CAP_NET_BIND_SERVICE" "systemd unit retains capability to bind low ports"

# 2.2 Test OpenRC script generation (Alpine Linux / Gentoo)
_openrc_out=$(
    PHYLAX_SOURCE_ONLY=1 . "${SERVICE_SCRIPT}"
    generate_openrc_script "${MOCK_BIN}" "${MOCK_CFG}" "${MOCK_USER}"
)

assert_contains "${_openrc_out}" "#!/sbin/openrc-run" "OpenRC script has correct openrc-run shebang"
assert_contains "${_openrc_out}" "command_background=\"yes\"" "OpenRC script enables background daemonization"
assert_contains "${_openrc_out}" "pidfile=\"/run/phylax.pid\"" "OpenRC script tracks runtime PID file"

# 2.3 Test SysVinit LSB script generation
_sysv_out=$(
    PHYLAX_SOURCE_ONLY=1 . "${SERVICE_SCRIPT}"
    generate_sysvinit_script "${MOCK_BIN}" "${MOCK_CFG}" "${MOCK_USER}"
)

assert_contains "${_sysv_out}" "### BEGIN INIT INFO" "SysVinit script includes standard LSB init header"
assert_contains "${_sysv_out}" "start-stop-daemon" "SysVinit script utilizes start-stop-daemon"

# 2.4 Test systemd user-unit generation (per-user / non-root)
_systemd_user_out=$(
    PHYLAX_SOURCE_ONLY=1 . "${SERVICE_SCRIPT}"
    generate_systemd_user_unit "${MOCK_BIN}" "${MOCK_CFG}"
)

assert_contains "${_systemd_user_out}" "ExecStart=${MOCK_BIN} serve --config ${MOCK_CFG}" "systemd user unit sets exact ExecStart command"
assert_contains "${_systemd_user_out}" "WantedBy=default.target" "systemd user unit targets default.target"
assert_not_contains "${_systemd_user_out}" "User=" "systemd user unit omits forbidden User= directive"
assert_not_contains "${_systemd_user_out}" "Group=" "systemd user unit omits forbidden Group= directive"

# ------------------------------------------------------------------------------
# TIER 3: Environment Discovery & Init System Detection
# ------------------------------------------------------------------------------
printf "\n%b[TIER 3] Environment Discovery & Init Detection%b\n" "${C_BOLD}" "${C_RESET}"

# 3.1 Override to systemd
_detected_systemd=$(PHYLAX_INIT_SYSTEM="systemd" sh "${SERVICE_SCRIPT}" --help 2>&1)
assert_contains "${_detected_systemd}" "Commands:" "CLI router processes commands with systemd override"

# 3.2 Environment override testing
_detected_override=$(
    PHYLAX_SOURCE_ONLY=1 . "${SERVICE_SCRIPT}"
    PHYLAX_INIT_SYSTEM="openrc" detect_init_system
)
assert_eq "${_detected_override}" "openrc" "detect_init_system respects PHYLAX_INIT_SYSTEM override"

_detected_sysv=$(
    PHYLAX_SOURCE_ONLY=1 . "${SERVICE_SCRIPT}"
    PHYLAX_INIT_SYSTEM="sysvinit" detect_init_system
)
assert_eq "${_detected_sysv}" "sysvinit" "detect_init_system respects sysvinit override"

# ------------------------------------------------------------------------------
# TIER 4: Command Router & Gating
# ------------------------------------------------------------------------------
printf "\n%b[TIER 4] Command Router & Gating%b\n" "${C_BOLD}" "${C_RESET}"

# 4.1 Help command outputs all required actions
_help_out=$(sh "${SERVICE_SCRIPT}" help)
assert_contains "${_help_out}" "install" "Help menu includes install action"
assert_contains "${_help_out}" "start" "Help menu includes start action"
assert_contains "${_help_out}" "stop" "Help menu includes stop action"
assert_contains "${_help_out}" "restart" "Help menu includes restart action"
assert_contains "${_help_out}" "status" "Help menu includes status action"
assert_contains "${_help_out}" "reset" "Help menu includes reset action"
assert_contains "${_help_out}" "uninstall" "Help menu includes uninstall action"
assert_contains "${_help_out}" "--user" "Help menu documents --user flag"
assert_contains "${_help_out}" "--system" "Help menu documents --system flag"
assert_contains "${_help_out}" "PHYLAX_USER_MODE" "Help menu documents PHYLAX_USER_MODE environment variable"

# 4.2 Invalid command returns non-zero exit code
_invalid_exit=0
sh "${SERVICE_SCRIPT}" "invalid_unknown_action" >/dev/null 2>&1 || _invalid_exit=$?
assert_eq "${_invalid_exit}" "1" "Unknown action returns non-zero exit code (1)"

# 4.3 Missing binary gates installation cleanly
_install_fail=0
_fail_out=$(PHYLAX_BIN="/nonexistent/path/phylax_fake" sh "${SERVICE_SCRIPT}" install 2>&1) || _install_fail=$?
assert_eq "${_install_fail}" "1" "Install fails gracefully when binary does not exist"
assert_contains "${_fail_out}" "Phylax binary not found" "Appropriate error emitted when binary missing"

# ------------------------------------------------------------------------------
# TIER 5: Execution Under Multiple Shells
# ------------------------------------------------------------------------------
printf "\n%b[TIER 5] Multi-Shell Portability Execution%b\n" "${C_BOLD}" "${C_RESET}"

if command -v dash >/dev/null 2>&1; then
    _dash_out=$(dash "${SERVICE_SCRIPT}" help 2>&1)
    assert_contains "${_dash_out}" "Usage:" "Runs cleanly under dash (Debian/Ubuntu /bin/sh)"
fi

if command -v bash >/dev/null 2>&1; then
    _bash_out=$(bash "${SERVICE_SCRIPT}" help 2>&1)
    assert_contains "${_bash_out}" "Usage:" "Runs cleanly under GNU bash"
fi

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
printf "\n%b====================================================================%b\n" "${C_BOLD}" "${C_RESET}"
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
if [ "${TESTS_FAILED}" -eq 0 ]; then
    printf "%b🎉 ALL %d TDD TESTS PASSED!%b (100%% Green)\n" "${C_BOLD}${C_GREEN}" "${TOTAL_TESTS}" "${C_RESET}"
    printf "%b====================================================================%b\n\n" "${C_BOLD}" "${C_RESET}"
    exit 0
else
    printf "%b❌ %d of %d TDD TESTS FAILED.%b\n" "${C_BOLD}${C_RED}" "${TESTS_FAILED}" "${TOTAL_TESTS}" "${C_RESET}"
    printf "%b====================================================================%b\n\n" "${C_BOLD}" "${C_RESET}"
    exit 1
fi
