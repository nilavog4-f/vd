#!/usr/bin/env bash
# ##############################################################
# ##   VOID OSINT  —  WSL / Kali Linux Edition               ##
# ##   Main Launcher                                          ##
# ##   Author : @lfw.k4rma_                                  ##
# ##############################################################

cd "$(dirname "$(realpath "$0")")" 2>/dev/null || cd "$(dirname "$0")"

# ── Palette ───────────────────────────────────────────────────
BLK='\033[0;30m'   BBLK='\033[1;30m'
R='\033[0;31m'     LR='\033[1;31m'
G='\033[0;32m'     LG='\033[1;32m'
Y='\033[0;33m'     LY='\033[1;33m'
B='\033[0;34m'     LB='\033[1;34m'
M='\033[0;35m'     LM='\033[1;35m'
C='\033[0;36m'     LC='\033[1;36m'
W='\033[0;37m'     LW='\033[1;37m'
DIM='\033[2m'      RST='\033[0m'
BOLD='\033[1m'
# 256-color extras
ORANGE='\033[38;5;208m'
BLOOD='\033[38;5;160m'
CRIMSON='\033[38;5;196m'
ROSE='\033[38;5;197m'
GRAY='\033[38;5;240m'
LGRAY='\033[38;5;246m'

OK="${LG}✔${RST}"
ERR="${LR}✘${RST}"
INF="${LC}◈${RST}"
WARN="${LY}!${RST}"
ARR="${LR}▶${RST}"
DOT="${BLOOD}•${RST}"

# ── Helpers ───────────────────────────────────────────────────
COLS() { tput cols 2>/dev/null || echo 80; }

rule() {
  local char="${1:-─}" color="${2:-$BBLK}"
  local w; w=$(COLS)
  printf "${color}"; printf '%*s' "$w" '' | tr ' ' "$char"; printf "${RST}\n"
}

center() {
  local text="$1"
  local plain; plain=$(printf '%b' "$text" | sed 's/\x1B\[[0-9;:]*[mK]//g')
  local w pad; w=$(COLS); pad=$(( (w - ${#plain}) / 2 ))
  [ $pad -lt 0 ] && pad=0
  printf "%${pad}s" ""; printf '%b\n' "$text"
}

pad_line() {
  # pad_line LEFT_COLOR "text" RIGHT_COLOR "text"
  local w; w=$(COLS)
  local plain1; plain1=$(printf '%b' "$2" | sed 's/\x1B\[[0-9;:]*[mK]//g')
  local plain2; plain2=$(printf '%b' "$4" | sed 's/\x1B\[[0-9;:]*[mK]//g')
  local space=$(( w - ${#plain1} - ${#plain2} - 4 ))
  [ $space -lt 1 ] && space=1
  printf "  %b%b%${space}s%b%b  \n" "$1" "$2" "" "$3" "$4"
}

spin() {
  local label="$1"; shift
  local frames=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
  "$@" &>/tmp/_void_out & local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${BLOOD}${frames[$i]}${RST}  ${LGRAY}%s${RST}   " "$label"
    i=$(( (i + 1) % ${#frames[@]} )); sleep 0.07
  done
  wait "$pid"; local rc=$?; printf "\r\033[2K"; return $rc
}

# ── Banner ────────────────────────────────────────────────────
show_banner() {
  clear
  echo ""
  rule "═" "$BLOOD"
  echo ""

  # ASCII art — bright red
  printf '%b' "${CRIMSON}${BOLD}"
  center "██╗   ██╗ ██████╗ ██╗██████╗      ██████╗ ███████╗██╗███╗   ██╗████████╗"
  center "██║   ██║██╔═══██╗██║██╔══██╗    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝"
  center "██║   ██║██║   ██║██║██║  ██║    ██║   ██║███████╗██║██╔██╗ ██║   ██║   "
  center "╚██╗ ██╔╝██║   ██║██║██║  ██║    ██║   ██║╚════██║██║██║╚██╗██║   ██║   "
  center " ╚████╔╝ ╚██████╔╝██║██████╔╝    ╚██████╔╝███████║██║██║ ╚████║   ██║   "
  center "  ╚═══╝   ╚═════╝ ╚═╝╚═════╝      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝  "
  printf '%b' "${RST}"

  echo ""
  center "${BLOOD}─────────────────────────────────────────────────────────────────${RST}"
  center "${LGRAY}O P E N   S O U R C E   I N T E L L I G E N C E   T O O L K I T${RST}"
  center "${BLOOD}─────────────────────────────────────────────────────────────────${RST}"
  echo ""
  pad_line "${GRAY}" "WSL / Kali Linux Edition" "${BLOOD}" "@lfw.k4rma_"
  echo ""
  rule "═" "$BLOOD"
  echo ""
}

# ── Startup checks ────────────────────────────────────────────
startup_checks() {
  echo -e "  ${BOLD}${LW}ENVIRONMENT${RST}\n"

  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo -e "  ${OK}  ${LW}WSL${RST}    ${GRAY}Windows Subsystem for Linux${RST}"
  else
    echo -e "  ${INF}  ${LW}Native Linux${RST}"
  fi

  if grep -qi kali /etc/os-release 2>/dev/null; then
    echo -e "  ${OK}  ${LR}Kali Linux${RST}"
  else
    distro=$(. /etc/os-release 2>/dev/null && echo "$NAME" || echo "Unknown")
    echo -e "  ${WARN}  ${LW}${distro}${RST}  ${GRAY}(not Kali — should still work)${RST}"
  fi

  if ! command -v python3 &>/dev/null; then
    echo -e "\n  ${ERR}  ${LW}Python3 not found${RST}"
    echo -e "  ${GRAY}Fix:  sudo apt update && sudo apt install python3 python3-pip -y${RST}\n"
    exit 1
  fi
  PY=$(python3 --version 2>&1 | awk '{print $2}')
  echo -e "  ${OK}  ${LW}Python ${LG}${PY}${RST}"

  echo ""
  rule "─" "$BBLK"
  echo ""
  echo -e "  ${BOLD}${LW}DEPENDENCIES${RST}\n"

  if [ -f requirements.txt ]; then
    spin "Installing packages from requirements.txt …" \
      pip3 install -r requirements.txt -q --break-system-packages 2>/dev/null \
      || pip3 install -r requirements.txt -q 2>/dev/null
  else
    spin "Installing core packages …" \
      pip3 install requests rich pyfiglet ddgs phonenumbers beautifulsoup4 flask -q \
           --break-system-packages 2>/dev/null \
      || pip3 install requests rich pyfiglet ddgs phonenumbers beautifulsoup4 flask -q 2>/dev/null
  fi

  if [ $? -eq 0 ]; then
    echo -e "  ${OK}  ${LW}All packages ready${RST}"
  else
    echo -e "  ${WARN}  ${Y}Some packages may have failed — tool auto-installs will handle them${RST}"
  fi

  echo ""
  rule "═" "$BLOOD"
  echo ""
  echo -e "  ${GRAY}Press Enter to continue…${RST}"
  read -r
}

# ── Menu ──────────────────────────────────────────────────────
show_menu() {
  show_banner

  center "${BOLD}${CRIMSON}— SELECT A TOOL —${RST}"
  echo ""
  rule "─" "$BLOOD"
  echo ""

  local entries=(
    "1"  "Phone Deep"      "phone_deep.py"       "Carrier · breach · OSINT lookup"                 "$LR"      "<+1 phone number>"
    "2"  "Phone"           "phone2.py"            "Full OSINT + AI phone framework"                 "$LR"      "<+1 phone number>"
    "3"  "OSINT"           "osint2.py"            "Deep scan · social · breach · AI report"         "$CRIMSON" "<phone / username / email>"
    "4"  "IP Intel"        "ip_intel.py"          "Geo · ASN · VPN/Tor · ports · DDG"              "$ORANGE"  "<ip address or hostname>"
    "5"  "Geo"             "geo.py"               "Flask lure page + Cloudflare tunnel"             "$LY"      "<no input — starts server>"
    "6"  "Phishing"        "phishing.py"          "Credential capture server"                       "$LM"      "<no input — starts server>"
    "7"  "Passwords"       "password_guesser.py"  "Social-data wordlist builder"                    "$LC"      "<target name / dob / keywords>"
    "8"  "VOID-AI"         "chatbot.py"           "OpenRouter AI red-team assistant"                "$LG"      "<chat prompt>"
    "9"  "DDoS Sim"        "ddos_sim.py"          "Visual attack simulator — fake/demo"             "$BLOOD"   "<target ip address>"
    "10" "Leak Scanner"    "git_leak_scanner.py"  "Public repo secret exposure auditor"             "$LG"      "<github user / org / owner-repo>"
    "11" "Scare Prank"     "scare_prank.sh"       "Fake hack scare screen — harmless prank"         "$CRIMSON" "<no input — just run it>"
    "12" "Ping Monitor"    "ping_check.py"        "Live RTT · stability · DDoS detection · MC"      "$ORANGE"  "<ip or hostname + port>"
    "13" "Port Scanner"    "port_scan.py"         "TCP/UDP · banner grab · Minecraft · vuln flags"  "$BLOOD"   "<ip address or hostname>"
    "14" "DDOS × 3"       "ddos_triple.py"       "3 instances simultaneously · 384 threads · sudo"  "$BLOOD"   "<target ip + port + mode (prompted once)>"
  )

  local i=0
  while [ $i -lt ${#entries[@]} ]; do
    local num="${entries[$i]}"
    local label="${entries[$((i+1))]}"
    local file="${entries[$((i+2))]}"
    local desc="${entries[$((i+3))]}"
    local col="${entries[$((i+4))]}"
    local placeholder="${entries[$((i+5))]}"
    i=$(( i + 6 ))

    local dot
    if [ -f "$file" ]; then dot="${LG}●${RST}"; else dot="${R}○${RST}"; fi

    printf "  ${BLOOD}[${RST}${BOLD}${LY}%s${RST}${BLOOD}]${RST}  %b  ${BOLD}%b%-14s${RST}  ${LGRAY}%s${RST}\n" \
      "$num" "$dot" "$col" "$label" "$desc"
    printf "         ${BBLK}**${RST}  ${LGRAY}%s${RST}\n" "$placeholder"
    echo ""
  done

  rule "─" "$BLOOD"
  echo ""
  echo -e "  ${GRAY}[Q]  Quit${RST}"
  echo ""
  printf "  ${BLOOD}◈${RST}  ${LW}Choice: ${RST}"
}

# ── Shell-script launcher ─────────────────────────────────────
launch_sh() {
  local script="$1" label="$2" col="${3:-$LR}"
  if [ ! -f "$script" ]; then
    echo ""
    echo -e "  ${ERR}  ${LW}${script}${RST} ${GRAY}not found in $(pwd)${RST}"
    echo ""
    sleep 2; return
  fi

  clear; echo ""
  rule "═" "$BLOOD"
  echo ""
  center "${BLOOD}▶▶  ${col}${BOLD}${label}${RST}  ${BLOOD}◀◀${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""

  bash "$script"
  local rc=$?

  echo ""
  rule "═" "$BLOOD"
  if [ $rc -eq 0 ]; then
    center "${LG}✔  ${label} exited cleanly${RST}"
  else
    center "${LR}✘  ${label} exited with code ${rc}${RST}"
  fi
  rule "═" "$BLOOD"
  echo ""
  echo -e "  ${GRAY}Press Enter to return to the menu…${RST}"
  read -r
}

# ── Python launcher ───────────────────────────────────────────
launch_sudo() {
  local script="$1" label="$2" col="${3:-$LR}"
  if [ ! -f "$script" ]; then
    echo ""
    echo -e "  ${ERR}  ${LW}${script}${RST} ${GRAY}not found in $(pwd)${RST}"
    echo ""
    sleep 2; return
  fi

  clear; echo ""
  rule "═" "$BLOOD"
  echo ""
  center "${BLOOD}▶▶  ${col}${BOLD}${label}${RST}  ${BLOOD}◀◀${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""

  sudo python3 "$script"
  local rc=$?

  echo ""
  rule "═" "$BLOOD"
  if [ $rc -eq 0 ]; then
    center "${LG}✔  ${label} exited cleanly${RST}"
  else
    center "${LR}✘  ${label} exited with code ${rc}${RST}"
  fi
  rule "═" "$BLOOD"
  echo ""
  echo -e "  ${DIM}Press Enter to return to the menu...${RST}"
  read -r
}

launch() {
  local script="$1" label="$2" col="${3:-$LR}"
  if [ ! -f "$script" ]; then
    echo ""
    echo -e "  ${ERR}  ${LW}${script}${RST} ${GRAY}not found in $(pwd)${RST}"
    echo ""
    sleep 2; return
  fi

  clear; echo ""
  rule "═" "$BLOOD"
  echo ""
  center "${BLOOD}▶▶  ${col}${BOLD}${label}${RST}  ${BLOOD}◀◀${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""

  python3 "$script"
  local rc=$?

  echo ""
  rule "═" "$BLOOD"
  if [ $rc -eq 0 ]; then
    center "${LG}✔  ${label} exited cleanly${RST}"
  else
    center "${LR}✘  ${label} exited with code ${rc}${RST}"
  fi
  rule "═" "$BLOOD"
  echo ""
  echo -e "  ${GRAY}Press Enter to return to the menu…${RST}"
  read -r
}

# ── Main ──────────────────────────────────────────────────────
show_banner
startup_checks

while true; do
  show_menu
  read -r choice

  case "$choice" in
    1)  launch "phone_deep.py"       "Phone Deep"    "$LR"     ;;
    2)  launch "phone2.py"           "Phone"         "$LR"     ;;
    3)  launch "osint2.py"           "OSINT"         "$CRIMSON";;
    4)  launch "ip_intel.py"         "IP Intel"      "$ORANGE" ;;
    5)  launch "geo.py"              "Geo"           "$LY"     ;;
    6)  launch "phishing.py"         "Phishing"      "$LM"     ;;
    7)  launch "password_guesser.py" "Passwords"     "$LC"     ;;
    8)  launch "chatbot.py"          "VOID-AI"       "$LG"     ;;
    9)  launch "ddos_sim.py"         "DDoS Sim"      "$BLOOD"  ;;
    10) launch "git_leak_scanner.py" "Leak Scanner"  "$LG"     ;;
    11) launch_sh "scare_prank.sh"   "Scare Prank"   "$CRIMSON";;
    12) launch "ping_check.py"       "Ping Monitor"  "$ORANGE"  ;;
    13) launch "port_scan.py"        "Port Scanner"  "$BLOOD"   ;;
    14) launch_sudo "ddos_triple.py"  "DDOS x3"       "$BLOOD"   ;;
    q|Q|quit|exit)
      clear; echo ""
      rule "═" "$BLOOD"
      echo ""
      center "${BLOOD}██╗   ██╗ ██████╗ ██╗██████╗ ${RST}"
      center "${BLOOD}██║   ██║██╔═══██╗██║██╔══██╗${RST}"
      center "${BLOOD}██║   ██║██║   ██║██║██║  ██║${RST}"
      center "${BLOOD}╚██╗ ██╔╝██║   ██║██║██║  ██║${RST}"
      center "${BLOOD} ╚████╔╝ ╚██████╔╝██║██████╔╝${RST}"
      center "${BLOOD}  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ${RST}"
      echo ""
      center "${GRAY}Session ended  •  @lfw.k4rma_${RST}"
      echo ""
      rule "═" "$BLOOD"
      echo ""
      exit 0
      ;;
    *)
      echo ""
      echo -e "  ${WARN}  ${Y}Enter a number 1–14 or Q to quit${RST}"
      sleep 1
      ;;
  esac
done
