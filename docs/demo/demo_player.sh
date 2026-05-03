#!/usr/bin/env bash
# Shadow runner used by VHS to render a deterministic demo.
# Emits ANSI-coloured output that mirrors a real `gisweep arcgis` scan,
# but against a local-only target so the GIF can ship in the public repo.
set -e

GREY='\033[2m'
BOLD='\033[1m'
CYAN='\033[36m'
YELLOW='\033[33m'
MAGENTA='\033[35m'
GREEN='\033[32m'
RED='\033[91m'
WHITE='\033[37m'
CRIT_BG='\033[1;37;41m'
HIGH_FG='\033[91m'
RESET='\033[0m'

sleep 0.2
echo -e "${GREY}🔎 Discovered ${CYAN}19${GREY} services and ${CYAN}71${GREY} layers across ${CYAN}4${GREY} folders; running checks…${RESET}"
sleep 0.4
echo -e "${GREY}2026-05-03 14:07:21${RESET} ${GREEN}[info]${RESET} ${BOLD}scan.started                  ${RESET} ${CYAN}check_count${RESET}=${MAGENTA}21${RESET} ${CYAN}target_count${RESET}=${MAGENTA}91${RESET}"
sleep 0.3
echo -e "${GREEN}⠋${RESET} ${BOLD}ARC-014 • …rest/services/ALTYAPI/LOCAL_YAGMUR/MapServer/0${RESET}        ${RED}━━━━━━━━━━━━━━━━━━━${RESET}╺━━━━━━━━━━━━━━━━━━━━━     ${GREEN}  912/1911${RESET}"
sleep 0.4
echo -e "${GREEN}⠼${RESET} ${BOLD}ARC-002 • …rest/services/BİRİMLER/HAVZA_YAPI_TESPIT/FeatureServer/0${RESET} ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}╺━━━━━━     ${GREEN} 1734/1911${RESET}"
sleep 0.4
echo -e "${GREEN}⠏${RESET} ${BOLD}WEB-002 • …rest/services/TEST/MUTLAK_KORUMA_ABONELER/MapServer/0${RESET}    ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}     ${GREEN} 1911/1911${RESET}"
sleep 0.3
echo -e "${GREY}2026-05-03 14:07:24${RESET} ${GREEN}[info]${RESET} ${BOLD}scan.finished                 ${RESET} ${CYAN}duration_s${RESET}=${MAGENTA}2.4${RESET} ${CYAN}findings${RESET}=${MAGENTA}9${RESET}"
sleep 0.3
echo
echo -e "                                ${BOLD}gisweep findings (showing critical)${RESET}"
echo "┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo -e "┃${BOLD} Severity ${RESET}┃${BOLD} ID       ${RESET}┃${BOLD} Target                                             ${RESET}┃${BOLD} Compliance                          ${RESET}┃"
echo "┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}ARC-002 ${RESET} │ http://localhost/arcgis/.../HAVZA_YAPI_TESPIT/0    │ KVKK m12, GDPR art32, GDPR art5-1-f │"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}ARC-002 ${RESET} │ http://localhost/arcgis/.../LOCAL_ICMESUYU/0       │ KVKK m12, GDPR art32, GDPR art5-1-f │"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}ARC-002 ${RESET} │ http://localhost/arcgis/.../LOCAL_ICMESUYU/1       │ KVKK m12, GDPR art32, GDPR art5-1-f │"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}ARC-003 ${RESET} │ http://localhost/arcgis/admin                      │ KVKK m12, GDPR art32                │"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}ARC-014 ${RESET} │ http://localhost/arcgis/.../HAVZA_ABONELER/0       │ KVKK m12 (PII), GDPR art32          │"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}COMP-001${RESET} │ http://localhost/arcgis/.../HAVZA_ABONELER/0       │ KVKK m12 aggregate (≥5 layers)      │"
sleep 0.18
echo -e "│ ${CRIT_BG}CRITICAL${RESET} │ ${BOLD}COMP-003${RESET} │ http://localhost/arcgis/admin                      │ GDPR art32 (admin + open data)      │"
sleep 0.18
echo -e "│ ${HIGH_FG}HIGH    ${RESET} │ ${BOLD}ARC-013 ${RESET} │ http://localhost/arcgis/.../LOCAL_ADRES/0          │ KVKK m12, GDPR art32                │"
sleep 0.18
echo -e "│ ${HIGH_FG}HIGH    ${RESET} │ ${BOLD}ARC-018 ${RESET} │ http://localhost/arcgis/.../HENDEK_SONDAJ/0        │ KVKK m12, GDPR art32                │"
echo "└──────────┴──────────┴────────────────────────────────────────────────────┴─────────────────────────────────────┘"
sleep 0.3
echo -e "${GREY}gisweep — ${YELLOW}scan_id${RESET}${GREY}=${MAGENTA}demo0001${GREY} ${YELLOW}duration${RESET}${GREY}=${CYAN}2.40s${GREY} ${YELLOW}critical${RESET}${GREY}=${CYAN}7${GREY} ${YELLOW}high${RESET}${GREY}=${CYAN}2${GREY} ${YELLOW}medium${RESET}${GREY}=${CYAN}0${GREY} ${YELLOW}info${RESET}${GREY}=${CYAN}0${RESET}"
sleep 0.3
echo -e "${GREY}wrote ${RESET}report.html"
