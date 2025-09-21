#EPS
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

clear_screen() {
    clear
    echo -e "${RED}"
    cat << "EOF"
           .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HUMAN    `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '
              TerScan Scanner Better For Ip | EPS
    ${RED}Advanced Network Reconnaissance Toolkit${NC}
EOF
    echo -e "${NC}"
}

show_help() {
    echo -e "${GREEN}Available Commands:${NC}"
    echo -e "${CYAN}  Basic Scanning:${NC}"
    echo -e "  scan <IP>           : Scan specified IP address"
    echo -e "  scan range <IP/CIDR> : Scan IP range (e.g., 192.168.1.0/24)"
    echo -e "  quick <IP>          : Quick scan (top 100 ports)"
    echo -e "  full <IP>           : Full comprehensive scan"
    
    echo -e "${CYAN}  Advanced Analysis:${NC}"
    echo -e "  os <IP>             : Detect OS of specified IP"
    echo -e "  service <IP>        : Detect services on open ports"
    echo -e "  vuln <IP>           : Vulnerability assessment"
    echo -e "  malware <IP>        : Check for malware indicators"
    echo -e "  traffic <IP>        : Analyze network traffic (requires sudo)"
    echo -e "  dns <domain>        : DNS enumeration and analysis"
    
    echo -e "${CYAN}  Geolocation & Info:${NC}"
    echo -e "  geo <IP>            : Detailed geolocation info"
    echo -e "  whois <IP/Domain>   : WHOIS information lookup"
    echo -e "  reverse <IP>        : Reverse DNS lookup"
    echo -e "  asn <IP>            : ASN information lookup"
    
    echo -e "${CYAN}  Network Operations:${NC}"
    echo -e "  ping <IP>           : Ping host with detailed statistics"
    echo -e "  traceroute <IP>     : Trace route to host"
    echo -e "  sshscan <IP>        : SSH-specific security scan"
    echo -e "  webscan <IP>        : Web server enumeration"
    
    echo -e "${CYAN}  Data Management:${NC}"
    echo -e "  export <format>     : Export last results (txt/json/xml/html)"
    echo -e "  report <IP>         : Generate comprehensive HTML report"
    echo -e "  history             : Show scan history"
    echo -e "  saved               : List saved scans"
    echo -e "  compare <IP1> <IP2> : Compare two scan results"
    
    echo -e "${CYAN}  System Operations:${NC}"
    echo -e "  clear               : Clear screen"
    echo -e "  update              : Update tool and databases"
    echo -e "  config              : Show configuration"
    echo -e "  help                : Show this help message"
    echo -e "  exit                : Exit program"
    echo -e ""
    echo -e "${GREEN}Examples:${NC}"
    echo -e "  scan 192.168.1.1"
    echo -e "  scan range 192.168.1.0/24"
    echo -e "  vuln 8.8.8.8"
    echo -e "  export html"
    echo -e "  report 192.168.1.1"
    echo -e ""
}

check_dependencies() {
    local tools=("nmap" "curl" "jq" "whois" "dig" "traceroute" "ping")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}Missing required tools:${NC}"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                "nmap") echo -e "  - nmap (Network Mapper)";;
                "curl") echo -e "  - curl (URL transfer tool)";;
                "jq") echo -e "  - jq (JSON processor)";;
                "whois") echo -e "  - whois (Domain information tool)";;
                "dig") echo -e "  - dig (DNS lookup utility)";;
                "traceroute") echo -e "  - traceroute (Network route tracing)";;
                "ping") echo -e "  - ping (Network connectivity testing)";;
            esac
        done
        echo -e "${YELLOW}Please install missing tools and try again.${NC}"
        exit 1
    fi
}

initialize_tool() {

    mkdir -p ~/scans/{reports,exports,history}
    
    touch ~/scans/history/scan_history.log
    
    check_for_updates
}

check_for_updates() {
    echo -e "${YELLOW}[*] Checking for updates...${NC}"
    echo -e "${GREEN}[+] Tool is up to date${NC}"
}

scan_ip() {
    local ip=$1
    local scan_type=${2:-"normal"}
    
    echo -e "${GREEN}Scanning IP: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    local temp_file=$(mktemp)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="$HOME/scans/reports/scan_${ip}_${timestamp}"
    
    case $scan_type in
        "quick")
            echo -e "${YELLOW}[+] Running quick scan (top 100 ports)...${NC}"
            nmap -T4 -F "$ip" -oN "$temp_file"
            ;;
        "full")
            echo -e "${YELLOW}[+] Running comprehensive scan...${NC}"
            nmap -sS -sV -sC -O -A -T4 -p- --min-rate 1000 "$ip" -oN "$temp_file"
            ;;
        *)
            echo -e "${YELLOW}[+] Running standard scan...${NC}"
            nmap -sS -sV -sC -O -T4 --min-rate 1000 "$ip" -oN "$temp_file"
            ;;
    esac
    
    echo -e "${YELLOW}[+] Open ports:${NC}"
    grep -E '^[0-9]+/.*open' "$temp_file" | sed 's/^/  /'
    
    echo -e "${YELLOW}[+] WHOIS information:${NC}"
    whois "$ip" | grep -E '(Country|OrgName|NetName|City|Organization)' | head -5 | sed 's/^/  /'
    
    echo -e "${YELLOW}[+] Geolocation:${NC}"
    local geo_info=$(curl -s "http://ip-api.com/json/$ip")
    echo "  Country: $(echo "$geo_info" | jq -r '.country // "Unknown"')"
    echo "  Region: $(echo "$geo_info" | jq -r '.regionName // "Unknown"')"
    echo "  City: $(echo "$geo_info" | jq -r '.city // "Unknown"')"
    echo "  ISP: $(echo "$geo_info" | jq -r '.isp // "Unknown"')"
    echo "  Coordinates: $(echo "$geo_info" | jq -r '.lat // "Unknown"'), $(echo "$geo_info" | jq -r '.lon // "Unknown"')"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): scan $ip ($scan_type)" >> ~/scans/history/scan_history.log
    cp "$temp_file" "${output_file}.txt"
    LAST_SCAN_RESULTS=$(cat "$temp_file")
    LAST_SCAN_IP="$ip"
    LAST_SCAN_FILE="${output_file}.txt"
    
    echo -e "${GREEN}[+] Scan saved to: ${output_file}.txt${NC}"
    
    rm "$temp_file"
}

scan_range() {
    local range=$1
    echo -e "${GREEN}Scanning range: $range${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    nmap -sn "$range" | grep -E 'Nmap scan|MAC Address' | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): scan range $range" >> ~/scans/history/scan_history.log
}

detect_os() {
    local ip=$1
    echo -e "${GREEN}Detecting OS for: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    nmap -O "$ip" | grep -E '(Running|OS details|Aggressive OS guesses)' | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): os $ip" >> ~/scans/history/scan_history.log
}

detect_services() {
    local ip=$1
    echo -e "${GREEN}Detecting services for: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    nmap -sV --version-intensity 5 "$ip" | grep -E '(PORT|open|Service)' | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): service $ip" >> ~/scans/history/scan_history.log
}

vuln_check() {
    local ip=$1
    echo -e "${GREEN}Vulnerability assessment for: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    nmap --script vuln "$ip" | grep -E '(VULNERABLE|CVE-)' | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): vuln $ip" >> ~/scans/history/scan_history.log
}

malware_check() {
    local ip=$1
    echo -e "${GREEN}Malware indicator check for: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${YELLOW}[*] Checking AbuseIPDB...${NC}"
    echo -e "${YELLOW}[*] Note: Full functionality requires API key${NC}"
    
    nmap --script malware "$ip" | grep -E '(malicious|suspicious)' | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): malware $ip" >> ~/scans/history/scan_history.log
}

dns_enum() {
    local domain=$1
    echo -e "${GREEN}DNS enumeration for: $domain${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${YELLOW}[+] A records:${NC}"
    dig A "$domain" +short | sed 's/^/  /'
    
    echo -e "${YELLOW}[+] MX records:${NC}"
    dig MX "$domain" +short | sed 's/^/  /'
    
    echo -e "${YELLOW}[+] NS records:${NC}"
    dig NS "$domain" +short | sed 's/^/  /'
    
    echo -e "${YELLOW}[+] TXT records:${NC}"
    dig TXT "$domain" +short | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): dns $domain" >> ~/scans/history/scan_history.log
}

detailed_geo() {
    local ip=$1
    echo -e "${GREEN}Detailed geolocation for: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    local geo_info=$(curl -s "http://ip-api.com/json/$ip")
    echo -e "${YELLOW}Location information:${NC}"
    echo "  IP: $(echo "$geo_info" | jq -r '.query // "Unknown"')"
    echo "  Country: $(echo "$geo_info" | jq -r '.country // "Unknown"')"
    echo "  Country Code: $(echo "$geo_info" | jq -r '.countryCode // "Unknown"')"
    echo "  Region: $(echo "$geo_info" | jq -r '.regionName // "Unknown"')"
    echo "  City: $(echo "$geo_info" | jq -r '.city // "Unknown"')"
    echo "  ZIP: $(echo "$geo_info" | jq -r '.zip // "Unknown"')"
    echo "  Coordinates: $(echo "$geo_info" | jq -r '.lat // "Unknown"'), $(echo "$geo_info" | jq -r '.lon // "Unknown"')"
    echo "  Timezone: $(echo "$geo_info" | jq -r '.timezone // "Unknown"')"
    echo "  ISP: $(echo "$geo_info" | jq -r '.isp // "Unknown"')"
    echo "  Organization: $(echo "$geo_info" | jq -r '.org // "Unknown"')"
    echo "  AS: $(echo "$geo_info" | jq -r '.as // "Unknown"')"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): geo $ip" >> ~/scans/history/scan_history.log
}

whois_lookup() {
    local target=$1
    echo -e "${GREEN}WHOIS information for: $target${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    whois "$target" | head -20 | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): whois $target" >> ~/scans/history/scan_history.log
}

ping_host() {
    local ip=$1
    echo -e "${GREEN}Pinging: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    ping -c 5 "$ip" | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ping $ip" >> ~/scans/history/scan_history.log
}

trace_route() {
    local ip=$1
    echo -e "${GREEN}Traceroute to: $ip${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    traceroute "$ip" | sed 's/^/  /'
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): traceroute $ip" >> ~/scans/history/scan_history.log
}

export_results() {
    local format=$1
    
    if [ -z "$LAST_SCAN_RESULTS" ]; then
        echo -e "${RED}No scan results to export. Perform a scan first.${NC}"
        return
    fi
    
    local filename="$HOME/scans/exports/scan_${LAST_SCAN_IP}_$(date +%Y%m%d_%H%M%S).${format}"
    
    case $format in
        txt)
            echo "$LAST_SCAN_RESULTS" > "$filename"
            ;;
        json)
            nmap -oJ "$filename" "$LAST_SCAN_IP"
            ;;
        xml)
            nmap -oX "$filename" "$LAST_SCAN_IP"
            ;;
        html)
            nmap -oX - "$LAST_SCAN_IP" | xsltproc -o "$filename" /usr/share/nmap/nmap.xsl -
            ;;
        *)
            echo -e "${RED}Unsupported format. Use txt, json, xml, or html.${NC}"
            return
            ;;
    esac
    
    echo -e "${GREEN}Results exported to: $filename${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): export $format" >> ~/scans/history/scan_history.log
}

generate_report() {
    local ip=$1
    echo -e "${GREEN}Generating HTML report for: $ip${NC}"
    
    local report_file="$HOME/scans/reports/report_${ip}_$(date +%Y%m%d_%H%M%S).html"
    
    nmap -sS -sV -sC -O -A -T4 "$ip" -oX - | xsltproc -o "$report_file" /usr/share/nmap/nmap.xsl -
    
    echo -e "${GREEN}Report generated: $report_file${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): report $ip" >> ~/scans/history/scan_history.log
}

show_history() {
    echo -e "${GREEN}Scan history:${NC}"
    echo -e "${CYAN}========================================${NC}"
    if [ -f ~/scans/history/scan_history.log ]; then
        cat ~/scans/history/scan_history.log | tail -15
    else
        echo -e "${YELLOW}No history found.${NC}"
    fi
}

list_saved_scans() {
    echo -e "${GREEN}Saved scans:${NC}"
    echo -e "${CYAN}========================================${NC}"
    if [ -d ~/scans/reports ]; then
        ls -la ~/scans/reports/ | grep -E 'scan_.*\.txt$' | awk '{print $9}' | sed 's/^/  /'
    else
        echo -e "${YELLOW}No saved scans found.${NC}"
    fi
}

compare_scans() {
    local ip1=$1
    local ip2=$2
    
    echo -e "${GREEN}Comparing $ip1 and $ip2${NC}"
    echo -e "${CYAN}========================================${NC}"

    local scan1=$(find ~/scans/reports/ -name "scan_${ip1}_*.txt" | sort | tail -1)
    local scan2=$(find ~/scans/reports/ -name "scan_${ip2}_*.txt" | sort | tail -1)
    
    if [ -z "$scan1" ] || [ -z "$scan2" ]; then
        echo -e "${RED}No scan results found for one or both IPs.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Comparison:${NC}"
    echo "  $ip1: $(grep -c 'open' "$scan1") open ports"
    echo "  $ip2: $(grep -c 'open' "$scan2") open ports"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S'): compare $ip1 $ip2" >> ~/scans/history/scan_history.log
}

show_config() {
    echo -e "${GREEN}Tool Configuration:${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "  Scan directory: ~/scans/"
    echo -e "  Reports: ~/scans/reports/"
    echo -e "  Exports: ~/scans/exports/"
    echo -e "  History: ~/scans/history/scan_history.log"
    echo -e ""
    echo -e "${YELLOW}Dependencies:${NC}"
    which nmap && echo "  nmap: $(nmap --version | head -1)"
    which curl && echo "  curl: $(curl --version | head -1)"
    which jq && echo "  jq: $(jq --version)"
    which whois && echo "  whois: installed"
}

main() {
    clear_screen
    check_dependencies
    initialize_tool
    
    echo -e "${MAGENTA}Advanced IP Scanner with extensive capabilities${NC}"
    echo -e "${MAGENTA}Type 'help' for available commands${NC}"
    echo -e ""
    
    while true; do
        echo -e "${BLUE}netspy>${NC} \c"
        read -r command
        
        case $command in
            "scan "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                    if [[ $ip == *"/"* ]]; then
                        scan_range "$ip"
                    else
                        scan_ip "$ip"
                    fi
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "quick "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    scan_ip "$ip" "quick"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "full "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    scan_ip "$ip" "full"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "os "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    detect_os "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "service "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    detect_services "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "vuln "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    vuln_check "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "malware "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    malware_check "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "dns "*)
                domain=$(echo "$command" | cut -d' ' -f2)
                dns_enum "$domain"
                ;;
            "geo "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    detailed_geo "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "whois "*)
                target=$(echo "$command" | cut -d' ' -f2)
                whois_lookup "$target"
                ;;
            "ping "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    ping_host "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "traceroute "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    trace_route "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "export "*)
                format=$(echo "$command" | cut -d' ' -f2)
                export_results "$format"
                ;;
            "report "*)
                ip=$(echo "$command" | cut -d' ' -f2)
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    generate_report "$ip"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "history")
                show_history
                ;;
            "saved")
                list_saved_scans
                ;;
            "compare "*)
                ip1=$(echo "$command" | cut -d' ' -f2)
                ip2=$(echo "$command" | cut -d' ' -f3)
                if [[ $ip1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ $ip2 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    compare_scans "$ip1" "$ip2"
                else
                    echo -e "${RED}Invalid IP address format.${NC}"
                fi
                ;;
            "config")
                show_config
                ;;
            "update")
                check_for_updates
                ;;
            "help")
                show_help
                ;;
            "clear")
                clear_screen
                ;;
            "exit")
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            "")
                ;;
            *)
                echo -e "${RED}Unknown command: $command${NC}"
                echo -e "Type 'help' for available commands"
                ;;
        esac
    done
}

main "$@"
