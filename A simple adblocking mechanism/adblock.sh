#!/bin/bash

# file names (do NOT change the names)
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"
adblockRulesIPv6="adblockRulesIPv6"

# function to create adblock rules
function adBlock() {
    # check if running as root
    [ "$EUID" -ne 0 ] && echo "Please run as root." && exit 1

    # configure rules based on options
    if [ "$1" = "-domains"  ]; then
        # configure adblock rules based on domain names
        while IFS= read -r domain; do
            # resolve domain to IP addresses and add rules
            ips=$(host "$domain" | awk '/has address/ {print $4} ; /has IPv6 address/ {print $5}')
            for ip in $ips; do

                echo "Processing IP: $ip"  # current ip

                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    # check if IPv4 address

                    iptables -A INPUT -s "$ip" -j REJECT
                    iptables -A OUTPUT -d "$ip" -j REJECT

                elif [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
                    # check if IPv6 address

                    ip6tables -A INPUT -s "$ip" -j REJECT
                    ip6tables -A OUTPUT -d "$ip" -j REJECT

                else
                echo "invalid address format: $ip"
                fi 
            done
        done < "$domainNames"
        echo "adblock rules configured based on domain names in $domainNames."
        true

    elif [ "$1" = "-ips"  ]; then
        # configure rules based on IP addresses

        while IFS= read -r ip; do
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    # check if IPv4 address
                    iptables -A INPUT -s "$ip" -j REJECT
                    iptables -A OUTPUT -d "$ip" -j REJECT
            elif [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
                    # check if IPv6 address
                    ip6tables -A INPUT -s "$ip" -j REJECT
                    ip6tables -A OUTPUT -d "$ip" -j REJECT
            fi
        done < "$IPAddresses"
        printf "IP block rules configured based on '%s' file.\n" "$IPAddresses"
        true

    elif [ "$1" = "-save"  ]; then
        # save rules to the adblockRules files

        iptables-save > "$adblockRules"
        ip6tables-save > "$adblockRulesIPv6"
        printf "rules saved to $adblockRules and $adblockRulesIPv6 \n"

    elif [ "$1" = "-load"  ]; then
        # load rules from the adblockRules files

        iptables-restore < "$adblockRules"
        ip6tables-restore < "$adblockRulesIPv6"
        echo "rules loaded from $adblockRules and $adblockRulesIPv6 \n"
        true

    elif [ "$1" = "-reset"  ]; then
        # reset rules to default settings

        iptables -F
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -X
        
        ip6tables -F
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        ip6tables -X
        
        echo "rules reset to default settings."
        true

    elif [ "$1" = "-list"  ]; then
        iptables -L -n -v
        ip6tables -L -n -v
        true

    elif [ "$1" = "-help"  ]; then
        # display help

        printf "The adblock.sh script is responsible for generating a set of firewall rules that block access for
specific network domain names.\n\n"
        printf "usage: $0  [option]\n\n"
        printf "options:\n\n"
        printf "  -domains\t Configure adblock rules based on the domain names of '$domainNames'file.\n"
        printf "  -ips\t\t Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t Save rules to '$adblockRules' and "$adblockRulesIPv6" file.\n"
        printf "  -load\t\t Load rules from '$adblockRules' and "$adblockRulesIPv6" file.\n"
        printf "  -list\t\t List current rules.\n"
        printf "  -reset\t Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t Display help and exit.\n"
        exit 0

    else
        printf "wrong argument. exiting...\n"
        exit 1
    fi
}

# call function with the provided argument
adBlock "$1"
exit 0

