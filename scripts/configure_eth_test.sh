#!/bin/bash

if [[ $# < 1 || $# > 2 ]] ; then
	echo "Bad input."
	echo "Usage: $(basename $0) <interface> <phy_lb (0/1 - optional)>"
	exit 1
fi

main ()
{
    local intf=${1};
    local phy_lb=${2};
    local ipaddr;
    local fakeipaddr;
    local fakemacaddr;
    local loopbackmode;
    local testmode;
    local identifier;

    if [ -z `cat /sys/class/net/${intf}/dev_id 2> /dev/null` ] ; then
	    echo "Bad input: interface ${intf} doesn't exist"
	    exit 1
    fi

    identifier=$(ip -br link show | grep -n "$intf " | cut -d ":" -f 1);
    ipaddr="192.168.${identifier}.10/24";
    fakeipaddr="192.168.${identifier}.20";
    fakemacaddr="00:00:00:11:${identifier}:20";

    if ! [ $(id -u) = 0 ]; then
        echo "The script need to be run as root." >&2
        exit 1
    fi;

    if ! [ -e /sys/kernel/debug/habanalabs_cn/hbl_cn0 ] ; then
        echo "/sys/kernel/debug/habanalabs_cn/hbl_cn0 not found!! is the driver up ? ";
        return 1;
    fi;

    loopbackmode=$(tr -d '\0' < /sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_mac_loopback);
    testmode=$(tr -d '\0' < /sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_eth_loopback);

    if [ ! -z ${phy_lb} ] ; then
	if [[ ${phy_lb} != "0" && ${phy_lb} != "1" ]] ; then
            echo "Bad input: wrong second argument value ${phy_lb} (should be 0/1)"
	    exit 1
        fi

	if [ ${phy_lb} == "1" ] ; then
	    loopbackmode=1;
	fi
    fi

    if [ ${loopbackmode} == "0x0" ] ; then
        echo "you need to be in loopback mode. do the following:";
        echo "echo 0xffffff | sudo tee /sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_mac_loopback";
        return 1;
    fi;

    if [ ${testmode} == "0" ] ; then
        echo "you need to be in test mode. do the following:";
        echo "echo 1 | sudo tee  /sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_eth_loopback";
        return 1;
    fi

    if [ $# -eq 0 ] ; then
        echo "please specify an interface";
        return 1;
    fi

    echo "setting ip address ${ipaddr} to interface  ${intf}";
    sudo ip addr add ${ipaddr} dev ${intf}
    sudo ip link set ${intf} up
    echo "setting fake ip/mac ${fakeipaddr}/${fakemacaddr} address in arp table";
    arp -s ${fakeipaddr} ${fakemacaddr};

    echo -e "try\n\tping ${fakeipaddr}"
    return 0;
}

main "$@"
exit $?
