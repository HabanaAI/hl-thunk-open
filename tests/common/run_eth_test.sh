#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2021 HabanaLabs, Ltd.
# All Rights Reserved.
#

trap cleanup EXIT

cleanup() {
    exit_code=$?
    echo -e "[==========] 1 test(s) run."
    if [[ $exit_code == 0 ]]; then
        echo -e "[  PASSED  ] 1 test(s)."
    else
        echo -e "[  FAILED  ] 1 test(s)."
    fi
    echo -e

    exec &> "$(tty)"
    kill_pending_proc
    delete_namespaces
    restore_iface_link_state $PORT1 $IF1_PREV_STATE
    restore_iface_link_state $PORT2 $IF2_PREV_STATE
    restore_mtu $PORT1 $IF1_PREV_MTU
    restore_mtu $PORT2 $IF2_PREV_MTU
    exit $exit_code
}

IP=ip

# network namespace names
NS1=net-ns1
NS2=net-ns2

TOOL=IPERF
IP1=10.3.10.11
IP2=10.3.10.22
PORT1="auto"
PORT2="auto"
SKIP_DWNLD_TOOLS=false
DEVICE_NAME=""
RESET="none"
DOWN_UP=0
INTERVAL=1
COUNT=30
MTU=0
FILENAME="./ethernet_run_result.txt"
HL_DEVICE_TYPE="none"
server_pid=0
client_pid=0
ping_pid=0
background="true"
habana_net_list=""
IF1_PREV_STATE="down"
IF2_PREV_STATE="down"
IF1_PREV_MTU=0
IF2_PREV_MTU=0
MULTI_PORT="true"
MAC_ADDRESS="aa:bb:cc:dd:ee:ff"
readonly HABANA_DRIVER_NAME="habanalabs"
readonly HABANA_MAC_OUI="(b0:fd:0b|68:93:2e|98:4f:ee)"

usage()
{
    echo -e "\nusage: $1 [options]\n"
    echo -e "options:\n"
    echo -e "  --tool               Specify tool to run IPERF/PING. Default is IPERF, only for \
creation"
    echo -e "  --ip1                Specify ip for first interface, only for creation"
    echo -e "  --ip2                Specify ip for second interface, only for creation"
    echo -e "  --port1              Specify first port number or "auto"/empty, only for creation"
    echo -e "  --port2              Specify second port number, only for creation"
    echo -e "  --if1                Specify first net interface name or "auto"/empty, only for \
creation"
    echo -e "  --if2                Specify second net interface name, only for creation"
    echo -e "  --reset              Run additional iteration after hard/soft reset [h/s]"
    echo -e "  --mtu                Change MTU value"
    echo -e "  --down_up            Toggle interfaces down and up while sending ping, up to 10 times"
    echo -e "  --interval           Interval in seconds between ping packets"
    echo -e "  --count              Number of ECHO_REQUEST packets to send"
    echo -e "  --skip_dwnld_tools   Skip installation of iperf"
    echo -e "  --single_port        Run test with single port (loopback)"
    echo -e "  --help               display usage"
    echo -e "\n"
}

get_device_name()
{
    __temp=`ls -l /sys/class/accel/ | grep -iP 'accel[0-9][0-5]?'`
    DEVICE_NAME=`echo $__temp | rev |  cut -d'/' -f 1 | rev`
}

wait_for_rst_done()
{
    local status=""
    local timeout

    if [[ "${DEVICE_NAME}" ==  "" ]]; then
        get_device_name
    fi

    if [[ -f "/sys/module/habanalabs/parameters/pldm"  &&
          $(cat /sys/module/habanalabs/parameters/pldm) == 1 ]]; then
        if [[ "${RESET}" == "hard" ]]; then
            timeout=600
        else
            timeout=40
        fi

        echo -e "Running on PLDM - extend wait for device to be operational to $timeout sec."
    elif [[ "$HL_DEVICE_TYPE" == *Simulator ]]; then
        if [ $RESET == "hard" ]; then
            timeout=20
        else
            timeout=10
        fi
    # else - ASIC
    else
        if [ $RESET == "hard" ]; then
            timeout=100
        else
            timeout=10
        fi
    fi

    while [[ $timeout -gt 0 && $status != "Operational" ]]
    do
        status=`cat /sys/class/accel/${DEVICE_NAME}/device/status`
        sleep 1
        let timeout--
    done

    if [[ $status != "Operational" ]]; then
        echo -e "Timeout while waiting for device to become operational"
        exit 1
    else
        echo -e "Reset device done"
    fi
    sleep 5
}

check_ping_passed()
{
    local line
    local next_line

    if [[ $DOWN_UP -gt 0 ]]; then
        line=$(grep -n "Network is unreachable" "$1" | tail -1 | cut -d':' -f1)
        next_line=$(expr $line + 1)
        head -${next_line} $1 | tail -1 | grep "64 bytes from"
        return $?
    elif [[ $RESET == "hard" ]]; then
        line=$(grep -n "Reset device done" "$1" | tail -1 | cut -d':' -f1)
        next_line=$(expr $line + 1)
        head -${next_line} $1 | tail -1 | grep "64 bytes from"
        return $?
    elif [[ "$HL_DEVICE_TYPE" == "GAUDI3" && $(grep -E " ([0-9](\.[0-9]+)?|10(\.0+)?)% packet loss" "$1") ]]; then
	return 0
    elif [[ $(grep " 0% packet loss" "$1") ]]; then
        return 0
    fi

    return 1
}

check_iperf_passed()
{
    if [[ $(grep "iperf Done" "$1") ]]; then
        return 0
    fi

    return 1
}

install_tool()
{
    if [[ $(command -v $1) ]]; then
        echo -e "$2 installed"
    else
        sudo apt install -y $2
        if [[ $? != 0 ]]; then
            echo -e "Failed to install $2"
            exit 1
        fi
        echo -e "installed $2 successfully"
    fi
}

check_tool()
{
    if [[ $TOOL != "PING" && $TOOL != "IPERF" ]]; then
        echo -e "\nInvalid --tool <TOOL> should be [PING|IPERF]\n"
        usage
        return 1
    fi

    return 0
}

check_ip()
{
     local count=$(echo $1 | grep -Fo "." | wc -l)
     if [[ "$count" == 3 ]]; then
        echo $1
     else
        echo $2
     fi
}

delete_namespaces()
{
    local namespace_list

    namespace_list=`${IP} netns list | cut -d' ' -f1`
    for cur_namespace in ${namespace_list}; do
        if [ "${cur_namespace}" == "${NS1}" ] || [ "${cur_namespace}" == "${NS2}" ]; then
            echo "Namespace '${cur_namespace}' was detected - deleting it"
            sudo ${IP} netns del ${cur_namespace}
        fi
    done

    if [[ -n $namespace_list ]]; then
        sleep 5
    fi
}

create_namespaces()
{
    local check1
    local check2=0

    sudo $IP netns add $1
    check1=$?
    if [[ "$MULTI_PORT" == "true" ]]; then
        sudo $IP netns add $2
        check2=$?
    fi

    if [[ "${check1}" != 0 || "${check2}" != 0 ]]; then
        echo "Namespaces already exists, please remove."
        exit 1
    fi
}

enable_net_if()
{
    local check1
    local check2=0

    sudo ifconfig "$1" up
    check1=$?
    if [[ "$MULTI_PORT" == "true" ]]; then
        sudo ifconfig "$2" up
        check2=$?
    fi

    if (( "${check1}" != 0 || "${check2}" != 0 )); then
        echo "Interfaces not available."
        exit 1
    fi
}

attach_if_to_ns()
{
    sudo ${IP} link set dev $1 netns $2
    [[ "$?" != 0 ]] && return 1
    sudo ${IP} netns exec $2 ifconfig $1 $3/24 up
    [[ "$?" != 0 ]] && return 1

    return 0
}

build_net_ifs_global_list()
{
    local net_if
    local if_info
    local driver_name
    habana_net_list=""

    for net_if in /sys/class/net/*/ ; do
        net_if=$(basename $net_if)

        # ignore loopback and virtual ethernet devices
        if [ $net_if == "lo" ] || [ `echo $net_if | cut -c1-4` == "veth" ]; then
            continue
        fi

        # consider habanalabs NICs only
        if [ ! -f /sys/class/net/$net_if/address ] || \
           [ ! $(cat /sys/class/net/$net_if/address | grep -E ^$HABANA_MAC_OUI) ]; then
            continue
        fi
        habana_net_list="$habana_net_list $net_if"
    done

    if [ -z "$habana_net_list" ]; then
        echo "Warning: no $HABANA_DRIVER_NAME network interfaces were detected"
        exit 1
    fi
}

assign_interface()
{
    local itf=/sys/class/net/$1
    if [[ -d "$itf" ]]; then
       return 0
    fi

    echo -e "Port $1 not found in /sys/class/net/"
    return 1
}

assign_port()
{
    for net_if in $habana_net_list;
    do
        if [[ $(cat /sys/class/net/$net_if/dev_port) == $1 || $net_if == $1 || "$1" == "auto" ]];
        then
            eval "$2=$net_if"

            # Remove selected port from pool.
            habana_net_list=$(echo $habana_net_list | tr ' ' '\n' | grep -v -w $net_if | tr '\n' ' ')

            return 0
        fi
    done

    echo -e "Port $1 not found in /sys/class/net/"
    return 1
}

check_down_up()
{
    if [[ $DOWN_UP -gt 10 ||  $DOWN_UP -lt 0 ]]; then
        echo -e "invalid --down_up <times> should be [1-10]"
        exit 1
    fi

    echo $1
}

check_reset()
{
    if [[ $RESET != "none" && $RESET != "soft" && $RESET != "hard" ]]; then
        echo -e "invalid --reset <type> should be [soft|hard]"
        return 1
    fi

    return 0
}

assign_ports()
{
    assign_port $PORT1 PORT1
    [ $? -ne 0 ] && exit 1

    if [[ "$MULTI_PORT" == "true" ]]; then
        assign_port $PORT2 PORT2
        [ $? -ne 0 ] && exit 1
    fi
}

restore_iface_link_state()
{
    if [[ $2 == "up" ]]; then
        echo "restore $1 link state: $2"
        sudo ifconfig $1 $2
    fi
}

get_iface_prev_state()
{
    if [[ $(cat /sys/class/net/$1/carrier 2> /dev/null) -eq 1 ]]; then
        eval "$2='up'"
    fi
}

restore_mtu()
{
    if (( $2 != 0 )); then
        echo "restore $1 MTU to $2"
        sudo ifconfig $1 mtu $2
    fi
}

get_mtu_prev_state()
{
    eval "$2=$(cat /sys/class/net/$1/mtu)"
}

cleanup_namespace()
{
    local ret1
    local ret2=0

    build_net_ifs_global_list
    assign_port $PORT1 DUMMY
    ret1=$?

    if [[ "$MULTI_PORT" == "true" ]]; then
        assign_port $PORT2 DUMMY
        ret2=$?
    fi

    if [ $ret1 -ne 0 ] || [ $ret2 -ne 0 ] ; then
        echo -e -n "\033[1;31mPorts were not found due to an exiting namespace."
        echo -e "Cleaning namespace.\033[1;0m"
        delete_namespaces
        exit 1
    fi
}

validate_parameters()
{
    build_net_ifs_global_list
    assign_ports

    check_tool
    [[ "$?" != 0 ]] && exit 1

    check_reset
    [[ "$?" != 0 ]] && exit 1

    check_down_up
    [[ "$?" != 0 ]] && exit 1
}

set_mtu()
{
    local run_w_namespace=""
    if [[ "$MULTI_PORT" == "true" ]]; then
        run_w_namespace="$IP netns exec $2"
    fi

    sudo $run_w_namespace ifconfig $1 mtu $MTU
    if [ $? -ne 0 ]; then
        echo -e "Failed to set MTU of $1: $MTU"
        return 1
    fi

    echo -e "Set MTU of $1: $MTU"
    return 0
}

kill_pending_proc()
{
    local pid2
    local pid1
    local namespace_list
    local ns1
    local ns2

    if [[ "$MULTI_PORT" == "true" ]]; then
        # kill any pending process in case of failure
        namespace_list=`$IP netns list | cut -d' ' -f1`

        $(echo $namespace_list | grep -w -q $NS1)
        ns1=$?

        $(echo $namespace_list | grep -w -q $NS2)
        ns2=$?

        if [ $ns1 -eq 0 ]; then
            pid1=$(sudo $IP netns pids $NS1)
            if [ "$pid1" != ""  ]; then
                echo "killing process $pid1"
                sudo kill -SIGINT $pid1
            fi
        fi

        if [ $ns2 -eq 0 ]; then
            pid2=$(sudo $IP netns pids $NS2)
            if [ "$pid2" != "" ]; then
                echo "killing process $pid2"
                sudo kill -SIGINT $pid2
            fi
        fi
    else
        if [ $client_pid -ne 0 ]; then
            sudo kill -SIGINT $client_pid  > /dev/null 2>&1
            client_pid=0
        fi

        if [ $server_pid -ne 0 ]; then
            sudo kill -SIGINT $server_pid > /dev/null 2>&1
            server_pid=0
        fi

        if [ $ping_pid -ne 0 ]; then
            sudo kill -SIGINT $ping_pid > /dev/null 2>&1
            ping_pid=0
        fi
    fi
}

run_tool()
{
    if [[ $1 == "PING" ]]; then
        run_ping $2
    else
        run_iperf
    fi
}

get_device_type()
{
    if [ -f /sys/class/accel/accel0/device/device_type ]; then
        HL_DEVICE_TYPE=$(cat /sys/class/accel/accel0/device/device_type)
    else
        echo "Unknown device"
        exit 1
    fi
    echo -e "Found "$HL_DEVICE_TYPE" device"
}

run_iperf()
{
    local limit

    if [[ -f "/sys/module/habanalabs/parameters/pldm" &&
              $(cat /sys/module/habanalabs/parameters/pldm) == 1 && $RESET != "none" ]]; then
        if [ $RESET == "hard" ]; then
            limit=650 # Hard reset takes about 10 minutes with preboot
        else
            limit=60
        fi

        echo -e "Running on PLDM with reset request - extend iperf time to $limit sec."
    elif [[ "$HL_DEVICE_TYPE" == *Simulator ]]; then
        if [ $RESET == "hard" ]; then
            limit=30
        else
            limit=30
        fi
    # else - ASIC
    else
        if [ $RESET == "hard" ]; then
            limit=180
        else
            limit=30
        fi
    fi

    if [ $DOWN_UP -gt 0 ]; then
        var=$DOWN_UP
        limit=$(expr 15 \* $var)
    fi

    local run_w_namespace1=""
    local run_w_namespace2=""
    if [[ "$MULTI_PORT" == "true" ]]; then
        run_w_namespace1="$IP netns exec $NS1"
        run_w_namespace2="$IP netns exec $NS2"
    fi

    sudo $run_w_namespace1 iperf3 -s -1 --daemon --bind $IP1
    if [ $? -eq 0 ]; then
        server_pid=$!
    fi

    if [[ "$MULTI_PORT" == "true" ]]; then
        sudo $run_w_namespace2 iperf3 -t $limit --client $IP1 --forceflush &
    else
        sudo $run_w_namespace2 iperf3 -t $limit --client $IP2 --forceflush &
    fi

    if [ $? -eq 0 ]; then
        client_pid=$!
    fi
}

run_ping()
{
    local run_w_namespace=""
    if [[ "$MULTI_PORT" == "true" ]]; then
        run_w_namespace="sudo $IP netns exec $NS1"
    fi

    if [ "$1" = "true" ]; then
        $run_w_namespace ping -i 0.4 $IP2 &
        if [ $? -eq 0 ]; then
            ping_pid=$!
        fi
    else
        $run_w_namespace ping -i $INTERVAL -c $COUNT $IP2 & wait $!
    fi
}

hard_reset()
{
    echo -e "Issuing hard reset to the device"
    echo 1 | sudo tee /sys/class/accel/$DEVICE_NAME/device/hard_reset 2>&1 > /dev/null
}

soft_reset()
{
    echo -e "Issuing soft reset via /dev/accel/0"
    rc=$(cat /dev/accel/$DEVICE_NAME 2>&1 > /dev/null)
}

check_results()
{
    if [[ $1 == "PING" ]]; then
        kill_pending_proc
        check_ping_passed $FILENAME
    else
        check_iperf_passed $FILENAME
    fi

    if [[ $? == 1 ]]; then
        echo ""$1" Test Failed"
        exit 1
    fi
}

init_environment()
{
    if [[ "$MULTI_PORT" == "true" ]]; then
        echo -e "\n============="
        echo -e " IF1 = $PORT1"
        echo -e " IF2 = $PORT2"
        echo -e "=============\n"

        get_iface_prev_state $PORT1 IF1_PREV_STATE
        echo "$PORT1 previous link state: $IF1_PREV_STATE"
        get_iface_prev_state $PORT2 IF2_PREV_STATE
        echo "$PORT2 previous link state: $IF2_PREV_STATE"

        get_mtu_prev_state $PORT1 IF1_PREV_MTU
        echo "$PORT1 previous MTU: $IF1_PREV_MTU"
        get_mtu_prev_state $PORT2 IF2_PREV_MTU
        echo "$PORT2 previous MTU: $IF2_PREV_MTU"

        echo -e "Creating namespaces '$NS1', '$NS2'"
        create_namespaces $NS1 $NS2

        echo -e "Enabling network interfaces"
        enable_net_if $PORT1 $PORT2

        echo -e "Attaching the network interfaces '$PORT1' to namespace '$NS1'"
        attach_if_to_ns "$PORT1" "$NS1" "$IP1"
        [ $? -ne 0 ] && echo -e "Failed to attach $PORT1 to namespace $NS1" && exit 1

        echo -e "Attaching the network interfaces '$PORT2' to namespace '$NS2'"
        attach_if_to_ns "$PORT2" "$NS2" "$IP2"
        [ $? -ne 0 ] && echo -e "Failed to attach $PORT2 to namespace $NS2" && exit 1
    else
        echo -e "\n============="
        echo -e " IF = $PORT1"
        echo -e "=============\n"

        get_iface_prev_state $PORT1 IF1_PREV_STATE
        echo "$PORT1 previous link state: $IF1_PREV_STATE"

        get_mtu_prev_state $PORT1 IF1_PREV_MTU
        echo "$PORT1 previous MTU: $IF1_PREV_MTU"

        echo -e "Enabling network interface"

        sudo ifconfig $PORT1 $IP1/24 up

        sudo arp -d $IP2
        sudo arp -s $IP2 $MAC_ADDRESS

        [ $? -ne 0 ] && return 1
    fi
}

iface_down_up()
{
    # start running ping in the background
    run_tool "$TOOL" "true"
    local run_w_namespace=""
    if [[ "$MULTI_PORT" == "true" ]]; then
        run_w_namespace="$IP netns exec $NS1"
    fi

    sleep 5
    for i in $(seq 1 $1);
    do
        # Disable the chosen ports
        sudo $run_w_namespace ifconfig $PORT1 down
        [ "$?" -ne 0 ] && return 1
        if [[ "$MULTI_PORT" == "true" ]]; then
            sudo $IP netns exec $NS2 ifconfig $PORT2 down
            [ "$?" -ne 0 ] && return 1
        fi
        sleep 5
        # Enable the chosen ports
        sudo $run_w_namespace ifconfig $PORT1 up
        [ "$?" -ne 0 ] && return 1
        if [[ "$MULTI_PORT" == "true" ]]; then
            sudo $IP netns exec $NS2 ifconfig $PORT2 up
            [ "$?" -ne 0 ] && return 1
        else
            # After port down, IP2 is removed from ARP table. Therefore, add it again.
            sudo arp -s $IP2 $MAC_ADDRESS
        fi
        sleep 5
    done

    # Check that ping returns
    if [[ "$TOOL" == "PING" ]]; then
        kill_pending_proc
        check_ping_passed "$FILENAME"
    else
        wait $client_pid
        sleep 5
        check_iperf_passed "$FILENAME"
    fi
    echo -e "\n============="
    echo -e "    Done     "
    echo -e "============="
}

iface_down_up_test()
{
    iface_down_up $1
    if [[ $? == 0 ]]; then
        echo -e "============================="
        echo -e "Interface down/up test passed"
        echo -e "============================="
        ret=0
    else
        echo -e "=============================="
        echo -e "Interfaces down/up test failed"
        echo -e "=============================="
        ret=1
    fi

    exit $ret
}

if [[ -f "$FILENAME" ]]; then
    sudo rm ${FILENAME}
fi

exec &> >(sudo tee -a "$FILENAME")

run_test()
{
    OPTIONS=tool:,ip1:,ip2:,port1:,port2:,if1:,if2:,reset:,mtu:,
    OPTIONS+=down_up:,interval:,count:,skip_dwnld_tools,single_port,help
    PARSED_ARGUMENTS=$(getopt --longoptions $OPTIONS --options ""  -- "$@")
    if [[ "$?" != 0 ]]; then
        usage
        exit 1
    fi

    eval set -- "$PARSED_ARGUMENTS"
    while :
    do
      case $1 in
          --tool)               TOOL=$2; shift 2 ;;
          --ip1)                IP1=$(check_ip $2 $IP1); shift 2 ;;
          --ip2)                IP2=$(check_ip $2 $IP2); shift 2 ;;
          --port1)              PORT1=$2; shift 2 ;;
          --port2)              PORT2=$2; shift 2 ;;
          --if1)                PORT1=$2; shift 2 ;;
          --if2)                PORT2=$2; shift 2 ;;
          --reset)              RESET=$2; shift 2 ;;
          --mtu)                MTU=$2; shift 2 ;;
          --down_up)            DOWN_UP=$2; shift 2 ;;
          --interval)           INTERVAL=$2; shift 2 ;;
          --count)              COUNT=$2; shift 2 ;;
          --skip_dwnld_tools)   SKIP_DWNLD_TOOLS=true; shift ;;
          --single_port)        MULTI_PORT="false"; shift ;;
          --help) shift ;;
          --) shift; break ;;
          *) echo "Invalid option"; break;;
        esac
    done

    if [[ "$PARSED_ARGUMENTS" =~ "--help" ]]; then usage; exit 0; fi

    if [[ $DOWN_UP != 0 && ( $MTU != 0 || $RESET != "none"  || $DOWN_UP -gt 10 ) ]]; then
        echo -e "\n\n===================================================="
        echo -e "Invalid parameters. To run interface down/up test:"
        echo -e "===================================================="
        echo -e "./run_eth_test --tool <tool> --port1 <port_1> --port2 <port_2> --down_up <0-10>"
        exit 1
    fi

    # For CI: to install on docker at runtime
    if [[ "${SKIP_DWNLD_TOOLS}" == "false" ]]; then
	sudo apt update
        install_tool "ifconfig" "net-tools"
        install_tool "arp" "net-tools"
        install_tool "iperf3" "iperf3"
        install_tool "ip" "iproute2"
        install_tool "ping" "iputils-ping"
        install_tool "ethtool" "ethtool"
    fi

    # Cleanup any open namespaces and exit
    cleanup_namespace

    # must occur after install_tool
    validate_parameters
    # Find which device is running
    get_device_type

    # Soft reset is not supported in Gaudi1
    if [[ "$RESET" == "soft" && ("$HL_DEVICE_TYPE" == "GAUDI" || "$HL_DEVICE_TYPE" == "GAUDI Simulator") ]]; then
        echo -e "Gaudi device does not support soft reset, aborting..."
        exit 1
    fi

    # Initialize test environment
    init_environment

    if [[ $DOWN_UP -gt 0 ]]; then
        iface_down_up_test $DOWN_UP
    fi

    if [[ $DOWN_UP == 0 && $RESET == "none" && $MTU == 0 ]]; then
        background="false"
    fi

    echo "Wait a bit for the ports to get link"
    sleep 5

    # Test the setup
    echo -e "Running '${TOOL}'"
    run_tool $TOOL $background
    sleep 3

    if [[ $TOOL == "IPERF" ]]; then sleep 5; fi

    if [[ ${MTU} != 0 ]]; then
        set_mtu ${PORT1} ${NS1}
        mtu1=$?

        mtu2=0
        if [[ "$MULTI_PORT" == "true" ]]; then
            set_mtu $PORT2 $NS2
            mtu2=$?
        fi

        if [ $mtu1 -ne 0 ] || [ $mtu2 -ne 0 ]; then
            echo -e "Failed to set MTU "$MTU", aborting..."
            exit 1
        fi
        sleep 5
    fi

    get_device_name
    [[ $? != 0 ]] && echo -e "Failed to read device name" && exit 1

    if [[ "${RESET}" == "hard" ]]; then
        hard_reset
    elif [[ "${RESET}" == "soft" ]]; then
        soft_reset
    fi

    if [[ $RESET != "none" ]]; then
        wait_for_rst_done
    fi

    if [[ $TOOL == "IPERF" && $client_pid != 0 ]]; then
        wait $client_pid
    fi

    sleep 10
    check_results $TOOL
    echo -e ""$TOOL" Test Passed"
}

run_test $@
