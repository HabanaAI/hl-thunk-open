#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2021 HabanaLabs, Ltd.
# All Rights Reserved.
#

SUPP_PARAMS="suppressions=$HLTHUNK_ROOT/sanitizer_ubsan_suppress.txt"
HLTHUNK_BUILD_PATH=$HLTHUNK_DEBUG_BUILD
CFG_DIR="$HLTHUNK_ROOT/tests"
DEVICE_TYPE=H3
DEVICE_NUMBER1="0"
DEVICE_NUMBER2="1"
OVERRIDE_PORT1=""
OVERRIDE_PORT2=""
DEVICE_NAME=""
EXT_PORT1=""
EXT_PORT2=""

IF1=""
IF2=""
PORT1=""
PORT2=""
LOOPBACK=false
DBTM=5

# currently only single connection is supported
debugfs_fp="/sys/kernel/debug/habanalabs_cn/hbl_cn$DEVICE_NUMBER1/nic_qp_id_offset_in_macro"
ODD_PORT_DST_CONN_ID=$((1 + $(sudo cat $debugfs_fp | tr '\0' '\n')))
EVEN_PORT_DST_CONN_ID=1
ITERATION=1
CMPL_MTHD=sob
retval=""

TEMP_DIR=$(mktemp -d)
SIM_FILE1="$TEMP_DIR/nic_tests_cfg_sim1.txt"
SIM_FILE2="$TEMP_DIR/nic_tests_cfg_sim2.txt"

# Clean up temporary directory on exit
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

get_pci_id()
{
	dev_type=${1}
	dev_num=${2}
	pci_id=$(cat /sys/class/accel/accel${dev_num}/device/pci_addr)

	if [ $? -ne 0 ]; then
		echo "failed to get PCI ID of device ${dev_num} for type ${dev_type}"
    		exit 1
	fi

	echo ${pci_id}
}


usage()
{
    echo -e  "\nusage: $1 [options]\n"
    echo -e  "options:\n"
    echo -e  "  --if1          Specify interface name of first simulator"
    echo -e  "  --if2          Specify interface name of second simulator"
    echo -e  "  --doorbell     Specify doorbell timeout in sec"
    echo -e  "  --dev_type     Specify device type gaudi(H3 -default) or gaudi2(H6) or gaudi3(H9)"
    echo -en "  --dev_number1  Specify device number of first simulator"
    echo -e  "(i.e. 0 for /sys/class/accel/accel0/)"
    echo -en "  --dev_number2  Specify device number of second simulator"
    echo -e  "(i.e. 0 for /sys/class/accel/accel0/)"
    echo -e  "  --iteration    Specify num of iterations"
    echo -e  "  --cmpl         Specify completion method cq_usr/sob(default)"
    echo -e  "  --release      Run tests with release build"
    echo -e  "  --loopback     Run tests in mac loopback mode (ignores irrelevant options)"
    echo -e  "  --port1        Override default port1"
    echo -e  "  --port2        Override default port2"
    echo -e  "\n"
}

check_cmpl()
{
    if [[ "$1" == "cq_usr" ]]; then
       echo $1
    else
       echo $CMPL_MTHD
    fi
}

update_cfg()
{
    local conn_id

     if [[ -f "$SIM_FILE1" ]]; then
        sudo rm ${SIM_FILE1}
     fi
     if [[ -f "$SIM_FILE2" ]]; then
        sudo rm ${SIM_FILE2}
     fi
     filename="$CFG_DIR$DEVICE_NAME/nic_tests_cfg.txt"
     e2e_conf=false
     while IFS= read -r line
     do
          if [[ "$line" =~ .*"[".* ]]; then
               if [[ "$line" == "[e2e]" ]]; then
                   e2e_conf=true
               else
                   e2e_conf=false
               fi
          fi
          if [[ "$e2e_conf" == true && "$LOOPBACK" == false ]]; then
               # common changes
               line=$(sed "s/doorbell_to=.*/doorbell_to=$DBTM/g" <<<"$line")
               line=$(sed "s/iterations=.*/iterations=$ITERATION/g" <<<"$line")
               line=$(sed "s/cmpl=.*/cmpl=$CMPL_MTHD/g" <<<"$line")
               # specific port changes
               if [[ $(($PORT2 % 2)) == 1 ]]; then
                   conn_id=$ODD_PORT_DST_CONN_ID
               else
                   conn_id=$EVEN_PORT_DST_CONN_ID
               fi
               line=$(sed "s/dst_conn_ids=.*/dst_conn_ids=$conn_id/g" <<<"$line")
               line=$(sed "s/ports=.*/ports=$PORT1/g" <<<"$line")
               line=$(sed "s/dst_macs=.*/dst_macs=$1/g" <<<"$line")
               echo $line >> $SIM_FILE1

               if [[ $(($PORT1 % 2)) == 1 ]]; then
                   conn_id=$ODD_PORT_DST_CONN_ID
               else
                   conn_id=$EVEN_PORT_DST_CONN_ID
               fi
               line=$(sed "s/dst_conn_ids=.*/dst_conn_ids=$conn_id/g" <<<"$line")
               line=$(sed "s/ports=.*/ports=$PORT2/g" <<<"$line")
               line=$(sed "s/dst_macs=.*/dst_macs=$2/g" <<<"$line")
               echo $line >> $SIM_FILE2
          elif [[ "$LOOPBACK" == true ]]; then
               # New infra
               line=$(sed "s/runtime_iterations=.*/runtime_iterations=$ITERATION/g" <<<"$line")
               # Old infra
               line=$(sed "s/iterations_mem=.*/iterations_mem=$ITERATION/g" <<<"$line")

               line=$(sed "s/cmpl=.*/cmpl=$CMPL_MTHD/g" <<<"$line")
               echo $line >> $SIM_FILE1
          else
               echo $line >> $SIM_FILE1
               echo $line >> $SIM_FILE2
          fi
     done < $filename
}

get_if_for_pci_id()
{
    local net_if=""
    local if_info=""
    local bus_info=""
    local dev_port=""
    local ext_port=""

    type ethtool &> /dev/null
    if [ $? -ne 0 ]; then
        echo "installing ethtool"
        sudo apt update
        sudo apt install ethtool -y
        if [ $? -ne 0 ]; then
            exit 1
        fi
    fi

    ext_port=$2

    for net_if in /sys/class/net/*/; do
        net_if=$(basename $net_if)

        # ignore loopback and virtual ethernet devices
        if [ $net_if == "lo" ] || [ `echo $net_if | cut -c1-4` == "veth" ]; then
            continue
        fi

        # ignore characters including and after '@' in interface name
        net_if=`echo "$net_if" | cut -d'@' -f1`

        if_info=`ethtool -i $net_if`
        if [ $? -ne 0 ]; then
            continue
        fi

        # ignore interfaces of other devices
        bus_info=`echo "$if_info" | grep 'bus-info' | awk '{print $2}'`
        if [ "$bus_info" != $1 ]; then
            continue
        fi

        if [ ! -f /sys/class/net/$net_if/dev_port ] ||
                [ ! -f /sys/class/net/$net_if/operstate ]; then
            echo "can't get dev_port/opersate of $net_if"
            exit 1
        fi

        dev_port=$(cat /sys/class/net/$net_if/dev_port)
	#echo $"interface ${net_if} dev_port ${dev_port} ext_port ${ext_port}"
        if [ $dev_port != $ext_port ]; then
            continue
        fi

        if [ $(cat /sys/class/net/$net_if/operstate) != "up" ]; then
            echo "$net_if is not up"
            exit 1
        fi

        retval=$net_if
        break
    done
}

FILENAME="./rdma_run_result.txt"
if [[ -f "$FILENAME" ]]; then
    sudo rm ${FILENAME}
fi

exec &> >(sudo tee -a "$FILENAME")

# get args. covered step7 in args
OPTIONS="if1:,if2:,doorbell:,dev_type:,dev_number1:,dev_number2:,iteration:,cmpl:,release,loopback,\
port1:,port2:,help"
PARSED_ARGUMENTS=$(getopt --longoptions $OPTIONS --options ""  -- "$@")
if [ $? -ne 0 ]
then
    usage
    exit 1
fi
#add trap to delete files

eval set -- "$PARSED_ARGUMENTS"
while :
do
  case $1 in
        --if1) IF1=$2; shift 2 ;;
        --if2) IF2=$2; shift 2 ;;
        --doorbell) DBTM=$2; shift 2 ;;
        --dev_type) DEVICE_TYPE=$2; shift 2 ;;
        --dev_number1) DEVICE_NUMBER1=$2; shift 2 ;;
        --dev_number2) DEVICE_NUMBER2=$2; shift 2 ;;
        --iteration) ITERATION=$2; shift 2 ;;
        --cmpl) CMPL_MTHD=$(check_cmpl $2); shift 2 ;;
        --release) HLTHUNK_BUILD_PATH=$HLTHUNK_RELEASE_BUILD; shift;;
        --loopback) LOOPBACK=true; shift;;
        --port1) OVERRIDE_PORT1=$2; shift 2 ;;
        --port2) OVERRIDE_PORT2=$2; shift 2 ;;
        --help) usage $1; exit 0;;
        --) shift; break ;;
   esac
done

echo "Getting PCI IDs"

PCIID1=$(get_pci_id ${DEVICE_TYPE} ${DEVICE_NUMBER1})

echo "hl0 PCI ID: $PCIID1 device1: ${DEVICE_NUMBER1}"

if [[ "$LOOPBACK" = false ]]; then
    PCIID2=$(get_pci_id ${DEVICE_TYPE} ${DEVICE_NUMBER2})
    echo "hl1 PCI ID: $PCIID2 device2: ${DEVICE_NUMBER2}"
fi

if [ $DEVICE_TYPE = "H3" ]; then
    DEVICE_NAME="/gaudi"
    # port 1 is connected to global switch
    EXT_PORT1="1"
    EXT_PORT2="1"
    ODD_PORT_DST_CONN_ID=1
elif [ $DEVICE_TYPE = "H6" ]; then
    DEVICE_NAME="/gaudi2"
     # port 8 is connected to global switch
    EXT_PORT1="8"
    EXT_PORT2="8"
    ODD_PORT_DST_CONN_ID=1
elif [ $DEVICE_TYPE = "H9" ]; then
    DEVICE_NAME="/gaudi3"

    nic_speed=$(sudo cat /sys/module/habanalabs/parameters/nic_lanes_per_port)
    if [ $nic_speed = "2" ]; then
        module_id=$(cat /sys/class/accel/accel0/device/module_id)
        # In G3 each card location has different external ports. For card location 0, choose port
        # 17. For card location 1, choose port 8.
        if [ $module_id = "0" ]; then
           EXT_PORT1="17"
           EXT_PORT2="8"
        else
           EXT_PORT1="8"
           EXT_PORT2="17"
        fi
    else
        EXT_PORT1="8"
        EXT_PORT2="8"
    fi
else
    echo "Device not specified or unsupported device, aborting"
    exit 1
fi


if [ ! -z "$OVERRIDE_PORT1" ]; then
	EXT_PORT1=${OVERRIDE_PORT1}
fi
if [ ! -z "$OVERRIDE_PORT2" ]; then
	EXT_PORT2=${OVERRIDE_PORT2}
fi
echo "port1: ${EXT_PORT1} port2: ${EXT_PORT2}"

if [[ "$LOOPBACK" = false ]]; then
    get_if_for_pci_id $PCIID1 $EXT_PORT1
    IF1=$retval

    get_if_for_pci_id $PCIID2 $EXT_PORT2
    IF2=$retval

    if [ -z "$IF1" ] || [ -z "$IF2" ]; then
        usage $1
        exit 1
    fi

    PORT1=$(cat /sys/class/net/${IF1}/dev_port)
    if [ $? -ne 0 ]; then
        usage $1
        exit 1
    fi

    PORT2=$(cat /sys/class/net/${IF2}/dev_port)
    if [ $? -ne 0 ]; then
        usage $1
        exit 1
    fi

    echo "Getting Mac address for $IF1"
    DEST_MAC_IF1=$(cat /sys/class/net/${IF1}/address)
    if [ $? -ne 0 ]; then
        usage $1
        exit 1
    fi

    echo "Getting Mac address for $IF2"
    DEST_MAC_IF2=$(cat /sys/class/net/${IF2}/address)
    if [ $? -ne 0 ]; then
        usage $1
        exit 1
    fi

    echo "IF1: $IF1, port: $PORT1, MAC: $DEST_MAC_IF1"
    echo "IF2: $IF2, port: $PORT2, MAC: $DEST_MAC_IF2"
fi

echo "Creating cfg files"
update_cfg $DEST_MAC_IF2 $DEST_MAC_IF1

if [[ "$LOOPBACK" = true ]]; then
    echo -e "\nRunning loopback test"
    TEST="test_nic_e2e_lpbk"

else
    echo -e "\nRunning e2e test"
    TEST="test_nic_e2e"
fi

TEST_RUN="sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH \
            UBSAN_OPTIONS=$SUPP_PARAMS \
            -E $HLTHUNK_BUILD_PATH/bin/nic_root \
            -s $TEST \
            -b $HLTHUNK_BUILD_PATH \
        "

$TEST_RUN -c $SIM_FILE1 -p $PCIID1 &
pid1=$!

if [[ "$LOOPBACK" = false ]]; then
    $TEST_RUN -c $SIM_FILE2 -p $PCIID2 &
    pid2=$!
fi

wait $pid1
if [ $? -ne 0 ]; then
    echo "test failed at A side\n"
    echo "FAILED"
    exit 1
fi

if [[ "$LOOPBACK" = false ]]; then
    wait $pid2
    if [ $? -ne 0 ]; then
        echo "test failed at B side\n"
        echo "FAILED"
        exit 1
    fi
fi

echo "PASSED"

exit 0
