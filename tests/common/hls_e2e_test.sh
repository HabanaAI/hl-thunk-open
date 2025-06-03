#!/bin/bash
#
# Copyright (C) 2020 HabanaLabs, Ltd.
# All Rights Reserved.
#
# Unauthorized copying of this file, via any medium is strictly prohibited.
# Proprietary and confidential.
# Author: Omer Shpigelman <oshpigelman@habana.ai>
#

readonly GREEN='\033[0;32m'
readonly NC='\033[0m'
readonly HABANA_DRIVER_NAME="habanalabs"
readonly DEV_NUM=8
readonly PORTS_NUM_MAX=64
readonly GAUDI_NET_FILE="/etc/gaudinet.json"

CFG_STR="[e2e]
ports=
dst_macs=
dst_ips=
qps_per_port=
dst_conn_ids=
remote_sob_idx=
remote_addr_idx=
user_cq_buf_len_shift=13
data_size_shift=16
wqe_size_shift=12
cmpl=cq_usr
print_data=no
seed=
iterations=1
wait_for_cleanup=no
sleep_before_cleanup=5
lazy=yes
doorbell_to=5
rand_data=yes
data_cmp=yes
cleanup=yes
verbose=0
wq_loc=host
user_db=no"

usage()
{
    echo -e "\nusage: $(basename "$1") [options]\n"

    echo -e "options:\n"
    echo -e "       --internal-only    run on internal ports only"
    echo -e "       --external-only    run on external ports only"
    echo -e "       --lazy             run lazy mode configurations"
    echo -e "  -c   --comp             chose completion type SOB or user CQ (values: cq_usr|sob,"\
                                       "default: cq_usr)"
    echo -e "  -q   --qps-per-port     number of QPs per port (default: 1, range: 1-1023)"
    echo -e "  -t   --timeout <val>    number of seconds to wait before doorbell (rang: 1-10)"
    echo -e "  -s   --size <val>       the log of the data size to use (range: 16-30)"
    echo -e "  -v,  --verbose          print more logs"
    echo -e "  -h,  --help             print this help"
}

# each element represents the corresponding module_id/port,
# so if ${dst_module_id[14]}=7 and ${dst_port[14]}=3, it means that port 4 on module_id 1 (since
# each gaudi has 10 ports in Gaudi1, 14/10 = 1 => module 1 and 14%10 = 4 => port 4)
# should communicate with module_id 7 port 3

dst_module_id_gaudi=(1 1 2 6 4 5 7 3 1 1 \
                     3 0 0 7 5 4 6 2 0 0 \
                     4 3 0 3 6 7 5 1 3 3 \
                     1 2 5 2 7 6 4 0 2 2 \
                     2 5 6 5 0 1 3 7 5 5 \
                     7 4 3 4 1 0 2 6 4 4 \
                     7 7 4 0 2 3 1 5 7 7 \
                     5 6 6 1 3 2 0 4 6 6 \
                     )
dst_port_gaudi=(2 1 2 3 4 5 6 7 8 9 \
                0 1 0 3 4 5 6 7 8 9 \
                0 1 2 3 4 5 6 7 8 9 \
                0 1 2 3 4 5 6 7 8 9 \
                0 1 2 3 4 5 6 7 8 9 \
                0 1 2 3 4 5 6 7 8 9 \
                2 1 2 3 4 5 6 7 8 9 \
                0 1 0 3 4 5 6 7 8 9 \
                )
# 8, 22, 23 are external ports, rest all internal ports. Based on the switch topology of ext
# ports, run tests b/w ext ports of different modules connected to same switch.
# based on the connection of ext ports, connect
#port 8 of module 0 ---> port 8 module 1.
#port 22 of module 0 ----> port 22 of module 1
#port 23 of module 0 ----> port 23 of module 1 and so on..
dst_module_id_gaudi2=(3 3 7 3 7 7 4 4 1 4 2 2 2 1 1 1 6 6 6 5 5 5 1 1 \
                      2 2 6 2 6 6 5 5 0 5 7 7 7 0 0 0 3 3 3 4 4 4 0 0 \
                      1 1 5 1 5 5 6 6 3 6 3 3 3 4 4 4 0 0 0 7 7 7 3 3 \
                      0 0 4 0 4 4 7 7 2 7 2 2 2 5 5 5 1 1 1 6 6 6 2 2 \
                      7 7 3 7 3 3 0 0 5 0 5 5 5 2 2 2 6 6 6 1 1 1 5 5 \
                      6 6 2 6 2 2 1 1 4 1 4 4 4 3 3 3 7 7 7 0 0 0 4 4 \
                      5 5 1 5 1 1 2 2 7 2 4 4 4 7 7 7 0 0 0 3 3 3 7 7 \
                      4 4 0 4 0 0 3 3 6 3 1 1 1 6 6 6 5 5 5 2 2 2 6 6 \
                      )

dst_port_gaudi2=(0 1 2 3 4 5 6 7 8 9 16 17 18 13 14 15 16 17 18 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 10 11 12 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 10 11 12 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 16 17 18 13 14 15 16 17 18 19 20 21 22 23 \
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 \
                 )

dst_module_id_gaudi2_hl288=(1 1 1 1 1 1 N N N N 3 3 3 3 3 3 2 2 2 2 2 2 \
                            0 0 0 0 0 0 N N N N 2 2 2 2 2 2 3 3 3 3 3 3 \
                            3 3 3 3 3 3 N N N N 1 1 1 1 1 1 0 0 0 0 0 0 \
                            2 2 2 2 2 2 N N N N 0 0 0 0 0 0 1 1 1 1 1 1 \
                            5 5 5 5 5 5 N N N N 7 7 7 7 7 7 6 6 6 6 6 6 \
                            4 4 4 4 4 4 N N N N 6 6 6 6 6 6 7 7 7 7 7 7 \
                            7 7 7 7 7 7 N N N N 5 5 5 5 5 5 4 4 4 4 4 4 \
                            6 6 6 6 6 6 N N N N 4 4 4 4 4 4 5 5 5 5 5 5 \
                            )

dst_port_gaudi2_hl288=(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 \
                       )

dst_module_id_gaudi3=(1  1  3  3  2  2  5  5  4  4  7  7  6  6  6  7  4  2  5  2  1  1  1  3 \
                      5  5  7  6  5  3  4  3  0  0  2  0  0  0  2  2  3  3  4  4  6  6  7  7 \
                      6  6  4  5  6  0  7  0  3  3  3  1  0  0  3  3  1  1  5  5  4  4  7  7 \
                      1  1  2  2  0  0  5  5  7  7  4  4  6  6  5  4  7  1  6  1  2  2  0  2 \
                      0  0  2  2  3  3  5  5  7  7  6  6  6  5  6  5  2  3  0  5  1  7  1  1 \
                      4  7  7  4  3  2  1  4  0  6  1  1  0  0  3  3  2  2  6  6  4  4  7  7 \
                      7  4  4  7  0  1  2  7  3  5  2  2  0  0  1  1  3  3  4  4  5  5  7  7 \
                      0  0  2  2  3  3  5  5  4  4  6  6  5  6  5  6  1  0  3  6  2  4  1  1 \
                      )

#dst_port_gaudi3 with spaces is moved so both tables will be exactly above each other
     dst_port_gaudi3=(12 13 4  5  12 13 12 13 0  1  0  1  12 13 4  17 18 5  8  7  8  9  11 22  \
                      10 11 16 5  6  17 20 19 20 21 11 22 0  1  16 17 0  1  22 23 14 15 22 23  \
                      10 11 16 5  6  17 20 19 20 21 23 10 4  5  2  3  14 15 16 17 2  3  2  3   \
                      16 17 14 15 2  3  14 15 4  5  4  5  16 17 4  17 18 5 8  7  8 9 23 10  \
                      8  9  20 21 10 11 20 21 8  9  18 19 1  0  2  3  2  15 16 7  6  21 18 19  \
                      13 12 14 15 14 3  4  19 18 9  0  1  6  7  6  7  18 19 20 21 6  7  6  7   \
                      13 12 14 15 14 3  4  19 18 9  0  1  12 13 20 21 12 13 10 11 18 19 10 11  \
                      10 11 22 23 8  9  22 23 8  9  22 23 1  0  2  3  2  15 16 7  6  21 22 23  \
                      )

declare -a dst_module_id
dst_module_id=("${dst_module_id_gaudi[@]}")
declare -a dst_port
dst_port=("${dst_port_gaudi[@]}")

declare -a pci_addrs
declare -a module_ids
declare -a dev_ports
declare -a mac_addrs
declare -a ip_addrs
declare -a tmp_cfg
declare -a tmp_err
dev_ifs=""
verbose=""
data_size_shift=16
db_to=5
num_of_ports=0
run_on_internal_ports=true
run_on_external_ports=true
run_lazy=false
completion_type="cq_usr"
internal_arg=false
external_arg=false
device="GAUDI"
nics_per_dev=10
external_ports="1 8 9"
qps_per_port=1
sob_increment=1
number_of_found_devices=0

cleanup()
{
    for (( i=0; i<$DEV_NUM; i++ )); do
        rm ${tmp_cfg[$i]} ${tmp_err[$i]}
    done
}

init_cfg_files()
{
    local i

    # prepare a test cfg file
    echo "$CFG_STR" > "${tmp_cfg[0]}"

    # edit the cfg file according to our needs
    # use CQ so the test will fail in case of timeout
    replace "${tmp_cfg[0]}" data_size_shift "$data_size_shift"
    replace "${tmp_cfg[0]}" doorbell_to "$db_to"
    replace "${tmp_cfg[0]}" lazy "$1"
    replace "${tmp_cfg[0]}" cmpl "$2"
    if [[ $device == "GAUDI3" ]]; then
        replace "${tmp_cfg[0]}" user_db yes
        #4 sobs are used when user_db is set, due to support of quarter cycles.
        sob_increment=4
    fi

    # copy to all cfg files
    for (( i=1; i<"$DEV_NUM"; i++ )); do
        cp "${tmp_cfg[0]}" "${tmp_cfg[$i]}"
    done
}

replace()
{
    local line
    line=$(grep -n "$2" "$1" | cut -d ":" -f 1)
    sed -i "${line}s/.*/${2}=${3}/" "$1"
}

add_at_end()
{
    local line
    line=$(grep -n "$2" "$1" | cut -d ":" -f 1)
    sed -i "${line}s/$/$3 /" "$1"
}

run_test()
{
    sudo LD_LIBRARY_PATH="$LD_LIBRARY_PATH" -E "$HLTHUNK_RELEASE_BUILD"/bin/nic_root \
                    -s test_nic_e2e -p "$1" -c "$2" 1>/dev/null 2>"$3"
}

get_dst_port_offset()
{
    local __dst_module_id=$1
    local __dst_port=$2
    local __external_ports=$(get_external_ports "$__dst_module_id")
    local __offset_to_reduce=0

    for port in $__external_ports; do
        if ((__dst_port > port)); then
            ((__offset_to_reduce++))
        fi
    done

    echo $((__dst_port - __offset_to_reduce))
}

get_dst_idx()
{
    local __dst_port=$1
    local __ext_en=$2
    local __qps_per_port=$3
    local __dst_idx
    local __nic_idx_in_run=$4
    local __dst_idx2
    local __dst_module_id=$5
    local __port_offset

    if [ $device = "GAUDI" ]; then
       if [ "$__ext_en" -eq 1 ]; then
           if [ "$__dst_port" -eq 1 ]; then
               __dst_idx=0
           elif [ "$__dst_port" -eq 8 ]; then
               __dst_idx=$((__qps_per_port))
           else
               __dst_idx=$((2*__qps_per_port))
           fi
       else
           if [ "$__dst_port" -gt 0 ]; then
               __dst_idx=$(((__dst_port-1)*__qps_per_port))
           else
              __dst_idx=$__dst_port
           fi
       fi
    elif [ $device = "GAUDI2" ]; then
       if [ "$__ext_en" -eq 1 ]; then
           if [ "$__dst_port" -eq 8 ]; then
               __dst_idx=0
           elif [ "$__dst_port" -eq 22 ]; then
               __dst_idx=$((__qps_per_port))
           else
               __dst_idx=$((2*__qps_per_port))
           fi
       else
           if [ "$__dst_port" -gt 8 ]; then
               __dst_idx=$(((__dst_port-1)*__qps_per_port))
           else
              __dst_idx=$((__dst_port*__qps_per_port))
           fi
       fi
    elif [ $device = "GAUDI2-HL288" ]; then
       if [ "$__ext_en" -eq 1 ]; then
           if [ "$__dst_port" -eq 6 ]; then
               __dst_idx=0
           elif [ "$__dst_port" -eq 7 ]; then
               __dst_idx=$((__qps_per_port))
           elif [ "$__dst_port" -eq 8 ]; then
               __dst_idx=$((2*__qps_per_port))
            else
                __dst_idx=$((3*__qps_per_port))
           fi
       else
           if [ "$__dst_port" -gt 6 ]; then
               __dst_idx=$(((__dst_port-4)*__qps_per_port))
           else
              __dst_idx=$((__dst_port*__qps_per_port))
           fi
       fi
    elif [ $device = "GAUDI3" ]; then
       if [ "$__ext_en" -eq 1 ]; then
           __dst_idx=$((__nic_idx_in_run*__qps_per_port))
       else
           __port_offset=$(get_dst_port_offset "$__dst_module_id" "$__dst_port")
           __dst_idx=$((__port_offset*__qps_per_port))
       fi
    else
        echo "script should run on Gaudi/Gaudi2/Gaudi3 HLS machine only"
        exit 1
    fi

    echo "$__dst_idx"
}

get_seed()
{
    local s1 s2 s3 s4
    local _src_module_id=$1
    local _dst_module_id=$2
    local _src_port=$3
    local _dst_port=$4

    if [ "$_src_module_id" -gt "$_dst_module_id" ]; then
      s1=$_src_module_id
      s2=$_dst_module_id
    else
      s1=$_dst_module_id
      s2=$_src_module_id
    fi
    if [ "$_src_port" -gt "$_dst_port" ]; then
      s3=$_src_port
      s4=$_dst_port
    else
      s3=$_dst_port
      s4=$_src_port
    fi

    echo $((1000*s1 + 100*s2 + 10*s3 + s4))
}

run_by_module_ids()
{
    local i j k p
    local __tmp_cfg
    local __dst_module_id
    local __dst_port
    local __dst_mac_addr
    local __dst_ip_addr
    local __seed
    local __ext_en
    local __dst_idx
    local __sob_idx
    local __test_num=1
    local __qps_per_port=$2
    local -a __pid
    local __lazy_cfg=$3
    local __cmpl=$4
    local __nic_idx_in_run

    init_cfg_files "$__lazy_cfg" "$__cmpl"

    if [ "$1" = "external" ]; then
        echo -e "\nrunning on external ports with $__qps_per_port QPs per port,"\
                "completion type: $__cmpl, lazy mode is_on=$__lazy_cfg"
        __ext_en=1
    else
        echo -e "\nrunning on internal ports with $__qps_per_port QPs per port,"\
                "completion type: $__cmpl, lazy mode is_on=$__lazy_cfg"
        __ext_en=0
    fi

    if [ -n "$verbose" ]; then
        echo ""
    fi

    for (( i=0; i<"$DEV_NUM"; i++ )); do
        __nic_idx_in_run=0

        if ! [ -e /sys/class/accel/accel$i/device/module_id ]; then
            continue
        fi

        module_id=$(cat /sys/class/accel/accel$i/device/module_id)
        if [ $device = "GAUDI3" ]; then
            external_ports=$(get_external_ports "$module_id")
            echo "dev $module_id ports $external_ports"
        fi
        for (( j=0; j<"$nics_per_dev"; j++ )); do
            # skip internal/external ports as requested
            echo "$external_ports" | grep -w -q $j
            if [ $? -eq $__ext_en ]; then
                continue
            fi

            k=$((module_id*nics_per_dev+j))

            __dst_module_id=${dst_module_id[$k]}
            __dst_port=${dst_port[$k]}

            # get the dst_port MAC address and dst IP address
            for (( p=0; p<"$num_of_ports"; p++ )); do
                if [ "${module_ids[$p]}" == "$__dst_module_id" ] && \
                    [ "${dev_ports[$p]}" == "$__dst_port" ]; then
                    __dst_mac_addr=${mac_addrs[$p]}
                    __dst_ip_addr=${ip_addrs[$p]}
                    break
                fi
            done

            # generate a unique seed shared by both sides
            __seed=$(get_seed "$module_id" "$__dst_module_id" "$j" "$__dst_port")

            # get the remote data address and SOB indexes
            __dst_idx=$(get_dst_idx "$__dst_port" "$__ext_en" "$__qps_per_port" \
                        "$__nic_idx_in_run" "$__dst_module_id")

            __sob_idx=$(get_dst_idx "$__dst_port" $__ext_en 1 $__nic_idx_in_run "$__dst_module_id")
            # When user_db is used there are 4 sobs instead of 1. Therefore the sob_increment takes
            # care of this configuration dependent setting
            __sob_idx=$((__sob_idx*sob_increment))

            __tmp_cfg=${tmp_cfg[$module_id]}

            # add the relevant test to the cfg file
            add_at_end "$__tmp_cfg" ports "$j"
            add_at_end "$__tmp_cfg" dst_macs "$__dst_mac_addr"
            add_at_end "$__tmp_cfg" dst_ips "$__dst_ip_addr"
            if [ $device = "GAUDI3" ]; then
                if [[ $(("$__dst_port" % 2)) == 1 ]]; then
                    debugfs_fp="/sys/kernel/debug/habanalabs_cn/hbl_cn0/nic_qp_id_offset_in_macro"
                    dst_conn_ids=$((1 + $(sudo cat $debugfs_fp | tr '\0' '\n')))
                    add_at_end "$__tmp_cfg" dst_conn_ids $dst_conn_ids
                else
                    add_at_end "$__tmp_cfg" dst_conn_ids 1
                fi
            else
                add_at_end "$__tmp_cfg" dst_conn_ids 1
            fi
            add_at_end "$__tmp_cfg" qps_per_port "$__qps_per_port"
            add_at_end "$__tmp_cfg" seed "$__seed"
            add_at_end "$__tmp_cfg" remote_sob_idx "$__sob_idx"
            add_at_end "$__tmp_cfg" remote_addr_idx "$__dst_idx"

            if [ -n "$verbose" ]; then
                echo "added test $__test_num: module_id $module_id port $j <->"\
                     "module_id $__dst_module_id port $__dst_port"
                echo "dst_mac $__dst_mac_addr dst_ip $__dst_ip_addr seed $__seed "\
                     "remote_idx $__dst_idx"
                ((__test_num++))
            fi
            ((__nic_idx_in_run++))
        done
    done

    if [ -n "$verbose" ]; then
        echo ""
    fi

    for (( i=0; i<"$DEV_NUM"; i++ )); do
        if ! [ -e /sys/class/accel/accel$i/device/module_id ]; then
            continue
        fi

        module_id=$(cat /sys/class/accel/accel$i/device/module_id)

        if [ -n "$verbose" ]; then
            echo "running test on module_id: $module_id, pci_addr: ${pci_addrs[$module_id]}"
        fi
        run_test "${pci_addrs["$module_id"]}" "${tmp_cfg["$module_id"]}" \
                "${tmp_err["$module_id"]}" &
        __pid["$module_id"]=$!
    done

    for i in "${!__pid[@]}"; do
        if ! wait "${__pid[$i]}"; then
            echo -e "\e[1;31mtest failed on device $i\e[0m"
            for (( j=0; j<"$number_of_found_devices"; j++ )); do
                echo "tmp_err $j:"
                cat "${tmp_err[$j]}"
                echo ""
            done
            exit 1
        fi
    done
}

get_ip_addr()
{
    local nic_mac_addr=$1
    echo $(cat $GAUDI_NET_FILE | \
            grep $nic_mac_addr -A 3 | grep "NIC_IP" | cut -d ":" -f 2 | tr -d '", ')
}

get_gateway_mac_addr()
{
    local nic_mac_addr=$1
    echo $(cat $GAUDI_NET_FILE | \
            grep $nic_mac_addr -A 3 | grep "GATEWAY_MAC" | cut -d ":" -f 2- | tr -d '", ')
}

get_external_ports()
{

    local module_id=$1
    local external_ports

    case $module_id in
    "0")
        external_ports="17 20 21"
        ;;
    "1")
        external_ports="5 8 9"
        ;;
    "2")
        external_ports="5 8 9"
        ;;
    "3")
        external_ports="17 20 21"
        ;;
    "4")
        external_ports="14 15 19"
        ;;
    "5")
        external_ports="2 3 7"
        ;;
    "6")
        external_ports="2 3 7"
        ;;
    "7")
        external_ports="14 15 19"
        ;;
    esac

    echo "$external_ports"
}

# ethtool is needed when running on simulator
if [[ $(command -v ethtool) ]]; then
    echo "ethtool is installed"
else
    echo "installing ethtool"
    sudo apt update
    sudo apt install -y ethtool
    if [[ $? -ne 0 ]]; then
        echo "failed to install ethtool"
        exit 1
    fi
    echo "ethtool was installed successfully"
fi

while [ -n "$1" ];
do
    case $1 in
    --internal-only )
        run_on_internal_ports=true
        run_on_external_ports=false
        internal_arg=true
        ;;
    --external-only )
        run_on_internal_ports=false
        run_on_external_ports=true
        external_arg=true
        ;;
    --lazy )
        run_lazy=true
        ;;
    -c  | --comp )
        shift
        if [ "$1" = "sob" ] || [ "$1" = "cq_usr" ]; then
             completion_type=$1
        else
             echo "Unknown completion type '$1'"
             usage "$0"
             exit 1;
        fi
        ;;
    -q  | --qps-per-port )
        shift
        qps_per_port="$1"
        ;;
    -t  | --timeout )
        shift
        db_to="$1"
        ;;
    -s  | --size )
        shift
        data_size_shift=$1
        ;;
    -h  | --help )
        usage "$0"
        exit 0
        ;;
    -v  | --verbose )
        verbose="yes"
        ;;
    *)
        echo "Error, bad argument '$1'"
        usage "$0"
        exit 1
        ;;
    esac
    shift
done

if [ "$internal_arg" = true ] && [ "$external_arg" = true ]; then
    echo "can't use both --internal-only and --external-only"
    usage "$0"
    exit 1
fi

if [ "$qps_per_port" -le 0 ] || [ "$qps_per_port" -ge 1024 ]; then
    echo "invalid number of QPs per port $qps_per_port"
    usage "$0"
    exit 1
fi

if [ "$db_to" -le 0 ] || [ "$db_to" -gt 10 ]; then
    echo "invalid doorbell timeout of $db_to"
    usage "$0"
    exit 1
fi

if [ "$data_size_shift" -lt 16 ] || [ "$data_size_shift" -gt 30 ]; then
    echo "invalid data size shift of $data_size_shift"
    usage "$0"
    exit 1
fi

echo "timeout: $db_to seconds"
echo "data_size: 1 << $data_size_shift Bytes"

for (( i=0; i<"$DEV_NUM"; i++ )); do
    tmp_cfg["$i"]="$(mktemp -p /tmp/ dev${i}_XXXXXX)"
    tmp_err["$i"]="$(mktemp -p /tmp/ dev${i}_XXXXXX)"
done

# delete the tmp files on exit
trap cleanup EXIT

# get relevant info for all of our interfaces
for (( i=0; i<"$DEV_NUM"; i++ )); do
    dev_id="$i"
    dev_name="accel$dev_id"
    lpbk_path="/sys/kernel/debug/habanalabs_cn/hbl_cn$dev_id/nic_mac_loopback"

    if [ -e /sys/class/accel/accel$i/device/module_id ]; then
        (( number_of_found_devices++ ))
    else
        continue
    fi

    module_id=$(cat /sys/class/accel/accel$dev_id/device/module_id)
    if [ ! -d /sys/class/accel/$dev_name/ ]; then
        echo "$dev_name doesn't exist"
        exit 1
    fi
    lpbk_mask=$(sudo cat $lpbk_path | tr -d '\0')
    if [[ $lpbk_mask != 0x0 ]]; then
        echo "Some ports in $dev_name are in loopback mode."
        echo "Test should not run when ports are in loopback."
        exit 1
    fi
    if [ $i -eq 0 ]; then
        device=$(cat /sys/class/accel/$dev_name/device/device_type)
        if [[ $device == "GAUDI3"* ]]; then
            device="GAUDI3"
        elif [[ $device == "GAUDI2 HL-288"* ]]; then
            device="GAUDI2-HL288"
        elif [[ $device == "GAUDI2"* ]]; then
            device="GAUDI2"
        elif [[ $device == "GAUDI"* ]]; then
            device="GAUDI"
        else
            echo "script should run on Gaudi/Gaudi2/Gaudi3 HLS machine only"
            exit 1
        fi

        echo "device name: $device"

        if [ $device = "GAUDI" ]; then
            nics_per_dev=10
            external_ports="1 8 9"
            dst_module_id=("${dst_module_id_gaudi[@]}")
            dst_port=("${dst_port_gaudi[@]}")
        fi
        if [ $device = "GAUDI2" ]; then
            nics_per_dev=24
            external_ports="8 22 23"
            dst_module_id=("${dst_module_id_gaudi2[@]}")
            dst_port=("${dst_port_gaudi2[@]}")
        fi
        if [ $device = "GAUDI3" ]; then
            nics_per_dev=24
            external_ports=$(get_external_ports "$module_id")
            dst_module_id=("${dst_module_id_gaudi3[@]}")
            dst_port=("${dst_port_gaudi3[@]}")
        fi
        if [ $device = "GAUDI2-HL288" ]; then
            nics_per_dev=22
            external_ports="6 7 8 9"
            dst_module_id=("${dst_module_id_gaudi2_hl288[@]}")
            dst_port=("${dst_port_gaudi2_hl288[@]}")
        fi
    fi
    if [ "$(cat /sys/class/accel/$dev_name/device/status)" != "Operational" ]; then
        echo "$dev_name is not operational"
        exit 1
    fi

    pci_addr=$(cat /sys/class/accel/$dev_name/device/pci_addr)
    module_id=$("$HLTHUNK_RELEASE_BUILD"/bin/control_device -s test_print_hw_ip_info \
            -p "$pci_addr" -d 2>/dev/null | grep "Module ID" | cut -d ":" -f 2 | cut -c 2)
    pci_addrs["$module_id"]=$pci_addr

    dev_ifs=""
    ext_ports_mask=0

    if [ -d /sys/bus/pci/devices/"$pci_addr"/net/ ]; then
        for dev_if in /sys/bus/pci/devices/"$pci_addr"/net/*/; do
            dev_if=$(basename "$dev_if")

            if [ $run_on_external_ports = true ] &&
                [ "$(cat /sys/class/net/"$dev_if"/operstate)" != "up" ]; then
                echo "$dev_if is not up"
                exit 1
            fi

            dev_ifs="$dev_ifs $dev_if"
            dev_port=$(cat /sys/class/net/"$dev_if"/dev_port)
            (( ext_ports_mask |= (1 << "$dev_port") ))
        done
    else
        for dev_if in /sys/class/net/*; do
            dev_if=$(basename "$dev_if")

            # ignore loopback and virtual ethernet devices
            if [ "$dev_if" == "lo" ] || [ "$(echo "$dev_if" | cut -c1-4)" == "veth" ]; then
                continue
            fi

            # ignore characters including and after '@' in interface name
            dev_if=$(echo "$dev_if" | cut -d'@' -f1)

            # ignore NICs which aren't managed by KMD
            if_info=$(ethtool -i "$dev_if")
            if [ $? -ne 0 ]; then
                continue
            fi

            driver_name=$(echo "$if_info" | grep 'driver' | awk '{print $2}')
            if [[ $driver_name != $HABANA_DRIVER_NAME* ]]; then
                continue
            fi

            pci_addr2=$(echo "$if_info" | grep 'bus-info' | awk '{print $2}')
            if [ "$pci_addr" != "$pci_addr2" ]; then
                continue
            fi

            if [ $run_on_external_ports = true ] &&
                [ "$(cat /sys/class/net/"$dev_if"/operstate)" != "up" ]; then
                echo "$dev_if is not up"
                exit 1
            fi

            dev_ifs="$dev_ifs $dev_if"
            dev_port=$(cat /sys/class/net/"$dev_if"/dev_port)
            (( ext_ports_mask |= (1 << "$dev_port") ))
        done
    fi

    if [ $run_on_internal_ports = true ]; then
        set -o pipefail # propagate the error if some problem occurred in the pipe command
        if [ ! -e "$HLTHUNK_RELEASE_BUILD"/bin/control_device ]; then
            echo "File: $HLTHUNK_RELEASE_BUILD/bin/control_device not found." \
                " Did you compile hl-thunk?"
            exit 1
        fi

        dev_ports_mask=$("$HLTHUNK_RELEASE_BUILD"/bin/control_device -s test_get_nic_ports_mask \
                       -p "$pci_addr" -v 2> /dev/null | grep NIC | cut -d " " -f 4)

        if [ $? -ne 0 ]; then
            set +o pipefail
            echo "failed to get ports mask for $dev_name"
            exit 1
        fi
        set +o pipefail

        for (( j=0; j<"$PORTS_NUM_MAX"; j++ )); do
            (( is_port_enable = dev_ports_mask & (1 << "$j") ))
            (( is_port_ext = ext_ports_mask & (1 << "$j") ))
            if [ $is_port_enable -ne 0 ] && [ $is_port_ext -eq 0 ]; then
                module_ids["$num_of_ports"]=$module_id
                dev_ports["$num_of_ports"]=$j
                mac_addrs["$num_of_ports"]="ff:ff:ff:ff:ff:ff"
                ip_addrs["$num_of_ports"]="0"
                (( num_of_ports++ ))
            fi
        done
    fi

    if [ $run_on_external_ports = true ]; then
        for dev_if in $dev_ifs; do
            dev_if=$(basename "$dev_if")

            if [ "$(cat /sys/class/net/"$dev_if"/operstate)" != "up" ]; then
                echo "$dev_if is not up"
                exit 1
            fi

            dev_port=$(cat /sys/class/net/"$dev_if"/dev_port)
            mac_addr=$(cat /sys/class/net/"$dev_if"/address)

            # In case we are working on environment with L3 switches, we will need
            # the dst IP and the mac address of the switch port (gateway MAC) so here
            # we fetch from the gaudinet.json file the IP and the gateway mac address
            # (which will replace the regular mac address) of each port
            if [ -r $GAUDI_NET_FILE ]; then
                ip_addr=$(get_ip_addr "$mac_addr")
                mac_addr=$(get_gateway_mac_addr "$mac_addr")
            else
                ip_addr="0"
            fi

            module_ids["$num_of_ports"]=$module_id
            dev_ports["$num_of_ports"]=$dev_port
            mac_addrs["$num_of_ports"]=$mac_addr
            ip_addrs["$num_of_ports"]=$ip_addr
            (( num_of_ports++ ))
        done
    fi
done

if ! { [ "$number_of_found_devices" = "$DEV_NUM" ] || \
    { [ "$device" = "GAUDI2-HL288" ] && [ "$number_of_found_devices" = 4 ]; }; }; then
    echo "Number of found devices doesn't permit successful test execution," \
        " either use 8 cards or if HL288 use 4 or 8!"
    exit 1
fi

if [ $run_lazy = true ]; then
    __run_lazy="yes"
else
    __run_lazy="no"
fi

if [ $run_on_internal_ports = true ]; then
    run_by_module_ids "internal" "$qps_per_port" "$__run_lazy" "$completion_type"
fi

if [ $run_on_external_ports = true ]; then
    run_by_module_ids "external" "$qps_per_port" "$__run_lazy" "$completion_type"
fi

if [ -n "$DOCKER_CI_ENV" ]; then
        qps_per_port=8
        if [ $run_on_internal_ports = true ]; then
        run_by_module_ids "internal" $qps_per_port "yes" "cq_usr"
        fi

        if [ $run_on_external_ports = true ]; then
        run_by_module_ids "external" $qps_per_port "yes" "cq_usr"
        fi

        if [ $run_on_internal_ports = true ]; then
        run_by_module_ids "internal" $qps_per_port "yes" "sob"
        fi

        if [ $run_on_external_ports = true ]; then
        run_by_module_ids "external" $qps_per_port "yes" "sob"
        fi
fi
echo -e "\n${GREEN}all tests passed${NC}"

exit 0
