#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2024 HabanaLabs, Ltd.
# All Rights Reserved.
#

TESTS_DIR=$HLTHUNK_ROOT/tests
TEST_STDOUT_FILE="$HABANA_LOGS/hlthunk_test.log"
CORAL_STDOUT_FILE="$HABANA_LOGS/coral_stdout.log"
CORAL_STDERR_FILE="$HABANA_LOGS/coral_stderr.log"
DEVICE_NUMBER=0
DEVICE_STATUS_FILE="/sys/class/accel/accel${DEVICE_NUMBER}/device/status"

TIMEOUT=60s

# Arguments
SIM=false

# Coral arguments
CORAL_DEVICE=""
CORAL_DRAM=""
CORAL_RELEASE=""

# Test arguments
TEST_DEVICE=""
TEST_RELEASE=""

function usage() {
    echo -e "Starts a test and resets the device mid-test, then re-runs the test to verify \
successful recovery."
    echo -e "Usage: $0 [options] -- [run_rdma_test options]"
    echo -e "options:"
    echo -e "  -h            Print this help"
    echo -e "  -r            Run everything in release mode"
    echo -e "  -s            Run using simulator, requires '-C device'"
    echo -e "  -C device     Device to simulate (gaudi/gaudi2/gaudi2b/gaudi2c/gaudi3/gaudi3_1d)"
    echo -e "  -D dram       DRAM size in GB (default: 4)"
}

function log() {
    echo "[$(date +"%Y.%m.%d %H:%M:%S.%3N")]" "$1"
}

function run_timeout() {
    if ! timeout -k $TIMEOUT $TIMEOUT bash -c "$*"; then
        log "Timed out!"
        cleanup_and_exit 1
    fi
}

function __wait_until_device_operational() {
    while [[ ! -f $DEVICE_STATUS_FILE ]]; do
        sleep 0.1
    done

    while [[ "$(cat $DEVICE_STATUS_FILE)" != "Operational" ]]; do
        sleep 0.1
    done
}

function wait_until_device_operational() {
    export -f __wait_until_device_operational
    export DEVICE_STATUS_FILE
    run_timeout __wait_until_device_operational $1
}

function __wait_until_device_removed() {
    while [[ -f $DEVICE_STATUS_FILE ]]; do
        sleep 0.1
    done
}

function wait_until_device_removed() {
    export -f __wait_until_device_removed
    export DEVICE_STATUS_FILE
    run_timeout __wait_until_device_removed $1
}

function hard_reset() {
    log "Performing hard-reset!"
    echo 1 | sudo tee /sys/class/accel/accel${DEVICE_NUMBER}/device/hard_reset >/dev/null

    log "Waiting for device to finish resetting"
    wait_until_device_operational

    log "Device reset successfully"
}

function kill_sim() {
    coral_pid=$(
        cat $CORAL_STDOUT_FILE |
            grep "Simulation PID:" |
            tr -s " " |
            cut -d " " -f 3
    )

    log "Killing coral, PID: [$coral_pid]"

    kill -9 $coral_pid

    log "Waiting for device to be removed"
    wait_until_device_removed

    log "Simulator killed"
}

function start_sim() {
    log "Starting simulator"
    bash -e $HABANA_SCRIPTS_FOLDER/habana_functions.sh \
        run_coral_sim \
        $CORAL_DEVICE \
        $CORAL_DRAM \
        $CORAL_RELEASE \
        -b \
        >$CORAL_STDOUT_FILE \
        2>$CORAL_STDERR_FILE

    log "Waiting for simulator to start"
    wait_until_device_operational

    log "Simulator started"
}

function configure_ports() {
    log "Bringing up ports"
    bash -c "$NETWORK_SCRIPTS_FOLDER/manage_network_ifs.sh --up" >/dev/null

    log "Ports up"

    log "Switching device to MAC loopback"
    echo 0xFFFFFF |
        sudo tee /sys/kernel/debug/habanalabs_cn/hbl_cn${DEVICE_NUMBER}/nic_mac_loopback \
            >/dev/null

    log "MAC loopback enabled"
}

function set_device_number() {
    local EXISTING_NUMBERS=$(ls /sys/class/accel/ |
        grep -E '^accel[[:digit:]]+$' |
        grep -Eo '[[:digit:]]+$' || echo "")

    DEVICE_NUMBER=0

    # Keep incrementing device number until we find first available slot.
    while [[ $(echo "${EXISTING_NUMBERS[@]}" | grep -E "^${DEVICE_NUMBER}$") ]]; do
        DEVICE_NUMBER=$((DEVICE_NUMBER + 1))
    done
}

function cleanup() {
    log "Cleaning up"
    sudo kill -9 $TEST_PID 2>/dev/null

    if [[ $SIM == true ]]; then
        kill_sim
    fi
}

function cleanup_and_exit() {
    if [[ ! -v EXITING ]]; then
        EXITING=true
        cleanup
    fi

    if [[ $SIM == true ]]; then
        echo "coral stdout:"
        cat "$CORAL_STDOUT_FILE" 2>/dev/null
        echo "coral stderr:"
        cat "$CORAL_STDERR_FILE" 2>/dev/null
    fi

    exit $1
}

function trap_cleanup() {
    trap - INT
    log "Caught trap, exiting"
    cleanup_and_exit 130
}

function parse_arguments() {
    # Parse arguments
    while getopts "hrsC:D:" opt; do
        case $opt in
        r)
            CORAL_RELEASE="-r"
            TEST_RELEASE="--release"
            ;;
        s)
            SIM=true
            ;;
        C)
            CORAL_DEVICE="-C $OPTARG"
            case $OPTARG in
            gaudi)
                TEST_DEVICE="--dev_type H3"
                ;;
            gaudi2 | gaudi2b | gaudi2c)
                TEST_DEVICE="--dev_type H6"
                ;;
            gaudi3 | gaudi3_1d)
                TEST_DEVICE="--dev_type H9"
                ;;
            *)
                echo "Invalid device $OPTARG"
                usage $1
                exit 1
                ;;
            esac
            ;;
        D)
            CORAL_DRAM="-D $OPTARG"
            ;;
        h)
            usage "$1"
            exit 0
            ;;
        *)
            echo "Invalid option: --$OPTARG" >&2
            usage $1
            exit 1
            ;;
        esac
    done

    # Validate arguments
    if [[ $SIM == true && -z "$CORAL_DEVICE" ]]; then
        echo "-s option requires '-C device'"
        usage $1
        exit 1
    fi

    # Remove parsed arguments
    shift $((OPTIND - 1))

    TEST_COMMAND="$TESTS_DIR/common/run_rdma_test.sh --loopback $TEST_DEVICE $TEST_RELEASE $*"
}

function main() {
    parse_arguments $@

    # Arrange
    if [[ $SIM == true ]]; then
        set_device_number

        DEVICE_STATUS_FILE="/sys/class/accel/accel${DEVICE_NUMBER}/device/status"

        log "Will use accel${DEVICE_NUMBER}"
        TEST_COMMAND="$TEST_COMMAND --dev_number1 ${DEVICE_NUMBER}"

        start_sim
    else
        hard_reset
    fi

    wait_until_device_operational

    configure_ports

    # Act + Assert
    log "Starting test"
    timeout -k $TIMEOUT $TIMEOUT $TEST_COMMAND --iteration 10 >$TEST_STDOUT_FILE 2>&1 &
    TEST_PID=$!

    # Wait until the test actually started doing things before performing the hard reset.
    timeout -k $TIMEOUT $TIMEOUT tail -f $TEST_STDOUT_FILE | grep -m 1 'send job' >/dev/null
    res=$?

    if [[ $res -eq 0 ]]; then
        log "Test running"
    else
        log "Test failed to start! exit code: [$res], stdout:"
        cat $TEST_STDOUT_FILE
        cleanup_and_exit 1
    fi

    if [[ $SIM == true ]]; then
        kill_sim
    else
        hard_reset
    fi

    wait $TEST_PID
    res=$?

    if [[ $res -eq 0 ]]; then
        log "Test didn't fail! stdout:"
        cat $TEST_STDOUT_FILE
        cleanup_and_exit 1
    else
        log "Test failed successfully! exit code: [$res]"
    fi

    if [[ $SIM == true ]]; then
        start_sim
    fi

    wait_until_device_operational

    configure_ports

    log "Running test again..."

    timeout -k $TIMEOUT $TIMEOUT $TEST_COMMAND >$TEST_STDOUT_FILE 2>&1
    res=$?

    if [[ $res -eq 0 ]]; then
        log "Test passed successfully!"
    elif [[ $res -eq 124 ]]; then
        log "Test timed out! stdout:"
        cat $TEST_STDOUT_FILE
        cleanup_and_exit 1
    else
        log "Test failed! exit code: [$res], stdout:"
        cat $TEST_STDOUT_FILE
        cleanup_and_exit 1
    fi

    cleanup

    log "SUCCESS"
}

main $@
