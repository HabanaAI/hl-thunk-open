#!/bin/bash

if [[ $# < 3 || $# > 4 ]] ; then
        echo "Bad input."
        echo "Usage: $(basename $0) <reg_module> <reg_name> <reg_value> num_max_die (1/2 - optional, default 2)>"
        echo "e.g. $(basename $0) TXE WQE_CHECK_EN 0xFF"
        exit 1
fi

reg_module=$1
reg_name=$2
reg_value=$3
num_max_die=$((${4:-2} - 1))

echo -n > $1.txt

for ((i=0; i <= $num_max_die; i++));
do
   for j in {0..5}
   do
      echo "writereg32 D"$i"_NIC"$j"_"$reg_module $reg_name $reg_value >> $1.txt
   done
done
