#!/bin/bash

# Path to your CSV file
csv_file=$1
filename=$(basename -- "$csv_file")
filename="${filename%.*}"
bitmask_hex="${filename##*_}"
bitmask_dec=$((bitmask_hex))

# Print offset spaces (align header to the rest of the data)
line_count=$(wc -l < "$csv_file")
offset=${#line_count}  # Number of digits in the line count
printf "qp\u2193 port\u2192%${offset}s" ""

# Print header of column numbers
for ((i=0; i<63; i++)); do
    if (( (bitmask_dec & (1 << i)) != 0 )); then
        if ((i<10)); then
            printf "%d  " "$i"
        else
            printf "%d " "$i"
        fi
    fi
done
printf "\n"

# Print content of the CSV file with row numbers
awk '{
    printf "%d       ,", NR;  # Print row number
    print $0;          # Print the rest of the row
}' FS="," "$csv_file" | column -t -s ','
