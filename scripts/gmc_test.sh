#!/bin/bash

################################################################################
#
# Automatic testing script for graphic memory compression solutions.
# Author: Sergei V. Rogachev (s.rogachev@samsung.com), 2016.
#
# Available tests:
#
# ratio: print compression ratio
# saved: print saved memory
# sluggish_1: measure pagefault overhead by running and backgrounding of apps
# sluggish_2: measure performance gain because of saved memory
#
################################################################################

# Configuration. ###############################################################

conf_debug_path="/sys/kernel/debug" # Path to the mountpoint of debugfs.
conf_api="gmc"   # Can be equal to "gmc" or "nmc" depending on the version.

# List of applications for sluggish test.
conf_app_list=$(cat <<-EOM
org.tizen.setting
org.tizen.myfile
org.tizen.calendar
org.tizen.browser
org.tizen.gallery
org.tizen.email
EOM)

# Application started to background others.
conf_app_background="org.tizen.homescreen-efl"

# Time to sleep between runs of apps in sluggish test.
conf_sleep=1

# Number of iterations for sluggish test.
conf_nr_iters=10

# Globals. #####################################################################

glo_app_name="gmc_test"

test_init() {
	conf_debug_compress="${conf_debug_path}/${conf_api}/compress"
	conf_debug_decompress="${conf_debug_path}/${conf_api}/decompress"
	conf_debug_stat="${conf_debug_path}/${conf_api}/storage_stat"
	conf_debug_compress_all="${conf_debug_path}/mali/unmap_buf"
}

read_stat() {
	input=$(cat $conf_debug_stat)

	compr_data_size=$(echo "$input" | grep Compressed | awk '{ print $4 }')
	nr_zero=$(echo "$input" | grep Zeroed | awk '{ print $3 }')
	nr_pages=$(echo "$input" | grep Pages | awk '{ print $3 }')
}

compress() {
	echo -n "Try to compress graphic memory... "
	echo 1 > "$conf_debug_compress_all"
	echo "[done]"
}

start_app() {
	time su owner -c "launch_app $1"
}

background_app() {
	start_app $conf_app_background > /dev/null 2> /dev/null
}

test_sluggish_1() {
	echo "# Test running ovehead (sluggish 1) #"

	iter=0

	while [ $iter -ne $conf_nr_iters ]; do
		for app in $(echo "$conf_app_list"); do
			echo "Start app $app"
			start_app $app
			echo
			sleep $conf_sleep
			background_app
			sleep $conf_sleep
		done
		let "iter = $iter + 1"
	done

	echo "[done]"
}

test_sluggish_2() {
	echo "# Test speed gain (sluggish 2) #"

	iter=0

	while [ $iter -ne $conf_nr_iters ]; do
		for app in $(echo "$conf_app_list"); do
			echo "Start app $app"
			start_app $app
			echo
		done
		let "iter = $iter + 1"
	done

	echo "[done]"
}

start_apps() {
	echo "Running apps..."

	for app in $(echo "$conf_app_list"); do
		echo "Start app $app"
		start_app $app
		echo
		sleep $conf_sleep
	done

	background_app
	sleep $conf_sleep

	echo "[done]"
}

test_saved() {
	echo "# Test quantity of saved memory #"

	start_apps

	compress
	read_stat

	let "all_data_size = $nr_zero + $nr_pages"
	let "all_data_size = $all_data_size * 4096"
	let "result = $all_data_size - $compr_data_size"
	let "result_mb = $result / 1024 / 1024"

	echo "Quantity of saved memory: $result Bytes, $result_mb Megabytes."
}

test_ratio() {
	echo "# Test compression ratio #"

	start_apps

	compress
	read_stat

	let "all_data_size = $nr_zero + $nr_pages"
	let "all_data_size = $all_data_size * 4096"
	let "result = $all_data_size / $compr_data_size"
	let "result_percent = 100 - ($compr_data_size * 100 / $all_data_size)"

	echo "Compression ratio: $result times, $result_percent%."
}

# Implementation. ##############################################################

error() {
	echo "ERROR: " $1
}

usage() {
umessage=$(cat <<-EOM
$glo_app_name - a testing application for graphic memory compression solution.

Requires one argument - name of the test.
Possible names: saved, ratio, sluggish_1, sluggish_2.
EOM)

	echo "$umessage"
}

glo_app_name=$(basename $0)

if [ $# -ne 1 ]; then
	error "Invalid number of parameters."
	usage
	exit 1
fi

test_init

case $1 in
	"saved")
		test_saved
		;;
	"ratio")
		test_ratio
		;;
	"sluggish_1")
		test_sluggish_1
		;;
	"sluggish_2")
		test_sluggish_2
		;;
	*)
		error "Unknown test name."
		usage
		exit 1
esac
