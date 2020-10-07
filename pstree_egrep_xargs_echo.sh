#! /usr/bin/env bash
# pstree -p $$ | egrep -o "[0-9]+" | xargs
processes(){
	pstree -p $$ >/dev/null
}

flarf(){
	# just echo some weird stuff
	echo just saying
	echo some weird
	echo stuff in
	echo this function
}

filter(){
	grep "f"
}

processes | flarf | filter | xargs
