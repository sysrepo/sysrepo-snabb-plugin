#!/bin/bash

# Requirements
# Before running this script make sure these requirements are satisfied
# Compile the sysrepo-snabb-plugin in the root directory of this project
# Install snabb on your system

set -e

# Get the bare minimum config and veth setup script
if [ ! -e lwaftr-veth-env.sh ]; then
	curl 'https://raw.githubusercontent.com/snabbco/snabb/master/src/program/lwaftr/doc/tutorial/lwaftr-veth-env.sh' \
		> lwaftr-veth-env.sh
fi

if  [ ! -e ./config/lwaftr-start.conf ]; then
	mkdir config
	curl 'https://raw.githubusercontent.com/snabbco/snabb/master/src/program/lwaftr/doc/tutorial/lwaftr-start.conf' \
		> ./config/lwaftr-start.conf
fi


# create venv with dependencies
if [ ! -d test-venv ];then
	export LIBYANG_HEADERS=/usr/local/include
	export LIBYANG_LIBRARIES=/usr/local/lib
	export SYSREPO_HEADERS=/usr/local/include
	export SYSREPO_LIBRARIES=/usr/local/lib 
	python -m venv test-venv && source test-venv/bin/activate && pip install -r requirements.txt
fi

# Run the veth setup script
sh lwaftr-veth-env.sh create
