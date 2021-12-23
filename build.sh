#!/bin/bash - 
#===============================================================================
#
#          FILE: build.sh
# 
#         USAGE: ./build.sh 
# 
#   DESCRIPTION: THIS NEEDS ACTUAL FLOW CONTROL AND STUFF 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: YOUR NAME (), 
#  ORGANIZATION: 
#       CREATED: 19/12/21 17:08
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

# build

docker build . -t cve-build-image

# check for container 
docker rm -f dummy

# build dummy
docker create -it --name dummy cve-build-image /bin/bash

# copy build out of it 
docker cp dummy:/work/loguccino .

# clean up
docker rm -f dummy
