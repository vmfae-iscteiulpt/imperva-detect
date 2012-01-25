#!/bin/bash
#####################################################################################
#
# check_ciphers.sh - Determine ciphers supported by an SSL-enabled web server
#
# Author  - Lamar Spells (lamar.spells@gmail.com)
# Blog    - http://foxtrot7security.blogspot.com
# Twitter - lspells
#
# Copyright (c) 2012, Lamar Spells
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   - Redistributions of source code must retain the above copyright notice, this
#     list of conditions and the following disclaimer.
#   - Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################################

if [ $# -lt 1 ] ; then
   echo "USAGE: `basename $0` <ip> [port]"
   exit 1
fi

if [ $# -eq 1 ] ; then
  SERVER=${1}:443
else
  SERVER=${1}:${2}
fi
DELAY=1

echo Obtaining cipher list from `openssl version`.
ciphers=`openssl ciphers 'ALL:eNull' | tr -s ':' '\012' | sort -u | tr '\012' ' '`

for cipher in ${ciphers[@]}
do
echo -n $cipher...
result=`echo -n | openssl s_client -cipher "$cipher" -connect $SERVER 2>&1`
if [[ "$result" =~ "Cipher is " ]] ; then
  echo YES
else
  if [[ "$result" =~ ":error:" ]] ; then
    error=`echo -n $result | cut -d':' -f6`
    echo NO \($error\)
  else
    echo UNKNOWN RESPONSE
    echo $result
  fi
fi
sleep $DELAY
done
