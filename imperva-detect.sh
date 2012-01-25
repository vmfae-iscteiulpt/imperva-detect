#!/bin/bash
#####################################################################################
#
# imperva-detect.sh - Tool to verify presence of an Imperva application firewall
# This script functions by running a baseline test + 5 additional tests 
# against a user-specified website. Tests include the following:
#    Test 0 - Baseline to establish expected behavior
#    Test 1 - "Web Leech" blocking
#    Test 2 - "E-mail Robot" blocking
#    Test 3 - BlueCoat Proxy Manipulation blocking
#    Test 4 - Web Worm blocking
#    Test 5 - XSS blocking
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

# Global Variable
DEF_AGENT="Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"

function usage ()
{
   echo "`basename $0`: <Base URL to test>"
   echo "   Example:          `basename $0` http://www.example.com"
   echo "   Another Example:  `basename $0` https://secure.example.com"
}

function make_request ()
{
   # Input only parameters
   local AGENT=$1
   local URL=$2
   
   http_code=""
   size_download=""
   url_effective=""
 
   xx=`curl -s -k -A "$AGENT" -w "%{http_code} %{size_download} %{url_effective}\\n" "$URL" -o /dev/null | grep ^[0-9]` 

   http_code=`echo $xx | awk '{print $1}'`
   size_download=`echo $xx | awk '{print $2}'`
   url_effective=`echo $xx | awk '{print $3}'`
}

function url_hostname_to_ip ()
{
   local xx=""
   local host=""
   local method=""
   local ip=""

   method=`echo $1 | awk -F: '{print $1}'`
   host=`echo $1 | awk -F/ '{print $NF}'`

   # Check to see if we have an IP aleady...
   xx=`echo $host | grep [A-Z,a-z]`
   if [ "$xx" = "" ] ; then
      # We have an IP already... bail out here.
      new_url="${method}://${host}"
      return 0
   fi 
   xx=""

   # If we have a hostname, not an IP, look it up.
   ip=`nslookup $host | grep Address | tail -1 | awk '{print $NF}'` 
   xx=`echo $ip | grep '#53'`
   if [ "$xx" != "" ] ; then
      new_url=""
      return 1
   else 
      new_url="${method}://${ip}"
      return 0
   fi
}

function compare_baseline ()
{
   local l_http_code=$1
   local l_size_download=$2

   if [ $l_http_code -ne 200 ] ; then
      echo "  -- HTTP Return Code [$l_http_code] encountered - application firewall possibly present"
      appfw_indicator=$((appfw_indicator+1))
   else
      if [ $t0_size_download -ne $l_size_download ] ; then
         echo "  -- Size of content inconsistent versus Test 0 - application firewall possibly present"  
         echo "  -- Details:  Test 0 Size = $t0_size_download Size Recvd = $l_size_download"
         appfw_indicator=$((appfw_indicator+1))
      else
         echo "  -- HTTP Reutrn Code  = $l_http_code & downloaded content size is the same -- application firewall not detected"
      fi
   fi
}

function test_xss_block ()
{
   make_request "$DEF_AGENT" "$BASE_URL/javascript:alert('XSS');"
   if [[ $http_code -eq 404 || $http_code -eq 400 ]] ; then
      echo "  -- HTTP Return Code = $http_code -- application firewall probably not present"
   else
      echo "  -- HTTP Return Code = $http_code -- while checking XSS blocking"
      appfw_indicator=$((appfw_indicator+1))
   fi
}

###  MAIN main Main script logic

if [ $# -ne 1 ] ; then
  usage
  exit 1
fi
BASE_URL="$1"

appfw_indicator=0

echo " "
echo "--- Testing [$BASE_URL] for presence of application firewall ---"
echo " "

#  Run the various tests....
echo "Test 0 - Good User Agent... "
make_request "$DEF_AGENT" "$BASE_URL" 
t0_http_code=$http_code
t0_size_download=$size_download

if [ $t0_http_code -ne 200 ] ; then
   test_xss_block
   if [ $appfw_indicator -eq 1 ] ; then
     echo "--- Tests Finished on [$BASE_URL] -- Baseline failed but site blocks XSS. App FW may be present ---"
   else
     echo "--- Tests Finished on [$BASE_URL] -- Cannot establish baseline: HTTP Return Code [$t0_http_code] ---" 
   fi
   exit 1
fi
echo "  -- HTTP Return Code = $t0_http_code"
echo "  -- Content Size Downloaded = $t0_size_download"

echo "Test 1 - Web Leech User Agent... "
make_request "Mozilla/4.7 (compatible; OffByOne; Windows 2000) Webster Pro V3.4" $BASE_URL
compare_baseline $http_code $size_download

echo "Test 2 - E-mail Collector Robot User Agent Blocking..."
make_request "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; DTS Agent" $BASE_URL
compare_baseline $http_code $size_download

echo "Test 3 - BlueCoat Proxy Manipulation Blocking... "
make_request "$DEF_AGENT" "$BASE_URL/notified-testnotify"
if [[ $http_code -eq 404 ]] ; then
   echo "  -- HTTP Return Code = $http_code -- application firewall probably not present"
else
   echo "  -- HTTP Return Code = $http_code -- expected 404 -- application firewall possibly present"
   appfw_indicator=$((appfw_indicator+1))
fi

echo "Test 4 - Web Worm Blocking... "
url_hostname_to_ip "$BASE_URL"
make_request "$DEF_AGENT" "$new_url" 
compare_baseline $http_code $size_download

echo "Test 5 - XSS Blocking... "
test_xss_block

echo " "
echo "--- Tests Finished on [$BASE_URL] -- ${appfw_indicator} out of 5 tests indicate Imperva application firewall present ---"
exit $appfw_indicator

