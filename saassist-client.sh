#!/bin/ksh
#
# Copyright 2016, 2017 Kairo Araujo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

version='0.1'


if [ -f ./client_config ]; then
    . ./client_config
else
    echo "[ERROR] The 'client_config' file needs to be in"
    echo "the same directory of saassist-client"
    exit 1
fi

# Basic variables
server_version=$(oslevel -r)
server_release=$(oslevel -s | awk -F'-' '{ print $1"-"$2"-"$3 }')
server_url="http://$SAA_SERVER:$SAA_PORT/"
secid_url="$server_url$2/"
secid_url_version="$secid_url$server_version/"

# check if there is a emgr lock file
if [ -f /var/locks/emgr.lock ]; then
    echo "[ERROR] SAAssist found a emgr lock file /var/locks/emgr.lock"
    echo "        Check if process $(cat /var/locks/emgr.lock) exists and remove file"
    exit 1
fi

# Function to check if SAA Server is ready using NFS
function _check_APAR_nfs {
        echo "[CLIENT] Verifying SAA Server over NFS"

        #find_nfs=$(df -k | grep : | grep ${SAA_SERVER})
        if [ $? -ne 0 ]; then
            echo "[CLIENT] Filesystem ${SAA_FILESYTEM} not found"
            echo "[CLIENT] Trying to mount..."
            if [ ! -d ${SAA_FILESYSTEM} ]; then
                mkdir -p ${SAA_FILESYSTEM}
            fi
            mount ${SAA_SERVER}:${SAA_FILESYSTEM} ${SAA_FILESYSTEM}
            if [ $? -eq 0 ]; then
                echo "[CLIENT] Filesystem ${SAA_FILESYTEM} ready to be used"
            else
                echo "[ERROR] Please, check the NFS server or name resolution"
                exit 1
            fi
        fi
}

# Function to check if SAA Server is ready using HTTP
function _check_APAR_http {

    echo '[CLIENT] Verifying SAA Server over HTTP'

    # check if curl is installed, this required by HTTP Protocol
    curl_path='which curl'
    if [ $? -ne 0 ]; then
        echo '[ERROR] Command curl is required to use protocol HTTP'
        echo '        Please install curl, include on the PATH or try to use NFS '
        echo '        protocol on client_config'
    fi

    # test HTTP connection with SAA Server
    http_test=$(curl -o /dev/null -sSf ${server_url})

    if [ $? -ne 0 ]; then
        echo "[ERROR] HTTP Connection failed"
        exit 1
    else
        echo "[CLIENT] HTTP Connection OK"
    fi

}

# function to check if the temporally fs is ready to be used
# the temporally filesystem came from client_config file
function _check_tmp_dir {

    if [ ! -d $SAA_TMP_DIR ]; then
        echo "[ERROR] Check the client_config SAA_TMP_DIR."
        echo "        Directory doesn't exist."
        exit 1
    fi

    if [ ! -d $SAA_TMP_DIR/$1 ]; then
            mkdir -p $SAA_TMP_DIR/$1
    fi
}
# function to check CVE/IV on server
function _check_secid {

    # check if APAR fix is available on http/nfs server
    if [ ${SAA_PROTOCOL} == 'http' ]; then
        secid_test=$(curl -o /dev/null -s -I -f ${secid_url})
        rc=$?
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        secid_test=$(ls -ld ${SAA_FILESYSTEM}/$1 > /dev/null 2>&1)
        rc=$?
    fi

    if [ $rc -ne 0 ]; then
        echo "[CLIENT] The CVE/IV $1 is not available on server $SAA_SERVER."
        echo
        echo "         This APAR was not processed by SAAssist Server or not"
        echo "         exists."
        echo "         - Check if APAR ID $1 is correct"
        echo "         - Check with Security APAR Assistant server"
        echo "         administrator if that APAR is already available."
        echo
        exit 1

    else
        # if available, check if the version is affected
        echo "[CLIENT] Retrieving APAR $1 info from ${SAA_SERVER}"
        echo "[CLIENT] Checking if CVE/IV is applicable for OS version $(oslevel -r)"
        if [ ${SAA_PROTOCOL} == 'http' ]; then
            secid_version_test=$(curl -o /dev/null -s -I -f ${secid_url_version})
            rc=$?
        fi

        if [ ${SAA_PROTOCOL} == 'nfs' ]; then
            secid_version_test=$(ls -ld ${SAA_FILESYSTEM}/$1/$server_version > /dev/null 2>&1)
            rc=$?
        fi
        if [ $rc -ne 0 ]; then
            echo "      \`- The version $(oslevel -r) is not affected by $1"
            system_affected='False'
        else
            echo "      \`- This server is affected by $1"
            if [ ${SAA_PROTOCOL} == 'http' ]; then
                curl -s ${secid_url_version}/$1.info -o ${SAA_TMP_DIR}/$1/$1.info
                rc=$?
            fi

            if [ ${SAA_PROTOCOL} == 'nfs' ]; then
                cp ${SAA_FILESYSTEM}/$1/$server_version/$1.info ${SAA_TMP_DIR}/$1/$1.info > /dev/null 2>&1
                rc=$?
            fi

            if [ $rc -ne 0 ]; then
                echo "[ERROR] Failed to saved the $1.info file"
                exit 1
            fi
            . /${SAA_TMP_DIR}/$1/$1.info
            system_affected='True'

        fi

        # if the version is affected next step is check with the release is
        # affected
        if [ $system_affected == 'True' ]; then
            echo "[CLIENT] Checking if CVE/IV is applicable for OS release $server_release"
            for release in ${AFFECTED_RELEASES}; do
                if [ "$release" == "$server_release" ]; then
                    system_affected='True'
                fi
            done

            if [ "$system_affected" == 'False' ]; then
                echo "      \`- $server_release is not affected by $1"
            else
                echo "      \`- $server_release is affected by $1"
            fi
        fi

        # if the release is affected, check if the fix is already installed
        # by some TL or SP
        if [ $system_affected == 'True' ]; then
            echo "[CLIENT] Checking if there are APARs already applied"
            for iv in ${REMEDIATION_APARS}; do
                if [ $(echo $1 | cut -c1-2) == "IV" ]; then
                    iv_ver="$(echo $AFFECTED_RELEASES | awk '{ print $1 }' | cut -c1).$(echo $AFFECTED_RELEASES | awk '{ print $1 }' | cut -c2)"
                else
                    iv_ver=$(echo "$iv" | awk -F. '{ print $1"."$2 }')
                fi
                os_ver=$(oslevel | awk -F'.' '{ print $1"."$2 }')
                if [ "$iv_ver" == "$os_ver" ]; then
                    if [ $(echo $1 | cut -c1-2) == "IV" ]; then
                        apar_name=$1
                    else
                        apar_name=$(echo ${iv} | /usr/bin/awk -F':' '{ print $2 }')
                    fi
                    instfix -ik "$apar_name" > /dev/null 2>&1
                    if [ $? -eq 0 ]; then
                        echo "      \`- $apar_name is already installed"
                        system_affected='False'
                    else
                        echo "      \`- $apar_name is NOT installed"
                        system_affected='True'
                        break
                    fi
                fi
            done
        fi

        # if the IV is not already installed, check if some APAR fix is ready
        # to be installed, it means that iFIX is compatible
        if [ ${system_affected} == "True" ]; then
            echo "[CLIENT] This system is AFFECTED by $1"
            echo "      \`- Downloading APAR to $SAA_TMP_DIR"
            for apar in ${APAR_FIX}; do
                apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')

                if [ ${SAA_PROTOCOL} == 'http' ]; then
                    curl -s $secid_url_version/$apar_fix -o $SAA_TMP_DIR/$1/$apar_fix
                    rc=$?
                fi

               if [ ${SAA_PROTOCOL} == 'nfs' ]; then
                    cp ${SAA_FILESYSTEM}/$1/$server_version/$apar_fix ${SAA_TMP_DIR}/$1/$apar_fix > /dev/null 2>&1
                    rc=$?
                fi


                if [ $rc -ne 0 ]; then
                    echo "[ERROR] Failed to download ${apar_fix}"
                    exit 1
                fi
            done

            apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')
            apar_dir=$(echo $apar_fix | awk -F'.' '{ print $1 }')
            cd ${SAA_TMP_DIR}/$1
            if [ $(echo $apar_fix | awk -F'.' '{ print $NF }') == 'tar' ]; then
                tar xvf $apar_fix > /dev/null 2>&1
                cd $apar_dir
            fi

            for file in $(ls | grep epkg.Z | grep -v sig); do
                echo "      \`- Running $file preview "
                preview_cmd=$(emgr -p -e $file 2>&1)
                if [ $? -eq 0 ]; then
                    echo "      \`- APAR $file is APPLICABLE to the system"
                    system_affected_allv='True'
                    break
                else
                    efix_locked=$(echo "$preview_cmd" | grep "locked by efix")
                    if [ $? -eq 0 ]; then
                        echo "      \`- APAR $file is APPLICABLE to the system"
                        system_affected_allv='True'
                        break
                    else
                        echo "      \`- APAR $file is NOT applicable to the system"
                        system_affected_allv='False'
                    fi
                fi
            done
        fi

    fi

}

# function to check if there the APAR is for ALL version.
# this is updates for OpenSSL, OpenSSH, Java -- 'non-natives' AIX/PowerVM
# filesets and is better check for all versions. It is not for specific version
function _check_secid_allv {

    secid_url_all="${secid_url}ALL"
    if [ ${SAA_PROTOCOL} == 'http' ]; then
        secid_version_test=$(curl -o /dev/null -s -I -f ${secid_url_all})
        rc=$?
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        secid_version_test=$(ls -ld ${SAA_FILESYSTEM}/$1/ALL > /dev/null 2>&1)
        rc=$?
    fi

    if [ $rc -eq 0 ]; then
        # if available, check if the version is affected

        echo "[CLIENT] Retrieving APAR $1 info from ${SAA_SERVER}"
        if [ ${SAA_PROTOCOL} == 'http' ]; then
            curl -s ${secid_url_all}/$1.info -o ${SAA_TMP_DIR}/$1/$1.info
            rc=$?
        fi

        if [ ${SAA_PROTOCOL} == 'nfs' ]; then
            cp ${SAA_FILESYSTEM}/$1/ALL/$1.info ${SAA_TMP_DIR}/$1/$1.info > /dev/null 2>&1
            rc=$?
        fi

        if [ $rc -ne 0 ]; then
            echo "[ERROR] Failed to saved the $1.info file"
            exit 1
        fi
        . /${SAA_TMP_DIR}/$1/$1.info
        system_affected_allv='True'

        echo "[CLIENT] Was detected that this APAR also is not for a specific AIX/PowerVM"
        echo "         -> ${APAR_ABSTRACT}"

        for apar in ${APAR_FIX}; do
            apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')

            if [ ${SAA_PROTOCOL} == 'http' ]; then
                curl -s $secid_url_all/$apar_fix -o $SAA_TMP_DIR/$1/$apar_fix
                rc=$?
            fi

            if [ ${SAA_PROTOCOL} == 'nfs' ]; then
                cp ${SAA_FILESYSTEM}/$1/ALL/$apar_fix ${SAA_TMP_DIR}/$1/$apar_fix > /dev/null 2>&1
                rc=$?
            fi


            if [ $rc -ne 0 ]; then
                 echo "[ERROR] Failed to download ${apar_fix}"
                 exit 1
            fi
        done

        apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')
        apar_dir=$(echo $apar_fix | awk -F'.' '{ print $1 }')
        cd ${SAA_TMP_DIR}/$1
        if [ $(echo $apar_fix | awk -F'.' '{ print $NF }') == 'tar' ]; then
            tar xvf $apar_fix > /dev/null 2>&1
            cd $apar_dir
        fi

        for file in $(ls | grep epkg.Z | grep -v sig); do
            echo "      \`- Running $file preview "
            preview_cmd=$(emgr -p -e $file 2>&1)
            if [ $? -eq 0 ]; then
                echo "      \`- APAR $file is APPLICABLE to the system"
                system_affected_allv='True'
                break
            else
                efix_locked=$(echo "$preview_cmd" | grep "locked by efix")
                if [ $? -eq 0 ]; then
                    echo "      \`- APAR $file is APPLICABLE to the system"
                    system_affected_allv='True'
                    break
                else
                    echo "      \`- APAR $file is NOT applicable to the system"
                    system_affected_allv='False'
                fi
            fi
        done

    else
        system_affected_allv='False'

    fi
}

# function to check the protocols
function _check_protocols {
    if [ ${SAA_PROTOCOL} == 'http' ]; then
        _check_APAR_http
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        _check_APAR_nfs
    fi

}

# function to get the APAR details info
function APAR_info  {

    if [ ${system_affected} == "True" ]; then
        echo "[CLIENT] This system is AFFECTED by $1 (REBOOT REQUIRED: $APAR_REBOOT)"
    else
        echo "[CLIENT] This system is NOT AFFECTED by $1"
    fi

    echo "[CLIENT] Getting APAR '$1' info"

    if [ ${SAA_PROTOCOL} == 'http' ]; then
        sleep 2
        curl -L ${secid_url_version}/${APAR_ASC} | more
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        more ${SAA_FILESYSTEM}/$1/$server_version/${APAR_ASC}
    fi

}

# function to check if the apar is affected or not
function APAR_check  {
    if [ $system_affected == "True" ] || [ $system_affected_allv == "True" ];
    then
        echo "[CLIENT] This system is AFFECTED by $1 (REBOOT REQUIRED: $APAR_REBOOT)"
    else
        echo "[CLIENT] This system is NOT AFFECTED by $1"
        exit 1
    fi
}

# function to install the APAR fix after check
function APAR_install {

    if [ $system_affected == "True" ]; then
        echo "[CLIENT] Starting the APAR $1 in 10 seconds. Use CTRL+C to cancel now!"
        sleep 10
        for apar in ${APAR_FIX}; do
            apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')
            if [ $? -ne 0 ]; then
                echo "[ERROR] Failed to download ${apar_fix}"
                exit 1
            fi
        done

        apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')
        apar_dir=$(echo $apar_fix | awk -F'.' '{ print $1 }')
        cd ${SAA_TMP_DIR}/$1

        if [ $(echo $apar_fix | awk -F'.' '{ print $NF }') == 'tar' ]; then
           cd $apar_dir
        fi

        for file in $(ls | grep epkg.Z | grep -v sig); do
            echo "      \`- Running $file install preview/test "
            preview_cmd=$(emgr -p -e $file 2>&1)
            if [ $? -eq 0 ]; then
                echo "      \`- APAR $file is APPLICABLE to the system"
                emgr -X -e $file
            else
                efix_locked=$(echo "$preview_cmd" | grep "locked by efix")
                if [ $? -eq 0 ]; then
                    locker=$(echo "$efix_locked" | head -1 | awk '{ print $NF}' | awk -F \" '{ print $2 }' | cut -c0-7)
                    echo "      \`- Uninstalling the efix locker $locker"
                    emgr -r -L $locker
                    echo "      \`- Installing the new efix"
                    emgr -X -e $file
                else
                    echo "      \`- APAR $file is NOT applicable to the system"
                fi
            fi
        done
        echo
        echo "[CLIENT] APAR $1 Installation finished. (REBOOT REQUIRED: $APAR_REBOOT)"
    else
        echo "[CLIENT] This system is NOT AFFECTED by $1 "
        exit 1
    fi

}

# install APARs All versions if affected
function APAR_install_allv {

    if [ $system_affected_allv == "True" ]; then
        echo "[CLIENT] Starting the APAR $1 in 10 seconds. Use CTRL+C to cancel now!"
        sleep 10
        for apar in ${APAR_FIX}; do
            apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')
            if [ $? -ne 0 ]; then
                echo "[ERROR] Failed to download ${apar_fix}"
                exit 1
            fi
        done

        apar_fix=$(echo $apar | awk -F'/' '{ print $NF }')
        apar_dir=$(echo $apar_fix | awk -F'.' '{ print $1 }')
        cd ${SAA_TMP_DIR}/$1

        if [ $(echo $apar_fix | awk -F'.' '{ print $NF }') == 'tar' ]; then
           cd $apar_dir
        fi

        for file in $(ls | grep epkg.Z | grep -v sig); do
            echo "      \`- Running $file install preview/test "
            preview_cmd=$(emgr -p -e $file 2>&1)
            if [ $? -eq 0 ]; then
                echo "      \`- APAR $file is APPLICABLE to the system"
                emgr -X -e $file
            else
                efix_locked=$(echo "$preview_cmd" | grep "locked by efix")
                if [ $? -eq 0 ]; then
                    locker=$(echo "$efix_locked" | head -1 | awk '{ print $NF}' | awk -F \" '{ print $2 }' | cut -c0-7)
                    echo "      \`- Uninstalling the efix locker $locker"
                    emgr -r -L $locker
                    echo "      \`- Installing the new efix"
                    emgr -X -e $file
                else
                    echo "      \`- APAR $file is NOT applicable to the system"
                fi
            fi
        done
        echo
        echo "[CLIENT] APAR $1 Installation finished. (REBOOT REQUIRED: $APAR_REBOOT)"
    else
        echo "[CLIENT] This system is NOT AFFECTED by $1 "
        exit 1
    fi


}


# function to print help message
function _print_help {

    echo 'Usage: saassist-client [check|info|install] "CVE|IV-NUM" | help'
    echo
    echo 'check   : Verify if the system is affected by CVE/IV'
    echo 'info    : Open the details about the CVE/IV if system is affected'
    echo 'install : Install the APAR if it is available and applicable to the'
    echo '          the system'
    echo
    echo 'Example:'
    echo '  saassist-client check "CVE-2016-0281"'
    echo '  saassist-client check "IV91004"'
    echo
    echo 'It requires the client_config properly configured and a Security APAR'
    echo 'Assistant server.'
    echo 'It works over HTTP and NFS protocols, please check the README for'
    echo 'more information.'
    echo

}


#
# Main
#

echo
echo "========================================================================"
echo "SAAssist-client (Security APAR Assist Client) - Version $version"
echo "========================================================================"
echo
echo "Current OS Version: $(oslevel -s)"
echo
if [ -z $2 ]; then
    echo "[ERROR] A CVE or IV is required"
    echo
    _print_help
    exit 1
fi

case $1 in

    'check')

        _check_tmp_dir $2
        _check_protocols
        _check_secid $2
        if [ system_affected == "False" ]; then
            _check_secid_allv $2
        fi
   echo
        APAR_check $2



    ;;

    'info')

        _check_tmp_dir $2
        _check_protocols
        _check_secid $2
        if [ system_affected == "False" ]; then
            _check_secid_allv $2
        fi
        echo
        APAR_info $2

    ;;

    'install')

        _check_tmp_dir $2
        _check_protocols
        echo
        APAR_install $2
        if [ system_affected == "False" ]; then
            _check_secid_allv $2
        fi

    ;;

    *)

        _print_help

    ;;
esac