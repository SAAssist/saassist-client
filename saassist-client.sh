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

version='0.2.0'

session_hash=$(date +%s_${RANDOM})

if [ -f ./client_config ]; then
    . ./client_config
else
    echo "[ERROR] The 'client_config' file needs to be in"
    echo "the same directory of saassist-client"
    exit 1
fi

OS_TYPE=$(uname)

if [ $OS_TYPE == "AIX" ]; then
    continue
else
    echo "[ERROR] Only IBM AIX or PowerVM are supported."
    exit 1
fi

if [ $(whoami) != "root" ]; then
    echo "[ERROR] Run saassist-client.sh with root user."
    exit 1
fi

# Basic variables
if [ -f /usr/ios/cli/ioscli ]; then
   server_version=$(/usr/ios/cli/ioscli ioslevel | awk -F . '{ print $1"."$2 }')
   server_release=$(/usr/ios/cli/ioscli ioslevel)

else
   server_version=$(oslevel -r)
   server_release=$(oslevel -s | awk -F'-' '{ print $1"-"$2"-"$3 }')

fi

server_url="http://$SAA_SERVER:$SAA_PORT/"
server_nfs="${SAA_SERVER}"
secid_url="$server_url$2/"
secid_nfs="${SAA_FILESYSTEM}/$2"
secid_url_version=${secid_url}${server_version}
secid_nfs_version=${secid_nfs}/${server_version}
saas_flrt_data=${SAA_PATH}/data/flrt_cache.csv

# check if there is a emgr lock file
if [ -f /var/locks/emgr.lock ]; then
    echo "[ERROR] SAAssist found a emgr lock file /var/locks/emgr.lock"
    echo "        Check if process $(cat /var/locks/emgr.lock) exists and remove file"
    exit 1
fi

# Function to check if SAA Server is ready using NFS
function _check_APAR_nfs {
        echo "[CLIENT] Verifying SAA Server over NFS"

        find_nfs=$(df -k | grep : | grep ${SAA_SERVER})
        if [ $? -ne 0 ]; then
            echo "[CLIENT] Filesystem ${SAA_FILESYSTEM} not found"
            echo "[CLIENT] Trying to mount..."
            if [ ! -d ${SAA_FILESYSTEM} ]; then
                mkdir -p ${SAA_FILESYSTEM}
            fi
            mount ${server_nfs}:${SAA_FILESYSTEM} ${SAA_FILESYSTEM}
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
            if [ $? -ne 0 ]; then
                echo "[ERROR] Error to create $SAA_TMP_DIR/$1"
                exit 1
            fi

    else
        # this is to avoid multiple sessions using the same temporary file
        # system, for example a NFS. In this case, if another session is
        # writing or downloading the files it will wait 30 seconds maximum
        # remark: check on _check_secid comments with "# lock to create files"
        count=0
        while [ $count -lt 3 ]; do
            if [ -f $SAA_TMP_DIR/$1/$1.lock ]; then
                sleep 10;
                count=$((count+1))
            else
                count=3
            fi
        done
        rm $SAA_TMP_DIR/$1/$1.lock  > /dev/null 2>&1
    fi
}

# function to check CVE/IV on server
function _check_secid {

    # check if APAR fix is available on http/nfs server
    if [ ${SAA_PROTOCOL} == 'http' ]; then
        secid_test=$(curl -o /dev/null -sIf ${secid_url})
        rc=$?

    elif [ ${SAA_PROTOCOL} == 'nfs' ]; then
        secid_test=$(ls -ld ${secid_nfs} > /dev/null 2>&1)
        rc=$?
    else
        echo "[ERROR] Unexpected protocol ${SAA_PROTOCOL}"
        exit 1
    fi

    if [ $rc -ne 0 ]; then
        echo "[CLIENT] The CVE/IV $1 is not available on server $SAA_SERVER."
        echo
        echo "         This APAR was not processed by SAAssist Server or does"
        echo "         not exist."
        echo "         - Check with Security APAR Assistant server"
        echo "         administrator if that APAR is already available."
        echo "         Run on SAAssist Server: saassist-server -c $1"
        echo
        echo "         - Check if APAR ID $1 is correct"
        echo
        exit 1

    else
        # if available, check if the version is affected
        echo "[CLIENT] Retrieving APAR $1 info from ${server_nfs}"
        echo "[CLIENT] Checking if CVE/IV is applicable for OS version ${server_version}"
        if [ ${SAA_PROTOCOL} == 'http' ]; then
            secid_version_test=$(curl -o /dev/null -sIf ${secid_url_version})
            rc=$?
        fi

        if [ ${SAA_PROTOCOL} == 'nfs' ]; then
            secid_version_test=$(ls -ld ${secid_nfs_version} > /dev/null 2>&1)
            rc=$?
        fi

        if [ $rc -ne 0 ]; then
            # check if there is a general update, IBM sometimes creates a
            # generic version based only on the fileset.
            # Examples: CVE-2015-7974 There is a generic entry + versioned
            #           CVE-2015-7973 Only generic entry
            if [ ${SAA_PROTOCOL} == 'http' ]; then
                http_test=$(curl -o /dev/null -sIf ${secid_url}ALL)
                rc=$?
            fi

            if [ ${SAA_PROTOCOL} == 'nfs' ]; then
                nfs_test=$(ls -ld ${secid_nfs}/ALL)
                rc=$?
            fi

            if [ $rc -eq 0 ]; then
                secid_url_version=${secid_url}ALL
                secid_nfs_version=${secid_nfs}/ALL
                echo "      \`- There is a generic patch for $1."
                system_affected='True'
            else
                echo "      \`- The version $server_version is not affected by $1"
                system_affected='False'
            fi

        else
            system_affected='True'
        fi

        if [ ${system_affected} == 'True' ]; then
            if [ ! -f ${SAA_TMP_DIR}/$1/$1.info ]; then
                if [ ${SAA_PROTOCOL} == 'http' ]; then
                    # lock to create files
                    touch $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1

                    curl -s ${secid_url_version}/$1.info -o ${SAA_TMP_DIR}/$1/$1.info
                    rc=$?

                    # unlock
                    rm $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1
                fi

                if [ ${SAA_PROTOCOL} == 'nfs' ]; then
                    # lock to create files
                    touch $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1

                    cp ${secid_nfs_version}/$1.info ${SAA_TMP_DIR}/$1/$1.info > /dev/null 2>&1
                    rc=$?

                    # unlock
                    rm $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1
                fi
            else
                rc=0
            fi

            if [ $rc -ne 0 ]; then
                echo "[ERROR] Failed to saved the $1.info file"
                exit 1
            fi

            # load APAR information
            . /${SAA_TMP_DIR}/$1/$1.info

            echo "[CLIENT] Checking if CVE/IV is applicable for OS release $server_release"
            for release in ${AFFECTED_RELEASES}; do
                if [ "$release" == "$server_release" ] || [ $release == "ALL" ];
                then
                    system_affected='True'
                    break
                fi
            done
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
                if [ -f /usr/ios/cli/ioscli ]; then
                    os_ver=$server_version

                else
                    os_ver=$(oslevel | awk -F'.' '{ print $1"."$2 }')
                fi

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

                if [ ! -f $SAA_TMP_DIR/$1/$apar_fix ]; then
                    if [ ${SAA_PROTOCOL} == 'http' ]; then
                        # lock to create files
                        touch $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1

                        curl -s $secid_url_version/$apar_fix -o $SAA_TMP_DIR/$1/$apar_fix
                        rc=$?

                        # unlock
                        rm $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1
                    fi

                    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
                        # lock to create files
                        touch $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1

                        cp $secid_nfs_version/$apar_fix ${SAA_TMP_DIR}/$1/$apar_fix > /dev/null 2>&1
                        rc=$?

                        # unlock
                        rm $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1
                    fi

                else
                    rc=0
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
                if [ ! -f $apar_dir ]; then
                    # lock to create files
                    touch $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1

                    untar_output=$(tar xvf $apar_fix 2> /dev/null)
                    if [ $? -ne 0 ]; then
                        echo "[ERROR] Failed to uncompress the fix"
                        exit
                    fi

                    apar_dir=$(echo ${untar_output} | tail -1 | awk '{ print $2 }' | awk -F "/" '{ print $1 }')

                    # unlock
                    rm $SAA_TMP_DIR/$1/$1.lock > /dev/null 2>&1
                fi
                cd $apar_dir
            fi

            for file in $(ls | grep epkg.Z | grep -v sig); do
                echo "      \`- Running $file preview "
                preview_cmd=$(emgr -p -e $file 2>&1)
                if [ $? -eq 0 ]; then
                    echo "      \`- APAR $file is APPLICABLE to the system"
                    system_affected='True'
                    break
                else
                    efix_locked=$(echo "$preview_cmd" | grep "locked by efix")
                    if [ $? -eq 0 ]; then
                        echo "      \`- APAR $file is APPLICABLE to the system"
                        system_affected='True'
                        break
                    else
                        echo "      \`- APAR $file is NOT applicable to the system"
                        system_affected='False'
                    fi
                fi
            done
        fi

    fi

}


# function to check the protocols
function _check_protocols {
    if [ ${SAA_PROTOCOL} == 'http' ]; then
        _check_APAR_http

    elif [ ${SAA_PROTOCOL} == 'nfs' ]; then
        _check_APAR_nfs

    else
        echo "[ERROR] Unexpected protocol ${SAA_PROTOCOL}."
        exit 1
    fi

}

# function to get flrt data file
function _get_flrt_data_file {
    echo "[CLIENT] Downloading FLRT data from SAAssist Server"
    if [ ${SAA_PROTOCOL} == 'http' ]; then
        curl -s ${server_url}/repos/flrt_cache.csv -o ${saas_flrt_data}
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to download FLRT data file from Server ${SAA_SERVER}"
            exit 1
        else
            echo "[CLIENT] Downloading finished."
        fi
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        cp ${SAA_FILESYSTEM}/flrt_cache.csv ${saas_flrt_data}
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to download FLRT data file from Server ${SAA_SERVER}"
            exit 1
        else
            echo "[CLIENT] Downloading finished."

        fi
    fi
}

# function to check version saassist-server
function  _check_saaserver_version {

    if [ ${SAA_PROTOCOL} == 'http' ]; then
        SAA_SERVER_VERSION=$(curl -s ${server_url}/repos/VERSION)
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to download FLRT data file from Server ${SAA_SERVER}"
            exit 1
        fi
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        SAA_SERVER_VERSION=$(cat ${SAA_FILESYSTEM}/VERSION)
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to download FLRT data file from Server ${SAA_SERVER}"
            exit 1
        fi
    fi

    SAA_SERVER_MAJOR=$(echo ${SAA_SERVER_VERSION} | awk -F"." '{ print $1"."$2 }')
    if [ ${SAA_SERVER_MAJOR} != "0.2" ]; then
        echo "[ERROR] The Security APAR Assistant server must be 0.2.x"
        exit
    fi


}

# function to get the APAR details info
function APAR_info  {

    echo "[CLIENT] Getting APAR '$1' info"

    if [ ${SAA_PROTOCOL} == 'http' ]; then
        sleep 2
        curl -L ${secid_url_version}/$1.asc | more
    fi

    if [ ${SAA_PROTOCOL} == 'nfs' ]; then
        more ${secid_nfs_version}/$1.asc
    fi

}

# function to check if the apar is affected or not
function APAR_check  {
    if [ $system_affected == "True" ]; then
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
                break
            else
                efix_locked=$(echo "$preview_cmd" | grep "locked by efix")
                if [ $? -eq 0 ]; then
                    locker=$(echo "$efix_locked" | head -1 | awk '{ print $NF}' | awk -F \" '{ print $2 }')
                    echo "      \`- Uninstalling the efix locker $locker"
                    emgr -r -L $locker
                    echo "      \`- Installing the new efix"
                    emgr -X -e $file
                    break
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

function APAR_checkall {

    echo "[CLIENT] Generating checkall report"
    apar_server_list="${SAA_TMP_DIR}/apar_server_list_${session_hash}"
    grep ${server_release} ${saas_flrt_data} | awk -F, '{ print $5" ; "$10" ; "$4" ; "$9" ; "$NF" ; "$7" ; "$14}' | sed 's/ *$//' | sed 's/: /:/g' | sort -k1 -u > ${apar_server_list}
    if [ $? -ne 0 ];then
        echo "[ERROR] Error to collect server APAR list."
        exit 1
    fi

    if [ $(du -sk ${apar_server_list} | awk '{ print $1 }') -eq 0 ]; then
        echo "[INFO] No APARs available for ${server_release} version"
        exit
    fi

    clear
    printf "SECURITY APAR     DATE       AFFECTED       BOOT         DESCRIPTION\n"
    printf "-------------------------------------------------------------------------------------------------------------\n"

    LAST_APAR_VERIFIED="None"
    while read apar_info;
    do
            APAR=$(echo $apar_info | awk -F ";" '{ print $1 }')
            APAR_DATE=$(echo $apar_info | awk -F ";" '{ print $2 }')
            APAR_DESCRIPTION=$(echo $apar_info | awk -F ";" '{ print $3 }')
            APAR_FILESETS=$(echo $apar_info | awk -F ";" '{ print $4 }')
            APAR_BOOT_REQUIRED=$(echo $apar_info | awk -F ";" '{ print $5 }')
            APAR_IFIX=$(echo $apar_info | awk -F ";" '{ print $6 }' | sed 's/\///g')
            APAR_CODE=$(echo $apar_info | awk -F ";" '{ print $7 }' | awk -F '/' '{ print $NF }' | awk -F ':' '{ print $1 }' | sed 's/ CVE/CVE/g')

            if [ "${APAR_CODE}" == "" ];
            then
                APAR_CODE=${APAR}
            fi

        if [ "${LAST_APAR_VERIFIED}" == "${APAR_CODE}" ]; then
            continue
        fi

        # check if some ifix is installed to the APAR
        APAR_IFIX_APPLIED=False
        for ifix in ${APAR_IFIX};
        do
            ifix_number=$(echo ${ifix} | grep IV | awk -F "." '{ print $1 }')
            if [ "${ifix_number}" != "" ]; then
                ifix_status=$(emgr -l 2> /dev/null | grep ${ifix_number})
                if [ $? -eq 0 ]; then
                    APAR_IFIX_APPLIED=True
                fi
            fi
        done

        # getting filesets and test
        for fileset in ${APAR_FILESETS};
        do
            fileset_name=$(echo ${fileset} | awk -F":" '{ print $1 }')
            fileset_affected=$(echo ${fileset} | awk -F":" '{ print $2 }')
            apar_installed=$(lslpp -Lcq ${fileset_name} 2> /dev/null)

            if [ "${apar_installed}" == "" ];
            then
                        APAR_AFFECT=False
            else
                installed_lpp_package=$(echo ${apar_installed} | awk -F: '{ print $1 }')
                installed_lpp_name=$(echo ${apar_installed} | awk -F: '{ print $2 }')
                installed_lpp_release=$(echo ${apar_installed} | awk -F: '{ print $3 }')
                installed_lpp_version=$(echo ${installed_lpp_release} | awk -F"." '{ print $1"."$2"."$3 }')
                installed_lpp_minor=$(echo ${installed_lpp_release} | awk -F"." '{ print $NF }')
            fi

            #check if fileset_affect is a range
            fileset_range=$(echo ${fileset_affected} | grep "-")
            if [ $? -eq 0 ]; then
                release_start=$(echo ${fileset_range} | awk -F"-" '{ print $1 }')
                release_start_minor=$(echo ${release_start} | awk -F"." '{ print $NF }')
                release_finish=$(echo ${fileset_range} | awk -F"-" '{ print $2 }')
                release_finish_minor=$(echo ${release_finish} | awk -F"." '{ print $NF }')
                release_count=$(echo ${release_start} | awk -F"." '{ print $NF }')
                fileset_version=$(echo ${release_start} | awk -F"." '{ print $1"."$2"."$3 }')

                if [ "${fileset_version}" == "${installed_lpp_version}" ];
                then
                    if [ $installed_lpp_minor -ge $release_start_minor -a $installed_lpp_minor -le $release_finish_minor ];
                    then
                        APAR_AFFECTED=True
                        break
                    else
                        APAR_AFFECTED=False
                    fi
                fi

            else

                if [ "$installed_lpp_release" == "$fileset_range" ]; then
                    APAR_AFFECTED=True
                    break
                else
                    APAR_EFFECTED=False
                fi
            fi
        done

        if [ "${APAR_AFFECTED}" == True ]; then

            if [ "${APAR_IFIX_APPLIED}" == True ]; then
                printf "${APAR_CODE}\t ${APAR_DATE}     N(ifix)    ${APAR_BOOT_REQUIRED} \t${APAR_DESCRIPTION}\n"
                APAR_IFIX_APPLIED=False

            else
                saa_preview=$(sh saassist-client.sh preview ${APAR_CODE} | tail -1 | grep "NOT AFFECTED")
                if [ $? -eq 0 ] ; then
                     printf "${APAR_CODE}\t ${APAR_DATE}     N          ${APAR_BOOT_REQUIRED} \t${APAR_DESCRIPTION}\n"

                else
                     printf "${APAR_CODE}\t ${APAR_DATE}    *Y*         ${APAR_BOOT_REQUIRED} \t${APAR_DESCRIPTION}\n"
                fi

            fi

        else
                printf "${APAR_CODE}\t ${APAR_DATE}     N          ${APAR_BOOT_REQUIRED} \t${APAR_DESCRIPTION}\n"
        fi

        LAST_APAR_VERIFIED=${APAR_CODE}

    done < ${apar_server_list}

}


# function to print help message
function _print_help {

    echo 'Usage: saassist-client [help] [checkall] [preview|info|install "CVE|IV-NUM"]'
    echo
    echo 'optional arguments:'
    echo
    echo 'help     : show this help and exit'
    echo 'checkall : List all existent APARS for the system and check if it'
    echo '           affects the system'
    echo 'preview  "CVE|IV-NUM":'
    echo '           Run a preview and validate if it is affected'
    echo 'info     "CVE|IV-NUM":'
    echo '           Open the details about the CVE/IV if system is affected'
    echo 'install  "CVE|IV-NUM":'
    echo '           Install the APAR if it is available and applicable to the'
    echo '           the system'
    echo
    echo 'Examples:'
    echo '  saassist-cleint checkall'
    echo '  saassist-client preview "CVE-2016-0281"'
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
echo "Current OS Version: $server_release"
echo
#if [ -z $2 ]; then
#    echo "[ERROR] A CVE or IV is required"
#    echo
#    _print_help
#    exit 1
#fi

case $1 in

    'checkall')

        _check_tmp_dir
        _check_protocols
        _check_saaserver_version
        _get_flrt_data_file
        APAR_checkall
    ;;


    'preview')

        _check_tmp_dir $2
        _check_protocols
        _check_saaserver_version
        _check_secid $2
        echo
        APAR_check $2
    ;;

    'info')

        _check_tmp_dir $2
        _check_protocols
        _check_saaserver_version
        echo
        APAR_info $2

    ;;

    'install')

        _check_tmp_dir $2
        _check_protocols
        _check_saaserver_version
        _check_secid $2
        APAR_check $2
        echo
        APAR_install $2

    ;;

    *)

        _print_help

    ;;
esac
