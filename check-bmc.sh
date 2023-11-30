#!/bin/bash
# 名称: bmc检查脚本
# 描述: 此脚本运行环境需安装ipmitool、net-snmp-utils、curl安装包
#      先填写bmclist.csv文件再运行此脚本
# 支持的制造商:
# huawei:      华为
# h3c:         华三
# kunpeng:     鲲鹏（湘江鲲鹏、长江鲲鹏）
# inspur:      浪潮
# suma:        曙光


#########################################
# ping测试
ping_test(){
    ping ${ip} -c 1 > /dev/null
    if [ $? -eq 0 ];then
        echo "${ip} reachable!"
    else
        echo "${ip} is unreachable!"
        continue
    fi
}
# 型号信息
model_info(){
    ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} lan print > ${mydir}/net_info.txt
    mask=$(cat ${mydir}/net_info.txt|grep "Subnet Mask"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    gateway=$(cat ${mydir}/net_info.txt|grep "Default Gateway IP"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmp_str=$(cat ${mydir}/net_info.txt|grep "SNMP Community String"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} fru > ${mydir}/fru_info.txt
    sn=$(cat ${mydir}/fru_info.txt|grep "Product Serial"|awk -F: '{print $2}'|head -n 1|sed -e 's/[[:space:]]//g')
    manufacturer=$(cat ${mydir}/fru_info.txt|grep "Product Manufacturer"|awk -F: '{print $2}'|head -n 1|sed -e 's/^[ ]*//g')
    model=$(cat ${mydir}/fru_info.txt|grep "Product Name"|awk -F: '{print $2}'|head -n 1|sed -e 's/[[:space:]]//g')

}
# snmp连通性
snmp_test(){
    snmpwalk -v 2c -c "yundiao*&COC2016" ${ip} sysname > /dev/null 2>&1
    if [ $? -eq 0 ];then
        snmp_str="yundiao*&COC2016"
        snmp_result="Passed"
    else
        snmpwalk -v 2c -c yundiao_COC2016 ${ip} sysname > /dev/null 2>&1
        if [ $? -eq 0 ];then
            snmp_str="yundiao_COC2016"
            snmp_result="Passed"
        else
            snmp_result="Failed"
        fi
    fi
}
# 主机名对比
compare_hostname(){
    if [ "${file_hostname,,}" == "${bmc_hostname,,}" ]; then
        hostname_result="Passed"
    else
        hostname_result=${bmc_hostname}
    fi
}

# 用户权限
user_priv(){
    ipmitool -I lanplus -H ${ip} -U ${id2_user} -P ${id2_pass} user list > ${mydir}/userlist
    id2_priv=$(cat ${mydir}/userlist|grep -w 2|awk -F" " '{print $6}')

    id3_priv=$(cat ${mydir}/userlist|grep -w 3|awk -F" " '{print $6}')
    server_id3=$(cat ${mydir}/userlist|grep -w 3|awk -F" " '{print $2}')
    if [[ "${server_id3}" == "${id3_user}" && "${id3_result}" == "Passed" ]]; then
        id3_result="Passed"
    else
        id3_result="Failed"
    fi

    id4_priv=$(cat ${mydir}/userlist|grep -w 4|awk -F" " '{print $6}')
    server_id4=$(cat ${mydir}/userlist|grep -w 4|awk -F" " '{print $2}')
    if [[ "${server_id4}" == "${id4_user}" && "${id4_result}" == "Passed" ]]; then
        id4_result="Passed"
    else
        id4_result="Failed"
    fi

    id5_priv=$(cat ${mydir}/userlist|grep -w 5|awk -F" " '{print $6}')
    server_id5=$(cat ${mydir}/userlist|grep -w 5|awk -F" " '{print $2}')
    if [[ "${server_id5}" == "${id5_user}" && "${id5_result}" == "Passed" ]]; then
        id5_result="Passed"
    else
        id5_result="Failed"
    fi

    id6_priv=$(cat ${mydir}/userlist|grep -w 6|awk -F" " '{print $6}')
    server_id6=$(cat ${mydir}/userlist|grep -w 6|awk -F" " '{print $2}')
    if [[ "${server_id6}" == "${id6_user}" && "${id6_result}" == "Passed" ]]; then
        id6_result="Passed"
    else
        id6_result="Failed"
    fi

    id7_priv=$(cat ${mydir}/userlist|grep -w 7|awk -F" " '{print $6}')
    server_id7=$(cat ${mydir}/userlist|grep -w 7|awk -F" " '{print $2}')
    if [[ "${server_id7}" == "${id7_user}" && "${id7_result}" == "Passed" ]]; then
        id7_result="Passed"
    else
        id7_result="Failed"
    fi

    id8_priv=$(cat ${mydir}/userlist|grep -w 8|awk -F" " '{print $6}')
    server_id8=$(cat ${mydir}/userlist|grep -w 8|awk -F" " '{print $2}')
    if [[ "${server_id8}" == "${id8_user}" && "${id8_result}" == "Passed" ]]; then
        id8_result="Passed"
    else
        id8_result="Failed"
    fi

    priv=$(echo -e "id2:${id2_priv:-none}/id3:${id3_priv:-none}/id4:${id4_priv:-none}/id5:${id5_priv:-none}/id6:${id6_priv:-none}/id7:${id7_priv:-none}/id8:${id8_priv:-none}")
}
# 用户密码测试
user_test(){
    if [ "${id2_user}" == "none" ];then
        id2_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 2 20 ${id2_pass})
        if [ "${status}" == "Success" ];then
            id2_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 2 16 ${id2_pass})
                if [ "${status}" == "Success" ];then
                    id2_result="Passed"
                else
                    id2_result="Username or password is wrong,please check!"
                    continue
                fi
            else
                id2_result="Password:${id2_pass} failed"
            fi
        fi
    fi

    if [ "${id3_user}" == "none" ];then
        id3_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 3 20 ${id3_pass})
        if [ "${status}" == "Success" ];then
            id3_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 3 16 ${id3_pass})
                if [ "${status}" == "Success" ];then
                    id3_result="Passed"
                else
                    id3_result="Password:${id3_pass} failed"
                fi
            else
                id3_result="Password:${id3_pass} failed"
            fi
        fi
    fi

    if [ "${id4_user}" == "none" ];then
        id4_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 4 20 ${id4_pass})
        if [ "${status}" == "Success" ];then
            id4_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 4 16 ${id4_pass})
                if [ "${status}" == "Success" ];then
                    id4_result="Passed"
                else
                    id4_result="Password:${id4_pass} failed"
                fi
            else
                id4_result="Password:${id4_pass} failed"
            fi
        fi
    fi

    if [ "${id5_user}" == "none" ];then
        id5_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 5 20 ${id5_pass})
        if [ "${status}" == "Success" ];then
            id5_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 5 16 ${id5_pass})
                if [ "${status}" == "Success" ];then
                    id5_result="Passed"
                else
                    id5_result="Password:${id5_pass} failed"
                fi
            else
                id5_result="Password:${id5_pass} failed"
            fi
        fi
    fi

    if [ "${id6_user}" == "none" ];then
        id6_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 6 20 ${id6_pass})
        if [ "${status}" == "Success" ];then
            id6_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 6 16 ${id6_pass})
                if [ "${status}" == "Success" ];then
                    id6_result="Passed"
                else
                    id6_result="Password:${id6_pass} failed"
                fi
            else
                id6_result="Password:${id6_pass} failed"
            fi
        fi
    fi

    if [ "${id7_user}" == "none" ];then
        id7_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 7 20 ${id7_pass})
        if [ "${status}" == "Success" ];then
            id7_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 7 16 ${id7_pass})
                if [ "${status}" == "Success" ];then
                    id7_result="Passed"
                else
                    id7_result="Password:${id7_pass} failed"
                fi
            else
                id7_result="Password:${id7_pass} failed"
            fi
        fi
    fi

    if [ "${id8_user}" == "none" ];then
        id8_result="none"
    else
        status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 8 20 ${id8_pass})
        if [ "${status}" == "Success" ];then
            id8_result="Passed"
        else
            if [ $(echo "${status}"|grep -i "size"|wc -l) -eq 1  ]; then
                status=$(ipmitool -I lanplus -H ${ip} -U ${adminuser} -P ${adminpasswd} user test 8 16 ${id8_pass})
                if [ "${status}" == "Success" ];then
                    id8_result="Passed"
                else
                    id8_result="Password:${id8_pass} failed"
                fi
            else
                id8_result="Password:${id8_pass} failed"
            fi
        fi
    fi
}

var_info(){
    file_hostname=$(echo ${LINE}|awk -F, '{print $2}')
    id2=$(echo ${LINE}|awk -F, '{print $3}')
    if [ ! -z "${id2}" ];then
        id2_user=`echo ${id2}|awk -F/ '{print $1}'`
        id2_pass=`echo ${id2}|awk -F/ '{print $2}'`
    else
        id2_user="none"
        id2_pass="none"
    fi
    id3=$(echo ${LINE}|awk -F, '{print $4}')
    if [ ! -z "${id3}" ];then
        id3_user=`echo ${id3}|awk -F/ '{print $1}'`
        id3_pass=`echo ${id3}|awk -F/ '{print $2}'`
    else
        id3_user="none"
        id3_pass="none"
    fi
    id4=$(echo ${LINE}|awk -F, '{print $5}')
    if [ ! -z "${id4}" ];then
        id4_user=`echo ${id4}|awk -F/ '{print $1}'`
        id4_pass=`echo ${id4}|awk -F/ '{print $2}'`
    else
        id4_user="none"
        id4_pass="none"
    fi
    id5=$(echo ${LINE}|awk -F, '{print $6}')
    if [ ! -z "${id5}" ];then
        id5_user=`echo ${id5}|awk -F/ '{print $1}'`
        id5_pass=`echo ${id5}|awk -F/ '{print $2}'`
    else
        id5_user="none"
        id5_pass="none"
    fi
    id6=$(echo ${LINE}|awk -F, '{print $7}')
    if [ ! -z "${id6}" ];then
        id6_user=`echo ${id6}|awk -F/ '{print $1}'`
        id6_pass=`echo ${id6}|awk -F/ '{print $2}'`
    else
        id6_user="none"
        id6_pass="none"
    fi
    id7=$(echo ${LINE}|awk -F, '{print $8}')
    if [ ! -z "${id7}" ];then
        id7_user=`echo ${id7}|awk -F/ '{print $1}'`
        id7_pass=`echo ${id7}|awk -F/ '{print $2}'`
    else
        id7_user="none"
        id7_pass="none"
    fi
    id8=$(echo ${LINE}|awk -F, '{print $9}')
    if [ ! -z "${id8}" ];then
        id8_user=`echo ${id8}|awk -F/ '{print $1}'`
        id8_pass=`echo ${id8}|awk -F/ '{print $2}'`
    else
        id8_user="none"
        id8_pass="none"
    fi
#   设置ipmitool管理账号
    adminuser=${id2_user}
    adminpasswd=${id2_pass}
}
# 删除会话指令
delete_session1(){
    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X DELETE https://${ip}/redfish/v1/SessionService/Sessions/${session_id} > /dev/null
}
delete_session2(){
    curl -s -k -w %{http_code} -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X DELETE https://${ip}/redfish/v1/SessionService/Sessions/${session_id} > /dev/null
}

# 删除会话
delete_info(){
    case ${choose} in
        huawei|jxkp|inspur|suma)
            delete_session1
            ;;
        h3c)
            delete_session2
#       ......
    esac
}
# redfish会话
redfish_session1(){
#   创建会话
    data="{\"UserName\":\"${adminuser}\",\"Password\":\"${adminpasswd}\"}"
    curl -D headers.txt -s -k -H "Content-Type: application/json" -w %{http_code} -d ${data} -X POST https://${ip}/redfish/v1/SessionService/Sessions > /dev/null
#   获取token
    tr -d "\r" < headers.txt > ${mydir}/tmp_headers.txt
    token=$(cat ${mydir}/tmp_headers.txt|grep "^X-Auth-Token"|awk '{print $2;}'|tr -d '"')
#   获取会话id
    session_id=$(cat ${mydir}/tmp_headers.txt|grep "^Location"|awk '{print $2;}'|tr -d '"'|awk -F/ '{print $6}')
#   查询所有会话
#   curl -k -H "X-Auth-Token: ${token}" -X GET https://10.14.143.101/redfish/v1/SessionService/Sessions
#   查询指定会话
#   curl -k -H "X-Auth-Token: ${token}" -X GET https://10.14.143.101/redfish/v1/SessionService/Sessions/${session_id}
}
redfish_session2(){
    data="{\"UserName\":\"${adminuser}\",\"Password\":\"${adminpasswd}\",\"SessionTimeOut\":\"300\"}"
    curl -D headers.txt -s -k -H "Content-Type: application/json" -w %{http_code} -d ${data} -X POST https://${ip}/redfish/v1/SessionService/Sessions > /dev/null
    tr -d "\r" < headers.txt > ${mydir}/tmp_headers.txt
    token=$(cat ${mydir}/tmp_headers.txt|grep "^X-Auth-Token"|awk '{print $2;}'|tr -d '"')
    session_id=$(cat ${mydir}/tmp_headers.txt|grep "^Location"|awk '{print $2;}'|tr -d '"'|awk -F/ '{print $6}')
}

# 获取redfish信息
choose_manufacturer(){
    if [ $(echo "${manufacturer}"|grep -i "huawei"|wc -l) -ge 1 ]; then
        choose="huawei"
    elif [ $(echo "${manufacturer}"|grep -i "yangtze"|wc -l) -ge 1 ]; then
        choose="kunpeng"
    elif [ $(echo "${manufacturer}"|grep -i "h3c"|wc -l) -ge 1 ]; then
        choose="h3c"
    elif [ $(echo "${manufacturer}"|grep -i "inspur"|wc -l) -ge 1 ]; then
        choose="inspur"
    elif [ $(echo "${manufacturer}"|grep -i "suma"|wc -l) -ge 1 ]; then
        choose="suma"        
#   ......

    else
        echo "${manufacturer} no support!"
        continue
    fi


    case ${choose} in
        huawei)
            redfish_session1
            huawei_redfish
            ;;
        kunpeng)
            redfish_session1
            kunpeng_redfish
            ;;
        h3c)
            redfish_session1
            h3c_redfish
            ;;
        inspur)
            redfish_session2
            inspur_redfish
            ;;
        suma)
            redfish_session1
            suma_redfish
            ;;
#       ......
        *)
            echo "miss match"
    esac
}
####################redfish info###################
huawei_redfish(){
    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
    sed -i 's/,/\n/g' ${mydir}/ntp.txt
    tr -d "\r" < ${mydir}/ntp.txt > ${mydir}/tmp_ntp.txt
#   ntp地址
    ntp1=$(cat ${mydir}/tmp_ntp.txt|grep "PreferredNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    ntp2=$(cat ${mydir}/tmp_ntp.txt|grep "AlternateNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
    sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
#   snmptrap告警地址
    snmptrap1=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId: 0"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap1_port=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId: 0"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap2=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId: 1"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap2_port=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId: 1"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1 > ${mydir}/systems.txt
    sed -i 's/,/\n/g' ${mydir}/systems.txt
#   bios版本
    bios_version=$(cat ${mydir}/systems.txt|grep "BiosVersion"|sed 's/"//g'|awk -F: '{print $2}')
#   启动方式
    BootMode=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideMode"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
#   启动设备
    BootTarget=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideTarget"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1 > ${mydir}/managers.txt
    sed -i 's/,/\n/g' ${mydir}/managers.txt
#   时区
    localtime=$(cat ${mydir}/managers.txt|grep "DateTimeLocalOffset"|sed 's/"//g'|awk -F: '{print $2}')
#   
    bmc_version=$(cat ${mydir}/managers.txt|grep "FirmwareVersion"|sed 's/"//g'|awk -F: '{print $2}')
    bmc_hostname=$(cat ${mydir}/managers.txt|grep "HostName"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
}
h3c_redfish(){
    curl -s -k -w %{http_code} -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
    sed -i 's/,/\n/g' ${mydir}/ntp.txt
    ntp1=$(cat ${mydir}/ntp.txt|grep "PreferredNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    ntp2=$(cat ${mydir}/ntp.txt|grep "AlternateNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
    sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
    snmptrap1=$(cat ${mydir}/snmptrap.txt|grep -A12 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 1"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap1_port=$(cat ${mydir}/snmptrap.txt|grep -A12 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 1"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')
    snmptrap2=$(cat ${mydir}/snmptrap.txt|grep -A12 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 2"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap2_port=$(cat ${mydir}/snmptrap.txt|grep -A12 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 2"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')

    curl -s -k -w %{http_code} -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1 > ${mydir}/systems.txt
    sed -i 's/,/\n/g' ${mydir}/systems.txt
    bios_version=$(cat ${mydir}/systems.txt|grep "BiosVersion"|sed 's/"//g'|awk -F: '{print $2}')
    BootMode=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideMode"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    BootTarget=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideTarget"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1 > ${mydir}/managers.txt
    sed -i 's/,/\n/g' ${mydir}/managers.txt
    localtime=$(cat ${mydir}/managers.txt|grep "DateTimeLocalOffset"|sed 's/"//g'|awk -F: '{print $2}')
    bmc_version=$(cat ${mydir}/managers.txt|grep "FirmwareVersion"|sed 's/"//g'|awk -F: '{print $2}')
    bmc_hostname=$(cat ${mydir}/managers.txt|grep "HostName"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
}
kunpeng_redfish(){
    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
    sed -i 's/,/\n/g' ${mydir}/ntp.txt
    tr -d "\r" < ${mydir}/ntp.txt > ${mydir}/tmp_ntp.txt
    ntp1=$(cat ${mydir}/tmp_ntp.txt|grep "PreferredNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    ntp2=$(cat ${mydir}/tmp_ntp.txt|grep "AlternateNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
    sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
    snmp_str=$(cat ${mydir}/snmptrap.txt|grep "CommunityName"|sed 's/"//g'|awk -F: '{print $2}')
    snmptrap1=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId:0"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed 's/[[:space:]]//g')
    snmptrap1_port=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId:0"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')
    snmptrap2=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId:1"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed 's/[[:space:]]//g')
    snmptrap2_port=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A5 "MemberId:1"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1 > ${mydir}/systems.txt
    sed -i 's/,/\n/g' ${mydir}/systems.txt
    bios_version=$(cat ${mydir}/systems.txt|grep "BiosVersion"|sed 's/"//g'|awk -F: '{print $2}')
    BootMode=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideMode"|sed 's/"//g'|awk -F: '{print $2}')
    BootTarget=$(cat ${mydir}/systems.txt|sed -e 's/"//g'|grep "BootSourceOverrideTarget:"| sed -e 's/{//g'|awk -F: '{print $3}')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1 > ${mydir}/managers.txt
    sed -i 's/,/\n/g' ${mydir}/managers.txt
    localtime=$(cat ${mydir}/managers.txt|grep "DateTimeLocalOffset"|sed 's/"//g'|awk -F: '{print $2}')
    bmc_version=$(cat ${mydir}/managers.txt|grep "FirmwareVersion"|sed 's/"//g'|awk -F: '{print $2}')
    bmc_hostname=$(cat ${mydir}/managers.txt|grep "HostName"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g') 
}
inspur_redfish(){
    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
    sed -i 's/,/\n/g' ${mydir}/ntp.txt
    tr -d "\r" < ${mydir}/ntp.txt > ${mydir}/tmp_ntp.txt
    ntp1=$(cat ${mydir}/tmp_ntp.txt|grep "Primary"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    ntp2=$(cat ${mydir}/tmp_ntp.txt|grep "Secondary"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
    sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
    snmp_str=$(cat ${mydir}/snmptrap.txt|grep "ReadOnlyCommunity"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap1=$(cat ${mydir}/snmptrap.txt|grep -A13 "TrapServer"|sed 's/"//g'|grep -A4 "Id: 0"|grep "Destination"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap1_port=$(cat ${mydir}/snmptrap.txt|grep -A13 "TrapServer"|sed 's/"//g'|grep -A4 "Id: 0"|grep "Port"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')
    snmptrap2=$(cat ${mydir}/snmptrap.txt|grep -A13 "TrapServer"|sed 's/"//g'|grep -A4 "Id: 1"|grep "Destination"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap2_port=$(cat ${mydir}/snmptrap.txt|grep -A13 "TrapServer"|sed 's/"//g'|grep -A4 "Id: 1"|grep "Port"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1 > ${mydir}/systems.txt
    sed -i 's/,/\n/g' ${mydir}/systems.txt
    bios_version=$(cat ${mydir}/systems.txt|grep "BiosVersion"|sed -e 's/"//g' -e 's/\\//g'|awk -F": " '{print $2}'|sed 's/ /-/g')
    bmc_hostname=$(cat ${mydir}/systems.txt|grep "HostName"|sed -e 's/"//g' -e 's/[[:space:]]//g'|awk -F: '{print $2}')
    BootMode=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideMode"|sed -e 's/"//g' -e 's/[[:space:]]//g'|awk -F: '{print $2}')
    BootTarget=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideTarget"|sed -e 's/"//g' -e 's/[[:space:]]//g' -e 's/{//g' -e 's/}//g'|awk -F: '{print $3}')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1 > ${mydir}/managers.txt
    sed -i 's/,/\n/g' ${mydir}/managers.txt
    localtime=$(cat ${mydir}/managers.txt|grep "DateTimeLocalOffset"|sed -e 's/"//g' -e 's/[[:space:]]//g'|awk -F: '{print $2":"$3}')
    bmc_version=$(cat ${mydir}/managers.txt|grep "FirmwareVersion"|sed 's/"//g' |awk -F": " '{print $2}'|sed 's/ /-/g')
}
suma_redfish(){
    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
    sed -i 's/,/\n/g' ${mydir}/ntp.txt
    tr -d "\r" < ${mydir}/ntp.txt > ${mydir}/tmp_ntp.txt
#   ntp地址
    ntp1=$(cat ${mydir}/tmp_ntp.txt|grep "PreferredNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    ntp2=$(cat ${mydir}/tmp_ntp.txt|grep "AlternateNtpServer"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
    sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
#   snmptrap告警地址
    snmptrap1=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 1"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')
    snmptrap1_port=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 1"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
    snmptrap2=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 2"|grep "TrapServerAddress"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g'|sed 's/}//g')
    snmptrap2_port=$(cat ${mydir}/snmptrap.txt|grep -A32 "TrapServer"|sed 's/"//g'|grep -A3 "MemberId: 2"|grep "TrapServerPort"|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1 > ${mydir}/systems.txt
    sed -i 's/,/\n/g' ${mydir}/systems.txt
#   bios版本
    bios_version=$(cat ${mydir}/systems.txt|grep "BiosVersion"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
#   启动方式
    BootMode=$(cat ${mydir}/systems.txt|grep "BootSourceOverrideMode"|sed 's/"//g'|awk -F: '{print $3}'|sed -e 's/[[:space:]]//g')
#   启动设备
    BootTarget=$(cat ${mydir}/systems.txt|sed 's/"//g'|grep -w "BootSourceOverrideTarget:"|awk -F": " '{print $2}')
#   主机名
    bmc_hostname=$(cat ${mydir}/systems.txt|grep "HostName"|sed -e 's/"//g' -e 's/[[:space:]]//g'|awk -F: '{print $2}')

    curl -s -k -w %{http_code} -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1 > ${mydir}/managers.txt
    sed -i 's/,/\n/g' ${mydir}/managers.txt
#   时区
    localtime=$(cat ${mydir}/managers.txt|grep "DateTimeLocalOffset"|sed 's/"//g'|awk -F": " '{print $2}')
#   bmc版本
    bmc_version=$(cat ${mydir}/managers.txt|grep "FirmwareVersion"|sed 's/"//g'|awk -F: '{print $2}'|sed -e 's/[[:space:]]//g')
}

################start##################
if [ ! -d "${PWD}/tmp_dir" ];then
    mkdir ${PWD}/tmp_dir
    mydir=${PWD}/tmp_dir
else
    mydir=${PWD}/tmp_dir
    continue
fi

echo "ip地址,子网掩码,网关地址,制造商,型号,序列号,bmc主机名,测试结果,\
id2用户,测试结果,id3用户,测试结果,id4用户,测试结果,id5用户,测试结果,id6用户,测试结果,id7用户,测试结果,id8用户,测试结果,用户权限,\
ntp地址1,ntp地址2,时区,snmp团体字,snmp连通性,snmp告警地址1,snmp告警地址1端口号,snmp告警地址2,snmp告警地址2端口号,\
bios版本,bmc版本,当前启动模式,当前启动设备" > check_result.csv
tr -d "\r" < bmclist.csv > ${mydir}/tmp_bmclist.csv
for LINE in `cat ${mydir}/tmp_bmclist.csv|sed "1d"`
do
    ip=`echo ${LINE}|awk -F, '{print $1}'`
    echo "正在收集${ip}服务器信息..."
    var_info

    ping_test
    user_test
    model_info
    user_priv
    choose_manufacturer
    compare_hostname
    snmp_test

    delete_info
    echo -e "${ip},${mask:-none},${gateway:-none},${manufacturer:-none},${model:-none},SN-${sn:-none},${bmc_hostname:-none},${hostname_result:-none},\
    ${id2_user}/${id2_pass},${id2_result},${id3_user}/${id3_pass},${id3_result},${id4_user}/${id4_pass},${id4_result},${id5_user}/${id5_pass},${id5_result},${id6_user}/${id6_pass},${id6_result},${id7_user}/${id7_pass},${id7_result},${id8_user}/${id8_pass},${id8_result},${priv:-none},\
    ${ntp1:-none},${ntp2:-none},${localtime:-none},${snmp_str:-none},${snmp_result},${snmptrap1:-none},${snmptrap1_port:-none},${snmptrap2:-none},${snmptrap2_port:-none},\
    ${bios_version:-none},${bmc_version:-none},${BootMode:-none},${BootTarget:-none}" >> check_result.csv
done
echo "收集完成!"
rm -rf headers.txt
rm -rf ${PWD}/tmp_dir

exit
