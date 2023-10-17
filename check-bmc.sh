#!/bin/bash
# 名称: bmc检查脚本
# 描述：支持的服务器制造商：华为、华三
#      此脚本运行环境需安装ipmitool、net-snmp-utils、curl安装包

# ping测试
ping_test(){
ping ${ip} -c 1 > /dev/null
if [ $? -eq 0 ];then
    echo "${ip} ping通!" > /dev/null
else
    echo "${ip} ping不通!" > /dev/null
    break
fi
}
# 型号信息
model_info(){
ipmitool -I lanplus -H ${useradmin} -U ${adminpasswd} lan print > ${mydir}/net_info.txt
mask=$(cat ${mydir}/net_info.txt | grep "Subnet Mask" | awk -F: '{print $2}')
#echo "mask:${mask}" >> ${ip}.txt
gateway=$(cat ${mydir}/net_info.txt | grep "Default Gateway IP" | awk -F: '{print $2}')
#echo "gateway:${gateway}" >> ${ip}.txt
snmp_str=$(cat ${mydir}/net_info.txt | grep "SNMP Community String" | awk -F: '{print $2}')
#echo "snmp:${snmp_str}" >> ${ip}.txt
ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} fru > ${mydir}/fru_info.txt
sn=$(cat ${mydir}/fru_info.txt | grep "Product Serial" | awk -F: '{print $2}' | head -n 1)
#echo "sn:${sn}" >> ${ip}.txt
manufacturer=$(cat ${mydir}/fru_info.txt | grep "Product Manufacturer" | awk -F: '{print $2}' | head -n 1)
#echo "manufacturer:${manufacturer}" >> ${ip}.txt
model=$(cat ${mydir}fru_info.txt | grep "Product Name" | awk -F: '{print $2}' | head -n 1)
#echo "model:${model}" >> ${ip}.txt
}
snmp_test(){
snmpwalk -v 2c -c ${snmp_str} ${ip} sysname > /dev/null 2>&1
if [ $? -eq 0 ];then
#    echo "Passed"
    snmp_result="Passed"
else
#    echo "Failed"
    snmp_result="Failed"
fi
}
# 用户权限
user_priv(){
list=`ipmitool -I lanplus -H ${ip} -U ${id2_user} -P ${id2_pass} user list`
id2_priv=$(echo ${list} | grep "${id2_user}" | awk -F" " '{print $6}')
id3_priv=$(echo ${list} | grep "${id3_user}" | awk -F" " '{print $6}')
id4_priv=$(echo ${list} | grep "${id4_user}" | awk -F" " '{print $6}')
id5_priv=$(echo ${list} | grep "${id5_user}" | awk -F" " '{print $6}')
id6_priv=$(echo ${list} | grep "${id6_user}" | awk -F" " '{print $6}')
id7_priv=$(echo ${list} | grep "${id7_user}" | awk -F" " '{print $6}')
id8_priv=$(echo ${list} | grep "${id8_user}" | awk -F" " '{print $6}')
priv=$(echo -e "id2:${id2_priv:-none}-id3:${id3_priv:-none}-id4:${id4_priv:-none}-id5:${id5_priv:-none}-id6:${id6_priv:-none}-id7:${id7_priv:-none}-id8:${id8_priv:-none}")
}
# 用户密码测试
user_test(){
if [ "${id2_user}" == "none" ];then
    id2_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 2 16 ${id2_pass})
    if [ "${status}" == "Success" ];then
        id2_result="Passed"
    else
        id2_result="Failed"
        echo "username or password is wrong,please check"
        exit 1
    fi
fi

if [ "${id3_user}" == "none" ];then
    id3_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 3 16 ${id3_pass})
    if [ "${status}" == "Success" ];then
        id3_result="Passed"
    else
        id3_result="Failed"
    fi
fi

if [ "${id4_user}" == "none" ];then
    id4_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 4 16 ${id4_pass})
    if [ "${status}" == "Success" ];then
        id4_result="Passed"
    else
        id4_result="Failed"
    fi
fi

if [ "${id5_user}" == "none" ];then
    id5_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 5 16 ${id5_pass})
    if [ "${status}" == "Success" ];then
        id5_result="Passed"
    else
        id5_result="Failed"
    fi
fi

if [ "${id6_user}" == "none" ];then
    id6_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 6 16 ${id6_pass})
    if [ "${status}" == "Success" ];then
        id6_result="Passed"
    else
        id6_result="Failed"
    fi
fi

if [ "${id7_user}" == "none" ];then
    id7_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 7 16 ${id7_pass})
    if [ "${status}" == "Success" ];then
        id7_result="Passed"
    else
        id7_result="Failed"
    fi
fi

if [ "${id8_user}" == "none" ];then
    id8_result="none"
else
    status=$(ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 8 16 ${id8_pass})
    if [ "${status}" == "Success" ];then
        id8_result="Passed"
    else
        id8_result="Failed"
    fi
fi
}

id_info(){
id2=$(echo ${LINE} | awk -F, '{print $2}')
if [ ! -z "${id2}" ];then
    id2_user=`echo ${id2} | awk -F/ '{print $1}'`
    id2_pass=`echo ${id2} | awk -F/ '{print $2}'`
else
    id2_user="none"
    id2_pass="none"
fi

id3=$(echo ${LINE} | awk -F, '{print $3}')
if [ ! -z "${id3}" ];then
    id3_user=`echo ${id3} | awk -F/ '{print $1}'`
    id3_pass=`echo ${id3} | awk -F/ '{print $2}'`
else
    id3_user="none"
    id3_pass="none"
fi

id4=$(echo ${LINE} | awk -F, '{print $4}')
if [ ! -z "${id4}" ];then
    id4_user=`echo ${id4} | awk -F/ '{print $1}'`
    id4_pass=`echo ${id4} | awk -F/ '{print $2}'`
else
    id4_user="none"
    id4_pass="none"
fi

id5=$(echo ${LINE} | awk -F, '{print $5}')
if [ ! -z "${id5}" ];then
    id5_user=`echo ${id5} | awk -F/ '{print $1}'`
    id5_pass=`echo ${id5} | awk -F/ '{print $2}'`
else
    id5_user="none"
    id5_pass="none"
fi

id6=$(echo ${LINE} | awk -F, '{print $6}')
if [ ! -z "${id6}" ];then
    id6_user=`echo ${id6} | awk -F/ '{print $1}'`
    id6_pass=`echo ${id6} | awk -F/ '{print $2}'`
else
    id6_user="none"
    id6_pass="none"
fi

id7=$(echo ${LINE} | awk -F, '{print $7}')
if [ ! -z "${id7}" ];then
    id7_user=`echo ${id7} | awk -F/ '{print $1}'`
    id7_pass=`echo ${id7} | awk -F/ '{print $2}'`
else
    id7_user="none"
    id7_pass="none"
fi

id8=$(echo ${LINE} | awk -F, '{print $8}')
if [ ! -z "${id8}" ];then
    id8_user=`echo ${id8} | awk -F/ '{print $1}'`
    id8_pass=`echo ${id8} | awk -F/ '{print $2}'`
else
    id8_user="none"
    id8_pass="none"
fi
# 设置ipmitool管理账号
useradmin=${id2_user}
adminpasswd=${id2_pass}
}
# 删除会话指令
# 华为删除会话指令
session1(){
curl -k -H "X-Auth-Token: ${token}" -X DELETE https://${ip}/redfish/v1/SessionService/Sessions/${session_id} > /dev/null
rm -rf headers.txt
rm -rf tmp_headers.txt
}
# 华三删除会话指令
session2(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X DELETE https://${ip}/redfish/v1/SessionService/Sessions/${session_id} > /dev/null
rm -rf headers.txt
rm -rf tmp_headers.txt
}

# 删除会话
delete_info(){
case ${choose} in
    huawei)
        session1
        ;;
    h3c)
        session2
#   ......
esac
rm -rf ${PWD}/tmp_dir
fi
}
# redfish会话
redfish_session(){
# 创建会话
curl -D headers.txt -k -H "Content-Type: application/json" -w %{http_code} -d '{"UserName":"${useradmin}", "Password":"${adminpasswd}"}' -X POST https://${ip}/redfish/v1/SessionService/Sessions > /dev/null
# 获取token
tr -d "\r" < headers.txt > ${mydir}/tmp_headers.txt
token=$(cat ${mydir}/tmp_headers.txt | grep "^X-Auth-Token" | awk '{print $2;}' | tr -d '"')
# 获取会话id
session_id=$(cat ${mydir}/tmp_headers.txt | grep "^Location" | awk '{print $2;}' | tr -d '"' | awk -F/ '{print $6}')
# 查询所有会话
#curl -k -H "X-Auth-Token: ${token}" -X GET https://10.14.143.101/redfish/v1/SessionService/Sessions
# 查询指定会话
#curl -k -H "X-Auth-Token: ${token}" -X GET https://10.14.143.101/redfish/v1/SessionService/Sessions/${session_id}
}

# 获取其他信息
choose_manufacturer(){
echo "${manufacturer}" | grep -i "huawei" > /dev/null
if [ $? -eq 0 ];then
    choose="huawei"
fi
echo "${manufacturer}" | grep -i "h3c" > /dev/null
if [ $? -eq 0 ];then
    choose="h3c"
fi
#......

case ${choose} in
    huawei)
        huawei_ntp
        huawei_snmptrap
        huawei_localtime
        huawei_bios_version
        huawei_bmc_version
        ;;
    h3c)
        h3c_ntp
        h3c_snmptrap
        h3c_localtime
        h3c_bios_version
        h3c_bmc_version
        ;;
#......
    *)
        echo "miss match"
esac
}
#################ntp#################
huawei_ntp(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
sed -i 's/,/\n/g' ${mydir}/ntp.txt
tr -d "\r" < ${mydir}/ntp.txt > ${mydir}/tmp_ntp.txt
ntp1=$(cat ${mydir}/tmp_ntp.txt | grep "PreferredNtpServer" | sed 's/"//g' | awk -F: '{print $2}')
ntp2=$(cat ${mydir}/tmp_ntp.txt | grep "AlternateNtpServer" | sed 's/"//g' | awk -F: '{print $2}')
}
h3c_ntp(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ${mydir}/ntp.txt
sed -i 's/,/\n/g' ${mydir}/ntp.txt
ntp1=$(cat ${mydir}/ntp.txt | grep "PreferredNtpServer" | sed 's/"//g' | awk -F: '{print $2}')
ntp2=$(cat ${mydir}/ntp.txt | grep "AlternateNtpServer" | sed 's/"//g' | awk -F: '{print $2}')
}
##############snmp#############
huawei_snmptrap(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
snmptrap1=$(cat ${mydir}/snmptrap.txt | grep -A32 "TrapServer" | sed 's/"//g' | grep -A5 "MemberId:0" | gerp "TrapServerAddress" | awk -F: '{print $1}')
snmptrap2=$(cat ${mydir}/snmptrap.txt | grep -A32 "TrapServer" | sed 's/"//g' | grep -A5 "MemberId:1" | gerp "TrapServerAddress" | awk -F: '{print $1}')
}
h3c_snmptrap(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > ${mydir}/snmptrap.txt
sed -i 's/,/\n/g' ${mydir}/snmptrap.txt
snmptrap1=$(cat ${mydir}/snmptrap.txt | grep -A12 "TrapServer" | sed 's/"//g' | grep -A1 "MemberId:1" | gerp "TrapServerAddress" | awk -F: '{print $1}')
snmptrap2=$(cat ${mydir}/snmptrap.txt | grep -A12 "TrapServer" | sed 's/"//g' | grep -A1 "MemberId:2" | gerp "TrapServerAddress" | awk -F: '{print $1}')
}
#############localtime###########
huawei_localtime(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/ > ${mydir}/localtime.txt
sed -i 's/,/\n/g' ${mydir}/localtime.txt
localtime=$(cat ${mydir}/localtime.txt | grep "DateTimeLocalOffset" | sed 's/"//g' | awk -F: '{print $2}')
}
h3c_localtime(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/ > ${mydir}/localtime.txt
sed -i 's/,/\n/g' ${mydir}/localtime.txt
localtime=$(cat ${mydir}/localtime.txt | grep "DateTimeLocalOffset" | sed 's/"//g' | awk -F: '{print $2}')
}
##############bios version###############
huawei_bios_version(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1/ > ${mydir}/bios_version.txt
sed -i 's/,/\n/g' ${mydir}/bios_version.txt
bios_version=$(cat ${mydir}/bios_version.txt | grep "BiosVersion" | sed 's/"//g' | awk -F: '{print $2}')
}
h3c_bios_version(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1/ > ${mydir}/bios_version.txt
sed -i 's/,/\n/g' ${mydir}/bios_version.txt
bios_version=$(cat ${mydir}/bios_version.txt | grep "BiosVersion" | sed 's/"//g' | awk -F: '{print $2}')
}
#############bmc version##############
huawei_bmc_version(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/ > ${mydir}/bmc_version.txt
sed -i 's/,/\n/g' ${mydir}/bmc_version.txt
bmc_version=$(cat ${mydir}/bmc_version.txt | grep "FirmwareVersion" | sed 's/"//g' | awk -F: '{print $2}')
}
h3c_bmc_version(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/ > ${mydir}/bmc_version.txt
sed -i 's/,/\n/g' ${mydir}/bmc_version.txt
bmc_version=$(cat ${mydir}/bmc_version.txt | grep "FirmwareVersion" | sed 's/"//g' | awk -F: '{print $2}')
}
#############bmc hostname############
huawei_bmc_hostname(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/ > ${mydir}/bmc_hostname.txt
sed -i 's/,/\n/g' ${mydir}/bmc_hostname.txt
bmc_hostname=$(cat ${mydir}/bmc_hostname.txt | grep "HostName" | sed 's/"//g' | awk -F: '{print $2}')
}
h3c_bmc_hostname(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Systems/1/ > ${mydir}/bmc_hostname.txt
sed -i 's/,/\n/g' ${mydir}/bmc_hostname.txt
bmc_hostname=$(cat ${mydir}/bmc_hostname.txt | grep "HostName" | sed 's/"//g' | awk -F: '{print $2}')
}



################start##################
if [ ! -d "${PWD}/tmp_dir" ];then
    mkdir ${PWD}/tmp_dir
    mydir=${PWD}/tmp_dir
else
    mydir=${PWD}/tmp_dir
    break
fi

echo -n "ip地址,子网掩码,网关地址,bmc主机名,制造商,型号,序列号,id2用户,测试结果,id3用户,测试结果,id4用户,测试结果,id5用户,测试结果,id6用户,测试结果,id7用户,测试结果,id8用户,测试结果,用户权限,ntp地址1,ntp地址2,时区,snmp团体字,snmp连通性,snmp告警地址1,snmp告警地址2,bmc版本,bios版本" > check_result.csv
tr -d "\r" < bmclist.csv > ${mydir}/tmp_bmclist.csv
for LINE in `cat ${mydir}/tmp_bmclist.csv | sed "1d"`
do
    ip=`echo ${LINE} | awk -F, '{print $1}'`
    echo "${ip}"
#    > ${PWD}/${ip}.txt
    id_info

    ping_test
    user_test
    model_info
    snmp_test
    user_priv
    redfish_session
    choose_manufacturer

    delete_info
    echo -e "${ip},${mask:-none},${gateway:-none},${bmc_hostname:-none},${manucturer:-none},${model:-none},${sn:-none},${id2_user}/${id2_pass},${id2_result},${id3_user}/${id3_pass},${id3_result},${id4_user}/${id4_pass},${id4_result},${id5_user}/${id5_pass},${id5_result},${id6_user}/${id6_pass},${id6_result},${id7_user}/${id7_pass},${id7_result},${id8_user}/${id8_pass},${id8_result},${priv:-none},${ntp1:-none},${ntp2:-none},${localtime:-none},${snmp_str:-none},${snmp_result},${snmptrap1:-none},${snmptrap2:-none},${bios_version:-none},${bmc_version:-none}" >> check_result.csv
done

exit
