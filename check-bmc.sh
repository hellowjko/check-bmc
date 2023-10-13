#!/bin/bash
# bmc检查脚本

user_priv(){
list=`ipmitool -I lanplus -H ${ip} -U ${id2_user} -P ${id2_pass} user list`
id2_priv=`echo ${list} | grep "${id2_user}" | awk -F" " '{print $6}'`
id3_priv=`echo ${list} | grep "${id3_user}" | awk -F" " '{print $6}'`
id4_priv=`echo ${list} | grep "${id4_user}" | awk -F" " '{print $6}'`
id5_priv=`echo ${list} | grep "${id5_user}" | awk -F" " '{print $6}'`
id6_priv=`echo ${list} | grep "${id6_user}" | awk -F" " '{print $6}'`
id7_priv=`echo ${list} | grep "${id7_user}" | awk -F" " '{print $6}'`
id8_priv=`echo ${list} | grep "${id8_user}" | awk -F" " '{print $6}'`
echo "Priv: id2:${id2_priv}-id3:${id3_priv}-id4:${id4_priv}-id5:${id5_priv}-id6:${id6_priv}-id7:${id7_priv}-id8:${id8_priv}" >> ${ip}.txt
}

user_test(){
status=`ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 3 16 ${id3_pass}`
if [ "${status}" == "Success" ];then
    id3_result="Passed"
else
    id3_result="Failed"
fi
status=`ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 4 16 ${id4_pass}`
if [ "${status}" == "Success" ];then
    id4_result="Passed"
else
    id4_result="Failed"
fi
status=`ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 5 16 ${id5_pass}`
if [ "${status}" == "Success" ];then
    id5_result="Passed"
else
    id5_result="Failed"
fi
status=`ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 6 16 ${id6_pass}`
if [ "${status}" == "Success" ];then
    id6_result="Passed"
else
    id6_result="Failed"
fi
status=`ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 7 16 ${id7_pass}`
if [ "${status}" == "Success" ];then
    id7_result="Passed"
else
    id7_result="Failed"
fi
status=`ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} user test 8 16 ${id8_pass}`
if [ "${status}" == "Success" ];then
    id8_result="Passed"
else
    id8_result="Failed"
fi
}

id_info(){
id2=`echo ${LINE} | awk -F, '{print $2}'`
id2_user=`echo ${id2} | awk -F/ '{print $1}'`
id2_pass=`echo ${id2} | awk -F/ '{print $2}'`

id3=`echo ${LINE} | awk -F, '{print $3}'`
id3_user=`echo ${id3} | awk -F/ '{print $1}'`
id3_pass=`echo ${id3} | awk -F/ '{print $2}'`

id4=`echo ${LINE} | awk -F, '{print $4}'`
id4_user=`echo ${id4} | awk -F/ '{print $1}'`
id4_pass=`echo ${id4} | awk -F/ '{print $2}'`

id5=`echo ${LINE} | awk -F, '{print $5}'`
id5_user=`echo ${id5} | awk -F/ '{print $1}'`
id5_pass=`echo ${id5} | awk -F/ '{print $2}'`

id6=`echo ${LINE} | awk -F, '{print $6}'`
id6_user=`echo ${id6} | awk -F/ '{print $1}'`
id6_pass=`echo ${id6} | awk -F/ '{print $2}'`

id7=`echo ${LINE} | awk -F, '{print $7}'`
id7_user=`echo ${id7} | awk -F/ '{print $1}'`
id7_pass=`echo ${id7} | awk -F/ '{print $2}'`

id8=`echo ${LINE} | awk -F, '{print $8}'`
id8_user=`echo ${id8} | awk -F/ '{print $1}'`
id8_pass=`echo ${id8} | awk -F/ '{print $2}'`

useradmin=${id2_user}
adminpasswd=${id2_pass}
}
# 删除会话命令
session1(){
curl -k -H "X-Auth-Token: ${token}" -X DELETE https://${ip}/redfish/v1/SessionService/Sessions/${session_id}
}
session2(){
curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" -X DELETE https://${ip}/redfish/v1/SessionService/Sessions/${session_id}
}
# 删除会话
delete_session(){
if [ "${choose}" == "huawei" ];then
    session1
elif [ "${choose}" == "h3c" ];then
    session2
#    ......
fi
}

useradmin_test(){
state_code=`curl -k -H "Content-Type: application/json" -w %{http_code} -d '{"UserName":"${useradmin}", "Password":"${adminpasswd}"}' -X POST https://${ip}/redfish/v1/ | sed 's/,/\n/g' | awk -F"]" '{print $2}'`
#curl -k -H "Content-Type: application/json" -w %{http_code} -d '{"UserName":"${ydadmin}", "Password":"TD@40wyGYdJR@YLL"}' -X POST https://10.14.143.101/redfish/v1/ | sed 's/,/\n/g' | awk -F"]" '{print $2}'
if [ ${state_code} -eq 200 ];then
    echo "id2:Passed" >> ${ip}.txt
# 创建会话
    curl -k -H "Content-Type: application/json" -w %{http_code} -d '{"UserName":"${useradmin}", "Password":"${adminpasswd}"}' -X POST https://${ip}/redfish/v1/SessionService/Sessions -D headers.txt
#    curl -k -H "Content-Type: application/json" -w %{http_code} -d '{"UserName":"ydadmin", "Password":"TD@40wyGYdJR@YLL"}' -X POST https://10.14.143.101/redfish/v1/SessionService/Sessions -D headers.txt
# 获取token
    token=`cat headers.txt | grep "^X-Auth-Token" | awk '{print $2;}' | tr -d '"'`
# 获取会话id
    session_id=`cat headers.txt | grep "^Location" | awk '{print $2;}' | tr -d '"'`
# 查询所有会话
#    curl -k -H "X-Auth-Token: ${token}" -X GET https://10.14.143.101/redfish/v1/SessionService/Sessions
# 查询指定会话
#    curl -k -H "X-Auth-Token: ${token}" -X GET https://10.14.143.101/redfish/v1/SessionService/Sessions/${session_id}
else
    echo "id2:username or password is wrong,please check!"
    rm -rf /tmp/tmp_bmclist.csv
    rm -rf tmp_session
    exit 1
fi
}

choose_manufacturer(){
echo "${manufacturer}" | grep -i "h3c" > /dev/null
if [ $? -eq 0 ];then
    choose=h3c
fi
echo "${manufacturer}" | grep -i "huawei" > /dev/null
if [ $? -eq 0 ];then
    choose=huawei
fi
#......


case ${choose} in
    h3c)
        h3c_huawei_ntp
        h3c_snmptrap
        h3c_huawei_localtime
        ;;
    hawei)
        h3c_huawei_ntp
        huawei_snmptrap
        h3c_snmptrap
        h3c_huawei_localtime
        ;;
#......
    *)
        echo "miss match"
        exit 1
esac
}
#################ntp#################
h3c_huawei_ntp(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/NtpService > ntp.txt
ntp1=`cat ntp.txt | grep "PreferredNtpServer" | sed 's/"//g' | awk -F: '{print $2}'`
ntp2=`cat ntp.txt | grep "AlternateNtpServer" | sed 's/"//g' | awk -F: '{print $2}'`
rm -rf ntp.txt
}
##############snmp#############
h3c_snmptrap(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > snmptrap.txt
snmptrap1=`cat ntp.txt | grep -A12 "TrapServer" | sed 's/"//g' | grep -A1 "MemberId:1" | gerp "TrapServerAddress" | awk -F: '{print $1}'`
snmptrap2=`cat ntp.txt | grep -A12 "TrapServer" | sed 's/"//g' | grep -A1 "MemberId:2" | gerp "TrapServerAddress" | awk -F: '{print $1}'`
rm -rf snmptrap.txt
}
huawei_snmptrap(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/SnmpService > snmptrap.txt
snmptrap1=`cat ntp.txt | grep -A32 "TrapServer" | sed 's/"//g' | grep -A5 "MemberId:0" | gerp "TrapServerAddress" | awk -F: '{print $1}'`
snmptrap2=`cat ntp.txt | grep -A32 "TrapServer" | sed 's/"//g' | grep -A5 "MemberId:1" | gerp "TrapServerAddress" | awk -F: '{print $1}'`
rm -rf snmptrap.txt
}
#############localtime###########
h3c_huawei_localtime(){
curl -k -H "X-Auth-Token: ${token}" -X GET https://${ip}/redfish/v1/Managers/1/ > localtime.txt
localtime=`cat localtime.txt | grep "DateTimeLocalOffset" | sed 's/"//g' | awk -F: '{print $2}' | sed 's/,//g'`
rm -rf ntp.txt
}

model_info(){
ipmitool -I lanplus -H ${useradmin} -U ${adminpasswd} lan print > net_info.txt
mask=`cat net_info.txt | grep "Subnet Mask" | awk -F: '{print $2}'`
echo "mask:${mask}" >> ${ip}.txt
gateway=`cat net_info.txt | grep "Default Gateway IP" | awk -F: '{print $2}'`
echo "gateway:${gateway}" >> ${ip}.txt
snmp_str=`cat net_info.txt | grep "SNMP Community String" | awk -F: '{print $2}'`
echo "snmp:${snmp_str}" >> ${ip}.txt
ipmitool -I lanplus -H ${ip} -U ${useradmin} -P ${adminpasswd} fru > fru_info.txt
sn=`cat fru_info.txt | grep "Product Serial" | awk -F: '{print $2}' | head -n 1`
echo "sn:${sn}" >> ${ip}.txt
manufacturer=`cat fru_info.txt | grep "Product Manufacturer" | awk -F: '{print $2}' | head -n 1`
echo "manufacturer:${manufacturer}" >> ${ip}.txt
model=`cat fru_info.txt | grep "Product Name" | awk -F: '{print $2}' | head -n 1`
echo "model:${model}" >> ${ip}.txt
}
ping_test(){
ping ${ip} -c 2 > /dev/null
if [ $? -eq 0 ];then
    echo "${ip} ping通!"
else
    echo "${ip} ping不通!"
    break
fi
}

################start##################
echo -e "ip地址,子网掩码,网关地址,制造商,型号,id2用户,测试结果,id3用户,测试结果,id4用户,测试结果,id5用户,测试结果,id6用户,测试结果,id7用户,测试结果,id8用户,测试结果,用户权限,ntp地址1,ntp地址2,时区,snmp团体字,snmp告警地址1,snmp告警地址2" > check_result.csv
tr -d "\r" < bmclist.csv > tmp_bmclist.csv
for LINE in `cat tmp_bmclist.csv | sed "1d"`
do
    ip=`echo ${LINE} | awk -F, '{print $1}'`
    echo "${ip}"
    > ${ip}.txt
    id_info

    ping_test
    id2_test
    model_info
    user_test
    user_priv
    choose_manufacturer



    delete_session
    echo -e "${ip},${mask},${gateway},${manucturer},${model},${id2_user}/${id2_pass},result,${id3_user}/${id3_pass},${id3_result},${id4_user}/${id4_pass},${id4_result},${id5_user}/${id5_pass},${id5_result},${id6_user}/${id6_pass},${id6_result},${id7_user}/${id7_pass},${id7_result},${id8_user}/${id8_pass},${id8_result},priv,ntp1,ntp2,localtime,snmp,snmptrap1,snmptrap2" >> check_result.csv
done
rm -rf tmp_bmclist.csv
exit
