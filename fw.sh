#!/bin/bash


# 定義顏色
GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BOLD_CYAN="\033[1;36;1m"
RESET="\033[0m"

version="5.0.0"

# 檢查是否以root權限運行
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${YELLOW}此腳本需要root權限運行${RESET}" 
  if command -v sudo >/dev/null 2>&1; then
    exec sudo "$0" "$@"
  else
    install_sudo_cmd=""
    if command -v apt >/dev/null 2>&1; then
      install_sudo_cmd="apt-get update && apt-get install -y sudo"
    elif command -v yum >/dev/null 2>&1; then
      install_sudo_cmd="yum install -y sudo"
    elif command -v apk >/dev/null 2>&1; then
      install_sudo_cmd="apk add sudo"
    else
      echo -e "${RED}無sudo指令${RESET}"
      sleep 1
      exit 1
    fi
    su -c "$install_sudo_cmd"
    if [ $? -eq 0 ] && command -v sudo >/dev/null 2>&1; then
      echo -e "${GREEN}sudo指令已經安裝成功，請等下輸入您的密碼${RESET}"
      exec sudo "$0" "$@"
    fi
  fi
fi


allow_port() {
  local PROTO="$1"  # 第一個參數是協議類型
  if [ -z "$2" ]; then
    echo -e "${RED}錯誤：未指定端口號${RESET}" >&2
    sleep 1
    return 1
  fi
  
  if [ -z "$PROTO" ]; then
    PROTO="tcp"  # 如果協議未提供，默認為TCP
  fi
  shift  # 移動參數，剩餘的是端口列表
  local PORTS=("$@")
  if [ $fw = ufw ]; then
    for PORT in "${PORTS[@]}"; do
      if [ -z "$PORT" ]; then
        continue  # 跳過空端口
      fi
      ufw allow $PORT/$PROTO
    done
    return 0
  fi
  for PORT in "${PORTS[@]}"; do
    if [ -z "$PORT" ]; then
      continue  # 跳過空端口
    fi
    # ipv4
    if ! iptables -C INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
      if iptables -A INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
        echo -e "${GREEN}IPv4 $PROTO 端口 $PORT 已開啟${RESET}" >&2
      else
        echo -e "${RED}錯誤：無法開啟 IPv4 $PROTO 端口 $PORT${RESET}" >&2
      fi
    fi
    # ipv6
    if ! ip6tables -C INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
      if ip6tables -A INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
        echo -e "${GREEN}IPv6 $PROTO 端口 $PORT 已開啟${RESET}" >&2
      else
        echo -e "${RED}錯誤：無法開啟 IPv6 $PROTO 端口 $PORT${RESET}" >&2
      fi
    fi
  done
  return 0
}
allow_ping() {
  if [ $fw = ufw ]; then
    sed -i 's/--icmp-type echo-request -j DROP/--icmp-type echo-request -j ACCEPT/' /etc/ufw/before.rules
    sed -i 's/--icmpv6-type echo-request -j DROP/--icmpv6-type echo-request -j ACCEPT/' /etc/ufw/before6.rules
    ufw reload
    echo -e "${GREEN}ICMP 已開啟${RESET}" >&2
    return
  fi

  # IPv4
  iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
  iptables -I INPUT -p icmp --icmp-type echo-request -j ACCEPT
  # IPv6
  ip6tables -D INPUT -p ipv6-icmp --icmpv6-type 128 -j DROP 2>/dev/null
  ip6tables -I INPUT -p ipv6-icmp --icmpv6-type 128 -j ACCEPT
  echo -e "${GREEN}ICMP 已開啟${RESET}" >&2

  save_rules
}

block_ping() {
  if [ $fw = ufw ]; then
    sed -i 's/--icmp-type echo-request -j ACCEPT/--icmp-type echo-request -j DROP/' /etc/ufw/before.rules
    sed -i 's/--icmpv6-type echo-request -j ACCEPT/--icmpv6-type echo-request -j DROP/' /etc/ufw/before6.rules
    ufw reload
    echo -e "${GREEN}ICMP 已封鎖${RESET}" >&2
    return
  fi

  # IPv4
  iptables -D INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null
  iptables -I INPUT -p icmp --icmp-type echo-request -j DROP

  # IPv6
  # 禁止 IPv6 ping（Echo Request）
  ip6tables -D INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT 2>/dev/null
  ip6tables -I INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j DROP
  echo -e "${GREEN}ICMP 已封鎖${RESET}" >&2
  save_rules
}

allow_cf_ip() (
  if [ "$fw" = ufw ]; then
    local temp_file_v4="/tmp/cloudflare_ips_v4.txt"
    local temp_file_v6="/tmp/cloudflare_ips_v6.txt"

    curl -s https://www.cloudflare.com/ips-v4 > "$temp_file_v4"
    curl -s https://www.cloudflare.com/ips-v6 > "$temp_file_v6"

    while read -r ip; do
      if [[ -n "$ip" ]]; then
        if ! ufw status | grep -q "ALLOW.*$ip"; then
          ufw allow from "$ip"
        fi
      fi
    done < "$temp_file_v4"

    while read -r ip; do
      if [[ -n "$ip" ]]; then
        if ! ufw status | grep -q "ALLOW.*$ip"; then
          ufw allow from "$ip"
        fi
      fi
    done < "$temp_file_v6"

    rm -f "$temp_file_v4" "$temp_file_v6"
    echo -e "${GREEN}已完成 Cloudflare IPv4 / IPv6 規則添加。${RESET}"
    return
  fi
  # Cloudflare IP 列表的 URL
  local CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
  local CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

  # 定義允許的 iptables 規則鏈
  local CHAIN_NAME="ALLOW_CF"

  # 刪除舊的規則鏈（如果存在）
  iptables -F $CHAIN_NAME 2>/dev/null
  iptables -X $CHAIN_NAME 2>/dev/null
  ip6tables -F $CHAIN_NAME 2>/dev/null
  ip6tables -X $CHAIN_NAME 2>/dev/null

  # 創建新規則鏈
  iptables -N $CHAIN_NAME
  ip6tables -N $CHAIN_NAME

  while IFS= read -r ip; do
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
      iptables -A $CHAIN_NAME -s "$ip" -j ACCEPT
    fi
  done < <(curl -s "$CF_IPV4_URL")

  echo "下載並添加 Cloudflare 的 IPv6 地址..."
  while IFS= read -r ip6; do
    if [[ "$ip10" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
      ip6tables -A $CHAIN_NAME -s "$ip6" -j ACCEPT
      echo "已允許 IPv6 地址：$ip6"
    fi
  done < <(curl -s "$CF_IPV6_URL")

  # 將規則應用到 INPUT 連接
  iptables -A INPUT -j $CHAIN_NAME
  ip6tables -A INPUT -j $CHAIN_NAME

  save_rules
  echo -e "${GREEN}已完成 Cloudflare IPv4 / IPv6 規則添加。${RESET}"

)

del_cf_ip(){
  if [ "$fw" = ufw ]; then
    local temp_file_v4="/tmp/cloudflare_ips_v4.txt"
    local temp_file_v6="/tmp/cloudflare_ips_v6.txt"

    curl -s https://www.cloudflare.com/ips-v4 > "$temp_file_v4"
    curl -s https://www.cloudflare.com/ips-v6 > "$temp_file_v6"

    while read -r ip; do
      if [[ -n "$ip" ]]; then
        if ufw status | grep -q "ALLOW.*$ip"; then
          ufw delete allow from "$ip"
        fi
      fi
    done < "$temp_file_v4"

    while read -r ip; do
      if [[ -n "$ip" ]]; then
        if ufw status | grep -q "ALLOW.*$ip"; then
          ufw delete allow from "$ip"
        fi
      fi
    done < "$temp_file_v6"

    rm -f "$temp_file_v4" "$temp_file_v6"
    echo -e "${GREEN}已完成 Cloudflare IPv4 / IPv6 規則刪除。${RESET}"
    return
  fi

  # Cloudflare IP 列表的 URL
  local CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
  local CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

  

  # 定義允許的 iptables 規則鏈
  local CHAIN_NAME="ALLOW_CF"

  while IFS= read -r ip; do
    if [[ "$ip9" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
      iptables -D $CHAIN_NAME -s "$ip" -j ACCEPT 2>/dev/null
    fi
  done < <(curl -s "$CF_IPV4_URL")

  while IFS= read -r ip6; do
    if [[ "$ip6" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
      ip6tables -D $CHAIN_NAME -s "$ip6" -j ACCEPT 2>/dev/null
    fi
  done < <(curl -s "$CF_IPV6_URL")

  # 刪除規則鏈
  iptables -F $CHAIN_NAME 2>/dev/null
  iptables -X $CHAIN_NAME 2>/dev/null
  ip6tables -F $CHAIN_NAME 2>/dev/null
  ip6tables -X $CHAIN_NAME 2>/dev/null
  iptables -D INPUT -j $CHAIN_NAME 2>/dev/null
  ip6tables -D INPUT -j $CHAIN_NAME 2>/dev/null

  save_rules

  echo -e "${GREEN}已完成 Cloudflare IPv4 / IPv6 規則刪除。${RESET}"
}

censys_block() {
  local action="$1"  # 用法：add 或 del

  local ipv4_list=(
    66.132.159.0/24
    162.142.125.0/24
    167.94.138.0/24
    167.94.145.0/24
    167.94.146.0/24
    167.248.133.0/24
    199.45.154.0/24
    199.45.155.0/24
    206.168.34.0/24
    206.168.35.0/24
  )

  local ipv6_list=(
    2602:80d:1000:b0cc:e::/80
    2620:96:e000:b0cc:e::/80
    2602:80d:1003::/112
    2602:80d:1004::/112
  )

  if [[ "$action" == "add" ]]; then
    if [ "$fw" = ufw ]; then

        # 合併 IPv4 與 IPv6 為一個陣列
        local combined_ips=( "${ipv4_list[@]}" "${ipv6_list[@]}" )

        for ip in "${combined_ips[@]}"; do
            ufw deny from "$ip" 2>/dev/null
        done

        echo -e "${GREEN}已將所有 CENSYS IP 加入封鎖規則${RESET}"
        return
    fi
    iptables -N CENSYS_BLOCK 2>/dev/null
    ip6tables -N CENSYS_BLOCK 2>/dev/null

    iptables -C INPUT -j CENSYS_BLOCK 2>/dev/null || iptables -I INPUT -j CENSYS_BLOCK
    ip6tables -C INPUT -j CENSYS_BLOCK 2>/dev/null || ip6tables -I INPUT -j CENSYS_BLOCK

    for ip in "${ipv4_list[@]}"; do
      iptables -I CENSYS_BLOCK -s "$ip" -j DROP
    done

    for ip in "${ipv6_list[@]}"; do
      ip6tables -I CENSYS_BLOCK -s "$ip" -j DROP
    done
    echo -e "${GREEN}已將所有 CENSYS IP 加入封鎖規則${RESET}"

  elif [[ "$action" == "del" ]]; then
    if [ "$fw" = ufw ]; then

        # 合併 IPv4 與 IPv6 為一個陣列
        local combined_ips=( "${ipv4_list[@]}" "${ipv6_list[@]}" )

        for ip in "${combined_ips[@]}"; do
            echo "刪除阻止規則：$ip"
            ufw delete deny from "$ip" 2>/dev/null
        done

        echo -e "${GREEN}已將所有 CENSYS IP刪除封鎖規則${RESET}"
        return
    fi
    iptables -F CENSYS_BLOCK 2>/dev/null
    iptables -D INPUT -j CENSYS_BLOCK 2>/dev/null
    iptables -X CENSYS_BLOCK 2>/dev/null

    ip6tables -F CENSYS_BLOCK 2>/dev/null
    ip6tables -D INPUT -j CENSYS_BLOCK 2>/dev/null
    ip6tables -X CENSYS_BLOCK 2>/dev/null
  else
    echo -e "${YELLOW}[!] 請使用參數：add 或 del${RESET}"
  fi
}


check_system(){
  if command -v apt >/dev/null 2>&1; then
    system=1
  elif command -v yum >/dev/null 2>&1; then
    system=2
  elif command -v apk >/dev/null 2>&1; then
    system=3
   else
    echo "不支援的系統。" >&2
    exit 1
  fi
}

check_ip() {
  local ip="$1"
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
    IFS='.' read -r -a octets <<< "${ip%%/*}"
    for octet in "${octets[@]}"; do
    if (( octet < 0 || octet > 255 )); then
      echo -e "${RED}無效的 IP 地址：每個八位元組必須在 0-255 之間${RESET}"
      sleep 1
      return 1
    fi
    done
    if [[ "$ip" == */* ]]; then
      local cidr="${ip##*/}"
      if (( cidr < 0 || cidr > 32 )); then
      echo -e "${RED}無效的 CIDR 前綴：必須在 0-32 之間${RESET}"
      return 1
      fi
    fi
    return 0
    elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
      if [[ "$ip" == */* ]]; then
      local cidr="${ip##*/}"
      if (( cidr < 0 || cidr > 128 )); then
          echo "無效的 CIDR 前綴：對於 IPv6 必須在 0-128 之間"
          return 1
      fi
    fi
    return 0
  else
    echo "無效的 IP 地址格式"
    return 1
  fi
}

check_port() {
    local port="$1"
    local proto="$2"

    # 檢查端口是否為有效的數字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo -e "${YELLOW}請輸入有效的數字端口號${RESET}"
        return 1
    # 檢查端口範圍是否正確
    elif (( port < 1 || port > 65535 )); then
        echo -e "${YELLOW}端口號必須在 1-65535 範圍內${RESET}"
        return 1
    fi

    # 預設協議為 tcp
    local proto=${proto:-tcp}

    # 檢查協議是否有效
    if [[ $proto != "tcp" && $proto != "udp" ]]; then
        echo -e "${RED}無效的協議類型，請使用tcp或udp${RESET}"
        return 1
    fi

    return 0
}

check_app() {
  if ! command -v jq >/dev/null 2>&1; then
    case "$system" in 
      1)
        apt update -y
        apt install jq -y
        ;;
      2)
        yum update -y
        yum install -y jq
        ;;
      3)
        apk update
        apk add jq
        ;;
    esac
  fi
  if ! command -v wget >/dev/null 2>&1; then
    case "$system" in 
      1)
        apt update -y
        apt install wget -y
        ;;
      2)
        yum update -y
        yum install -y wget
        ;;
      3)
        apk update
        apk add wget
        ;;
    esac
  fi
}

check_cli_fw() {
  [ "$fw" == "none" ] && echo -e "${YELLOW}您好，您尚未安裝防火牆軟體，請先安裝再進行執行cli工具${RESET}" >&2 && sleep 1 && exit 1
}
check_fw() {
    fw="none"
    if command -v ufw >/dev/null 2>&1; then
        fw=ufw
    elif command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${RED}檢測到firewalld,請解除安裝。${RESET}" >&2
        sleep 1
        exit 1
    elif command -v iptables >/dev/null 2>&1; then
        check_iptables
    fi
}

check_iptables(){
  case "$system" in 
  1)
    if command -v netfilter-persistent > /dev/null 2>&1; then
      fw=iptables
    fi
    ;;
  2)
    if systemctl list-unit-files | grep iptables > /dev/null 2>&1; then
      fw=iptables
    fi
    ;;
  3)
    if rc-service iptables status > /dev/null 2>&1; then
      fw=iptables
    fi
    ;;
  esac
}
check_docker(){
  if command -v docker &>/dev/null; then
    service docker restart
  fi
}

default_settings(){
  # 取得 SSH 設定中的 Port，若未設定則預設為 22
  local ssh_port=$(grep -E '^Port ' /etc/ssh/sshd_config | awk '{print $2}')

  # 如果未設定Port則預設為22
  if [[ -z "$ssh_port" ]]; then
    ssh_port=22
  fi
  echo "SSH端口是：$ssh_port"
  if [ "$system" -eq 1 ]; then
    # 設定需要替換的路徑
    local rules_v4="/etc/iptables/rules.v4"
    local rules_v6="/etc/iptables/rules.v6"
    rm /etc/iptables/rules.v4 /etc/iptables/rules.v6
    # 生成規則文件
    cat > "$rules_v4" <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport <port> -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT

COMMIT
EOF
    cat > "$rules_v6" <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j ACCEPT

# 保留連線與本機 loopback
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport <port> -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT

COMMIT
EOF

    chmod 600 "$rules_v6"
    chmod 600 "$rules_v4"
    chmod 600 "$rules_v6"
    # 替換 /etc/iptables/rules.v4 中的 <port> 為實際的 SSH port
    if [[ -f "$rules_v4" ]]; then
      sed -i "s/<port>/$ssh_port/g" "$rules_v4"
      echo "Replaced <port> in $rules_v4 with $ssh_port"
    else
      echo "$rules_v4 does not exist."
    fi

    # 替換 /etc/iptables/rules.v6 中的 <port> 為實際的 SSH port
    if [[ -f "$rules_v6" ]]; then
      sed -i "s/<port>/$ssh_port/g" "$rules_v6"
      echo "Replaced <port> in $rules_v6 with $ssh_port"
    else
      echo "$rules_v6 does not exist."
    fi
    iptables-restore < /etc/iptables/rules.v4
    ip6tables-restore < /etc/iptables/rules.v6
    systemctl restart netfilter-persistent
  elif [[ "$system" -eq 2 || "$system" -eq 3 ]]; then
    service iptables stop
    service ip6tables stop
    #ipv4
    iptables -F
    iptables -A INPUT -p tcp --dport $ssh_port -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    #ipv6
    ip6tables -F
    ip6tables -X

    # 接受 loopback
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A FORWARD -i lo -j ACCEPT

    # 允許你自己的 ssh port
    ip6tables -A INPUT -p tcp --dport "$ssh_port" -j ACCEPT

    # ICMPv6: 允許 IPv6 正常運作必要類型
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT   
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT 
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j ACCEPT

    # 已建立/相關連線
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # 允許主動輸出
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A OUTPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A OUTPUT -p tcp -j ACCEPT
    ip6tables -A OUTPUT -p udp -j ACCEPT

    # 預設政策
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT  # 或 DROP 如果你想更嚴格控制
    save_rules
    service iptables restart
    service ip6tables restart
  fi
  echo -e "${GREEN}配置成功！${RESET}"
  check_docker
}
disable_in_docker(){
  local daemon="/etc/docker/daemon.json"
  local EXTERNAL_INTERFACE=""
  if ! command -v docker &>/dev/null; then
    echo -e "${RED}未安裝docker，請先安裝${RESET}"
    sleep 1
    return 1
  fi
  # 偵測外網網卡 (優先 IPv4，失敗則嘗試 IPv6)
  EXTERNAL_INTERFACE=$(ip route | grep default | grep -o 'dev [^ ]*' | cut -d' ' -f2)
  if [ -z "$EXTERNAL_INTERFACE" ]; then
    EXTERNAL_INTERFACE=$(ip -6 route | grep default | grep -o 'dev [^ ]*' | cut -d' ' -f2)
    if [ -z "$EXTERNAL_INTERFACE" ]; then
      echo -e "${RED}未找到外網網卡！${RESET}"
      sleep 1
      return 1
    fi
  fi

  # 檢查網卡是否存在
  if ip link show "$EXTERNAL_INTERFACE" > /dev/null 2>&1; then
    echo "偵測到外網網卡: $EXTERNAL_INTERFACE"
  else
    echo -e "${RED}找不到網卡 $EXTERNAL_INTERFACE，請檢查網路配置。${RESET}"
    sleep 1
    return 1
  fi
  
  iptables -I DOCKER -i "$EXTERNAL_INTERFACE" -j DROP
  echo "關閉外網(IPv4)進入docker內部流量。"
  if [ -f "$daemon" ] && grep -q '"ipv6": true' "$daemon"; then
    local ipv6=true
  fi
  if [[ "$ipv6" == "true" ]]; then
    ip6tables -I DOCKER -i "$EXTERNAL_INTERFACE" -j DROP
    echo "已關閉外網(IPv6)進入docker內部流量。"
  fi

  # 確保 docker 設定檔目錄與檔案存在
  mkdir -p /etc/docker
  touch $daemon
  [ ! -s "$daemon" ] && echo '{}' > "$daemon"
      
  # 檢查並確保 daemon.json 是有效的 JSON
  if ! jq empty "$daemon" &>/dev/null; then
    echo '{}' > "$daemon"
  fi
      
  # 檢查並設定 "iptables": false
  if jq -e '.iptables == false' "$daemon" &>/dev/null; then
    open_docker_fw_service $ipv6
  else
    cp "$daemon" "$daemon.bak"
    local tmp=$(mktemp)
    jq '. + {"iptables": false}' "$daemon" > "$tmp" && mv "$tmp" "$daemon"
    # 重啟 Docker 服務
    service docker restart
    open_docker_fw_service $ipv6
    save_rules
  fi
}

del_port() {
  local PROTO="$1"  # 第一個參數是協議類型
  if [ -z "$2" ]; then
    echo -e "${RED}錯誤：未指定端口號${RESET}" >&2
    return 1
  fi
  
  if [ -z "$PROTO" ]; then
    PROTO="tcp"  # 如果協議未提供，默認為TCP
  fi
  shift  # 移動參數，剩餘的是端口列表
  local PORTS=("$@")

  if [ $fw = ufw ]; then
    for PORT in "${PORTS[@]}"; do
      if [ -z "$PORT" ]; then
        continue  # 跳過空端口
      fi
      ufw delete allow $PORT/$PROTO 2>/dev/null
      ufw delete allow $PORT 2>/dev/null
    done
    return 0
  fi
  for PORT in "${PORTS[@]}"; do
    if [ -z "$PORT" ]; then
      continue  # 跳過空端口
    fi
    local DEL_SUCCESS=0
    if iptables -D INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
      echo -e "${GREEN}已刪除 IPv4 $PROTO 端口 $PORT 的允許規則 (ACCEPT)${RESET}" >&2
      DEL_SUCCESS=1
    fi

    if iptables -D INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
      echo -e "${GREEN}已刪除 IPv4 $PROTO 端口 $PORT 的阻止規則 (DROP)${RESET}" >&2
      DEL_SUCCESS=1
    fi

    if [[ $DEL_SUCCESS -eq 0 ]]; then
      echo -e "${RED}錯誤：IPv4 $PROTO 端口 $PORT 無可刪除的規則${RESET}" >&2
    fi
  done
  save_rules
  return 0
}
deny_port() {
  local PROTO="$1"  # 第一個參數是協議類型
  if [ -z "$2" ]; then
    echo -e "${RED}錯誤：未指定端口號${RESET}" >&2
    return 1
  fi
  
  if [ -z "$PROTO" ]; then
    PROTO="tcp"  # 如果協議未提供，默認為TCP
  fi
  shift  # 移動參數，剩餘的是端口列表
  local PORTS=("$@")
  
  for PORT in "${PORTS[@]}"; do
    if [ -z "$PORT" ]; then
      continue  # 跳過空端口
    fi
    # ipv4
    if ! iptables -C INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
      if iptables -A INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
        echo -e "${GREEN}IPv4 $PROTO 端口 $PORT 已阻止${RESET}" >&2
      else
        echo -e "${RED}錯誤：無法阻止 IPv4 $PROTO 端口 $PORT${RESET}" >&2
      fi
    fi
    # 檢查是否允許之
    # IPv4
    if iptables -C INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
      iptables -D INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null
    fi

    # 確認 DROP 是否已存在，避免重複插入
    if ! iptables -C INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
      iptables -I INPUT -p "$PROTO" --dport "$PORT" -j DROP
      echo -e "${GREEN}已新增阻止 IPv4 $PROTO 端口 $PORT 的規則 (DROP)${RESET}" >&2
    fi 
    # ipv6
    if ! ip6tables -C INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
      if ip6tables -A INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
        echo -e ${GREEN}"IPv6 $PROTO 端口 $PORT 已阻止${RESET}" >&2
      else
        echo -e "${RED}錯誤：無法阻止 IPv6 $PROTO 端口 $PORT${RESET}" >&2
      fi
    fi
    # 檢查是否允許之
    # IPv6
    if ip6tables -C INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null; then
      ip6tables -D INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null
    fi

    # 確認 DROP 是否已存在，避免重複插入
    if ! ip6tables -C INPUT -p "$PROTO" --dport "$PORT" -j DROP 2>/dev/null; then
      ip6tables -I INPUT -p "$PROTO" --dport "$PORT" -j DROP
      echo -e "${GREEN}已新增阻止 IPv6 $PROTO 端口 $PORT 的規則 (DROP)${RESET}" >&2
    fi 
  done
  
  save_rules
  return 0
}

open_docker_fw_service() {
    local ipv6="${1:-false}"
    # 預先定義好服務要執行的最終指令
    local service_command="/etc/fw/docker.sh"

    mkdir -p /etc/fw/
    
    # 修正：下載 v4 腳本到正確的檔名
    wget -O /etc/fw/docker.sh https://gitlab.com/gebu8f/sh/-/raw/main/firewall/docker.sh
    chmod +x /etc/fw/docker.sh

    if [ "$ipv6" == "true" ]; then
      echo "IPv6 模式啟用，下載對應腳本並準備複合指令..."
      # 下載 v6 腳本
      wget -O /etc/fw/docker-v6.sh https://gitlab.com/gebu8f/sh/-/raw/main/firewall/docker-v6.sh
      chmod +x /etc/fw/docker-v6.sh
      
      # 【核心修改】使用 sh -c 來安全地執行兩個腳本
      # 這確保了無論是 systemd 還是 openrc 都能正確處理
      service_command="/bin/bash -c '/etc/fw/docker.sh & /etc/fw/docker-v6.sh &'"
    fi

    case $system in
    1|2)
      cat > /etc/systemd/system/docker-firewall.service << EOF
[Unit]
Description=Docker Firewall Auto-Guard Service
After=network.target docker.service

[Service]
ExecStart=${service_command}
Restart=always
RestartSec=5
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now docker-firewall
      ;;
    3)
      # 【優化】移除 sed 手動注入 PID 的操作，完全交給 OpenRC 管理，這樣更穩定可靠。
      # sed -i '/check_system/a echo $$ > /run/docker-firewall.pid' /etc/fw/docker.sh
      cat > /etc/init.d/docker-firewall << EOF
#!/sbin/openrc-run

name="docker-firewall"
# 使用我們動態構建的指令
command="${service_command}"
command_background="yes"
pidfile="/run/${name}.pid"

depend() {
    need net docker
}
EOF
      chmod +x /etc/init.d/docker-firewall
      rc-update add docker-firewall default
      rc-service docker-firewall start
      ;;
    esac
    echo "Docker 防火牆服務已設定並啟動。"
}

# 設置速率限制以防禦DDoS攻擊
rate_limit_port() {
  if [ -z "$1" ]; then
    echo "錯誤：未指定端口號"
    return 1
  fi
    
  local PORT=$1
  local PROTO=${2:-tcp}  # 默認為TCP協議
  local RATE=${3:-10}    # 默認速率限制為每分鐘10次連接
  local BURST=${4:-20}   # 默認突發量為20
  
  # 檢查端口是否有效
  check_port "$PORT" "$PROTO"
  result=$?
  if [[ $result -ne 0 ]]; then
    return 1
  fi
  
  echo "設置$PROTO端口 $PORT 的速率限制..."
  # IPv4 速率限制
  iptables -A INPUT -p $PROTO --dport $PORT -m limit --limit $RATE/minute --limit-burst $BURST -j ACCEPT
  iptables -A INPUT -p $PROTO --dport $PORT -j DROP
  echo "IPv4 $PROTO 端口 $PORT 已設置速率限制為每分鐘 $RATE 次，突發量 $BURST"
  
  # IPv6 速率限制
  ip6tables -A INPUT -p $PROTO --dport $PORT -m limit --limit $RATE/minute --limit-burst $BURST -j ACCEPT
  ip6tables -A INPUT -p $PROTO --dport $PORT -j DROP
  echo "IPv6 $PROTO 端口 $PORT 已設置速率限制為每分鐘 $RATE 次，突發量 $BURST"
  
  save_rules
}

# 移除速率限制
remove_rate_limit_port() {
  if [ -z "$1" ]; then
    echo "錯誤：未指定端口號"
    return 1
  fi
  
  local PORT=$1
  local PROTO=${2:-tcp}  # 默認為TCP協議
  
  # 檢查端口是否有效
  check_port "$PORT" "$PROTO"
  result=$?
  if [[ $result -ne 0 ]]; then
    return 1
  fi
  
  echo "移除$PROTO端口 $PORT 的速率限制..."
    # 針對 IPv4 刪除所有該端口的相關規則
  # IPv4
  iptables-save | grep -E "\-A INPUT .*-p $PROTO .*--dport $PORT" | while read -r line; do
    rule=$(echo "$line" | sed 's/^-A /-D /')
    iptables $rule 2>/dev/null && echo "已刪除 IPv4 規則: $rule"
    done

  # IPv6
  ip6tables-save | grep -E "\-A INPUT .*-p $PROTO .*--dport $PORT" | while read -r line; do
    rule=$(echo "$line" | sed 's/^-A /-D /')
    ip6tables $rule 2>/dev/null && echo "已刪除 IPV6規則: $rule"
    done
  save_rules
}

setup_iptables() {
    case $system in
    1)
      apt update
      apt install -y iptables-persistent
      systemctl enable netfilter-persistent
      read -p "是否執行基礎防火牆配置？(Y/n): [預設為是]" confirm
      confirm=${confirm,,}  # 轉小寫
      confirm=${confirm:-y}
      if [[ "$confirm" == "y" || "$confirm" == "" ]]; then
      default_settings
      else
        echo "跳過基礎配置。"
      fi
      ;;
    2)
      yum update -y
      yum install -y iptables-services
      read -p "是否執行基礎防火牆配置？(Y/n): [預設為是]" confirm
      confirm=${confirm,,}  # 轉小寫
      confirm=${confirm:-y}
      if [[ "$confirm" == "y" || "$confirm" == "" ]]; then
        default_settings
        systemctl enable iptables
        systemctl start iptables
        systemctl enable ip6tables
        systemctl start ip6tables
      else
        echo "正在開啟防火牆"
        systemctl enable iptables
        systemctl start iptables
        systemctl enable ip6tables
        systemctl start ip6tables
       fi
      ;;
    3)
      apk update
      apk add iptables ip6tables
      read -p "是否執行基礎防火牆配置？(Y/n): [預設為是]" confirm
      confirm=${confirm,,}  # 轉小寫
      confirm=${confirm:-y}
      if [[ "$confirm" == "y" || "$confirm" == "" ]]; then
        default_settings
        rc-service iptables start
        rc-service ip6tables start
        rc-update add iptables
        rc-update add ip6tables
      else
        echo "正在開啟防火牆"
        rc-service iptables start
        rc-service ip6tables start
        rc-update add iptables
        rc-update add ip6tables
      fi
    ;;
    esac
    check_fw
    menu_iptables
}

setup_ufw(){
  case "$system" in
  1) 
    apt update
    apt install ufw -y
    ;;
  2)
    echo -e "${RED}您好,您的系統不支持ufw,請安裝iptables${RESET}"
    read -p "操作完成,請按任意鍵繼續..." -n1
    return 1
    ;;
  3)
    apk update
    apk add ufw
    ;;
  esac
  local ssh_port=$(grep -E '^Port ' /etc/ssh/sshd_config | awk '{print $2}')
  # 如果未設定Port則預設為22
  if [[ -z "$ssh_port" ]]; then
    ssh_port=22
  fi
  echo "SSH端口是：$ssh_port"
  ufw allow $ssh_port/tcp
  echo "啟用 UFW 防火牆..."
  echo "y" | ufw enable
  echo "UFW 防火牆已啟用"
  check_fw
  menu_ufw
}
save_rules() {
  if [ $fw = ufw ]; then
    return
  fi
  if [ "$system" -eq 1 ]; then
    netfilter-persistent save >/dev/null 2>&1
  elif [ "$system" -eq 2 ]; then
    # 儲存規則
    service iptables save >/dev/null 2>&1
    service ip6tables save >/dev/null 2>&1
  elif [ "$system" -eq 3 ]; then
    /etc/init.d/iptables save >/dev/null 2>&1
    /etc/init.d/ip6tables save >/dev/null 2>&1
  else
    echo -e "${RED}此系統目前尚未支援自動儲存規則。${RESET}" >&2
  fi
}

update_script() {
  local download_url="https://gitlab.com/gebu8f/sh/-/raw/main/firewall/fw.sh"
  local temp_path="/tmp/fw.sh"
  local current_script="/usr/local/bin/fw"
  local current_path="$0"

  echo "正在檢查更新..."
  wget -q "$download_url" -O "$temp_path"
  if [ $? -ne 0 ]; then
    echo -e "${RES}無法下載最新版本，請檢查網路連線。${RESET}"
    return
  fi

  # 比較檔案差異
  if [ -f "$current_script" ]; then
    if diff "$current_script" "$temp_path" >/dev/null; then
      rm -f "$temp_path"
      return
    fi
    echo -e "${YELLOW}檢測到新版本，正在更新...${RESET}"
    cp "$temp_path" "$current_script" && chmod +x "$current_script"
    if [ $? -eq 0 ]; then
      echo -e ${GREEN} "更新成功！將自動重新啟動腳本以套用變更...${RESET}"
      sleep 1
      exec "$current_script"
    else
      echo -e "${RED}更新失敗，請確認權限。${RESET}"
    fi
  else
    # 非 /usr/local/bin 執行時 fallback 為當前檔案路徑
    if diff "$current_path" "$temp_path" >/dev/null; then
      rm -f "$temp_path"
      return
    fi
    echo "檢測到新版本，正在更新..."
    cp "$temp_path" "$current_path" && chmod +x "$current_path"
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}更新成功！將自動重新啟動腳本以套用變更...${RESET}"
      sleep 1
      exec "$current_path"
    else
      echo -e "${RED}更新失敗，請確認權限。${RESET}"
    fi
  fi

  rm -f "$temp_path"
}

menu_advanced(){
  local choice
  clear
  echo -e "\033[1;32m進階功能\033[0m"
  echo -e "\033[1;34m------------------------\033[0m"
  echo -e "\033[1;36m1. 設置DDoS防護速率限制    2. 移除DDoS防護速率限制\033[0m"
    echo ""
    echo -e "\033[1;36m3. 阻止端口訪問（INPUT）\033[0m"
    echo ""
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;31m0. 退出\033[0m"
  echo -n -e "\033[1;33m請選擇操作 [0-3]: \033[0m"
  read -r choice
  case $choice in
  1)
    clear
    echo -e "\033[1;32m設置DDoS防護速率限制\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    read -p "請輸入要設置速率限制的端口號: " port
    read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
    read -p "請輸入每分鐘允許的連接數(默認10): " rate
    read -p "請輸入突發量(默認20): " burst
    check_port "$port" "$proto"
    local proto=${proto:-tcp}
    result=$?
    if [[ $result -eq 0 ]]; then
      rate_limit_port "$port" "$proto" "$rate" "$burst"
      save_rules
    fi
    read -p "按任意鍵繼續..." -n1
    ;;
  2)
    clear
    echo -e "\033[1;32m移除DDoS防護速率限制\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    read -p "請輸入要移除速率限制的端口號: " port
    read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
    check_port "$port" "$proto"
    result=$?
    if [[ $result -eq 0 ]]; then
      remove_rate_limit_port "$port" "$proto"
    fi
    read -p "按任意鍵繼續..." -n1
    ;;
  3)
    clear
    menu_deny_port
    ;;
  0)
    return 0
    ;;
  esac
}

menu_allow_port(){
    local choice
    clear
    echo -e "\033[1;32m開啟端口\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;36m1. 開放指定端口\033[0m"
    echo ""
    echo -e "\033[1;36m2. 開放指定IP及端口\033[0m"
    echo ""
    echo -e "\033[1;36m3. 指定IP\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;31m0. 返回\033[0m"
    echo -n -e "\033[1;33m請選擇操作 [0-3]: \033[0m"
    read -r choice
    case $choice in
    1)
      clear
      echo "開放指定端口"
      echo "------------------------"
      read -p "請輸入要開啟的端口號（可輸入多個端口，用空格分隔）: " -a ports
      read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
      for port in "${ports[@]}"; do
        check_port "$port" "$proto"
        result=$?
        if [[ $result -ne 0 ]]; then
          break
        fi
      done
      allow_port "$proto" "${ports[@]}"
      save_rules
      read -p "操作完成，按任意鍵繼續..." -n1
      ;;
    2)
      # 請用戶輸入 IP 和端口
      read -p "請輸入要開放的端口: " port
      read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
      check_port "$port" "$proto"
      result=$?
      if [[ $result -eq 0 ]]; then
        local proto=${proto:-tcp}
        read -p "請輸入要開放的 IP 地址（支持單個IP或網段，如 192.168.1.0/24）: " ip
        check_ip "$ip"
        ip_result=$?
        if [[ $ip_result -eq 0 ]]; then
          if [ $fw = ufw ]; then
            ufw allow from "$ip" to any port "$port" proto "$proto"
            return
          fi
          if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            # IPv4 處理
            echo "檢測到 IPv4 地址/網段，將開放該地址的端口..."
            if iptables -A INPUT -p "$proto" -s "$ip" --dport "$port" -j ACCEPT 2>/dev/null; then
              echo "IPv4 端口 $port 已開放給 $ip 協議為 $proto"
              save_rules
            else
              echo "錯誤：無法為 IPv4 地址 $ip 開放端口 $port"
            fi
          elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
            # IPv6 處理
            echo "檢測到 IPv6 地址/網段，將開放該地址的端口..."
            if ip6tables -A INPUT -p "$proto" -s "$ip" --dport "$port" -j ACCEPT 2>/dev/null; then
              echo "IPv6 端口 $port 已開放給 $ip 協議為 $proto"
              save_rules
            else
              echo "錯誤：無法為 IPv6 地址 $ip 開放端口 $port"
            fi
          fi
        fi
      fi
      ;;
    3)
      read -p "請輸入要開放的 IP 地址（支持單個IP或網段，如 192.168.1.0/24）: " ip
      check_ip "$ip"
      ip_result=$?
      if [[ $ip_result -eq 0 ]]; then
        if [ $fw = ufw ]; then
          ufw allow from "$ip"
          return
        fi
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
          # IPv4 處理
          read -p "要開放的協議（預設tcp）：" proto
          local proto=${proto:-tcp}
          # 檢查協議是否有效
          if [[ $proto != "tcp" && $proto != "udp" ]]; then
            echo "無效的協議類型，請使用tcp或udp"
            break
          else
            if iptables -A INPUT -s "$ip" -p "$proto" -j ACCEPT 2>/dev/null; then
              save_rules
            else
              echo "錯誤：無法為 IPv4 地址 $ip 開放協議 $proto"
            fi
          fi
        elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
          # IPv6 處理
          read -p "要開放的協議（預設tcp）：" proto
          local proto=${proto:-tcp}
          # 檢查協議是否有效
          if [[ $proto != "tcp" && $proto != "udp" ]]; then
            echo "無效的協議類型，請使用tcp或udp"
            break
          else
            if ip6tables -A INPUT -s "$ip" -p "$proto" -j ACCEPT 2>/dev/null; then
              save_rules
            else
              echo "錯誤：無法為 IPv6 地址 $ip 開放協議 $proto"
            fi
          fi
        fi
      fi
      ;;
    esac
}

menu_deny_port(){
    local choice
    clear
    echo -e "\033[1;32m阻止端口訪問\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;36m1. 阻止指定端口\033[0m"
    echo ""
    echo -e "\033[1;36m2. 阻止指定IP及端口\033[0m"
    echo ""
    echo -e "\033[1;36m3. 指定IP\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;31m0. 返回\033[0m"
    echo -n -e "\033[1;33m請選擇操作 [0-3]: \033[0m"
    read -r choice
    case $choice in
    1)
      clear
      echo "阻止指定端口"
      echo "------------------------"
      read -p "請輸入要阻止的端口號（可輸入多個端口，用空格分隔）: " -a ports
      read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
      local valid=true
      for port in "${ports[@]}"; do
        check_port "$port" "$proto"
        result=$?
        if [[ $result -ne 0 ]]; then
          valid=false
          break
        fi
      done
      if [[ $valid == true ]]; then
        deny_port "$proto" "${ports[@]}"
        save_rules
      fi
      read -p "操作完成，按任意鍵繼續..." -n1
      ;;
    2)
      # 請用戶輸入 IP 和端口
      read -p "請輸入要阻止的端口: " port
      read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
      check_port "$port" "$proto"
      result=$?
      if [[ $result -eq 0 ]]; then
        proto=${proto:-tcp}
        read -p "請輸入要阻止的 IP 地址（支持單個IP或網段，如 192.168.1.0/24）: " ip
        check_ip "$ip"
        ip_result=$?
        if [[ $ip_result -eq 0 ]]; then
          if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            # IPv4 處理
            echo "檢測到 IPv4 地址/網段，將阻止該地址的端口..."
            if iptables -C INPUT -p "$proto" -s "$ip" --dport "$port" -j DROP 2>/dev/null; then
              echo "IPv4 $proto 端口 $port 已存在，跳過之"
            else
              iptables -A INPUT -p "$proto" -s "$ip" --dport "$port" -j DROP 2>/dev/null
              echo "IPv4 $proto 端口 $port 之指定ip $ip 已阻止"
            fi
            if iptables -C INPUT -p "$proto" -s "$ip" --dport "$port" -j ACCEPT 2>/dev/null; then
              echo "IPv4 $proto 端口 $port之指定ip $ip 有允許規則，將移除並阻止連線"
              iptables -D INPUT -p "$proto" -s "$ip" --dport "$port" -j ACCEPT 2>/dev/null
            fi
            save_rules
          elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
            # IPv6 處理
            echo "檢測到 IPv6 地址/網段，將阻止該地址的端口..."
            if ip6tables -C INPUT -p "$proto" -s "$ip" --dport "$port" -j DROP 2>/dev/null; then
              echo "IPv6 $proto 端口 $port 已存在，跳過之"
            else
              ip6tables -A INPUT -p "$proto" -s "$ip" --dport "$port" -j DROP 2>/dev/null
              echo "IPv6 $proto 端口 $port 之指定ip $ip 已阻止"
            fi
            if ip6tables -C INPUT -p "$proto" -s "$ip" --dport "$port" -j ACCEPT 2>/dev/null; then
              echo "IPv6 $proto 端口 $port之指定ip $ip 有允許規則，將移除並阻止連線"
              ip6tables -D INPUT -p "$proto" -s "$ip" --dport "$port" -j ACCEPT 2>/dev/null
            fi
            save_rules
          fi
        fi
      fi
      ;;
    3)
      read -p "請輸入要阻止的 IP 地址（支持單個IP或網段，如 192.168.1.0/24）: " ip
      check_ip "$ip"
      ip_result=$?
      if [[ $ip_result -eq 0 ]]; then
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
          # IPv4 處理
          read -p "要阻止的協議（預設tcp）：" proto
          local proto=${proto:-tcp}
          # 檢查協議是否有效
          if [[ $proto != "tcp" && $proto != "udp" ]]; then
            echo "無效的協議類型，請使用tcp或udp"
            break
          else
            if iptables -C INPUT -s "$ip" -p "$proto" -j DROP 2>/dev/null; then
              echo "IPv4 $proto 指定IP $ip 已存在，跳過"
            else
              iptables -A INPUT -s "$ip" -p "$proto" -j DROP 2>/dev/null
              echo "IPv4 $proto 指定IP $ip 已阻止"
            fi
            if iptables -C INPUT -s "$ip" -p "$proto" -j ACCEPT 2>/dev/null; then
              echo "IPv4 $proto 指定IP $ip 有允許規則，將移除並阻止連線"
              iptables -D INPUT -s "$ip" -p "$proto" -j ACCEPT 2>/dev/null
            fi
            save_rules
          fi
        elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
          # IPv6 處理
          read -p "要阻止的協議（預設tcp）：" proto
          local proto=${proto:-tcp}
          # 檢查協議是否有效
          if [[ $proto != "tcp" && $proto != "udp" ]]; then
            echo "無效的協議類型，請使用tcp或udp"
            break
          else
            if ip6tables -C INPUT -s "$ip" -p "$proto" -j DROP 2>/dev/null; then
              echo "IPv6 $proto 指定IP $ip 已存在，跳過"
            else
              ip6tables -A INPUT -s "$ip" -p "$proto" -j DROP 2>/dev/null
              echo "IPv6 $proto 指定IP $ip 已阻止"
            fi
            if ip6tables -C INPUT -s "$ip" -p "$proto" -j ACCEPT 2>/dev/null; then
              echo "IPv6 $proto 指定IP $ip1 有允許規則，將移除並阻止連線"
              ip6tables -D INPUT -s "$ip" -p "$proto" -j ACCEPT 2>/dev/null
            fi
            save_rules
          fi
        fi
      fi
      ;;
    esac
}

menu_del_port(){
    local choice
    clear
    echo -e "\033[1;32m刪除端口\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;36m1. 數字式刪除（適合量少）\033[0m"
    echo ""
    echo -e "\033[1;36m2. 刪除指定端口\033[0m"
    echo ""
    echo -e "\033[1;36m3. 刪除指定IP加端口\033[0m"
    echo ""
    echo -e "\033[1;36m4. 刪除指定IP\033[0m"
    echo -e "\033[1;34m------------------------\033[0m"
    echo -e "\033[1;31m0. 返回\033[0m"
    echo -n -e "\033[1;33m請選擇操作 [0-4]: \033[0m"
    read -r choice
    case $choice in
    1)
      if [ $fw = ufw ]; then
        ufw status numbered
        read -p "請輸入數字:ex [1] ...30/tcp...的1 " number
        ufw delete "$number"
      else
        clear
        local choice
        echo "數字式刪除"
        echo "------------------------"
        echo "1. ipv4"
        echo ""
        echo "2. ipv6"
        echo '------------------------'
        echo "0. 返回"
        echo -n "請選擇操作 [0-2]: "
        read -r choice
        case $choice in
        1)
          clear
          iptables -L INPUT --line-numbers
          read -p "請輸入數字：" number
          iptables -D INPUT "$number"
          save_rules
          ;;
        2)
          clear
          ip6tables -L INPUT --line-numbers
          read -p "請輸入數字：" number
          ip6tables -D INPUT "$number"
          save_rules
          ;;
        0)
          return 0
          ;;
        esac
      fi
      ;;
    2)
      clear
      echo "刪除指定端口"
      echo "------------------------"
      read -p "請輸入要刪除的端口號（可輸入多個端口，用空格分隔）: " -a ports
      read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
      local valid=true
      for port in "${ports[@]}"; do
        check_port "$port" "$proto"
        result=$?
        if [[ $result -ne 0 ]]; then
          valid=false
          break
        fi
      done
      if [[ $valid == true ]]; then
        del_port "$proto" "${ports[@]}"
        save_rules
      fi
      read -p "按任意鍵繼續..." -n1
      ;;
    3)
      # 請用戶輸入 IP 和端口
      read -p "請輸入要刪除的端口: " port
      read -p "請輸入協議類型(tcp/udp，默認tcp): " proto
      check_port "$port" "$proto"
      result=$?
      if [[ $result -eq 0 ]]; then
        read -p "請輸入要刪除的 IP 地址: " ip
        local proto=${proto:-tcp}
        if [ $fw = ufw ]; then
          ufw delete allow from $ip to any port $port proto $proto
          return
        fi
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
          # IPv4 處理
          echo "檢測到 IPv4 地址，將刪除該地址的端口..."
          iptables -D INPUT -p "$proto" -s $ip --dport $port -j ACCEPT
          iptables -D INPUT -p "$proto" -s $ip --dport $port -j DROP
          echo "IPv4 端口 $port 已刪除給 $ip 協議為 $proto"
        
          save_rules
        elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
          proto=${proto:-tcp}
        # IPv6 處理
          echo "檢測到 IPv6 地址，將刪除該地址的端口..."
          ip6tables -D INPUT -p $proto -s $ip --dport $port -j ACCEPT
          ip6tables -D INPUT -p $proto -s $ip --dport $port -j DROP
          echo "IPv6 端口 $port 已刪除給 $ip 協議為 $proto"
          save_rules
        else
          echo "無效的 IP 地址"
        fi
      fi
      ;;
      4)
        read -p "請輸入要刪除的 IP 地址（支持單個IP或網段，如 192.168.1.0/24）: " ip
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
          # IPv4 處理
          read -p "要刪除的協議（預設tcp）：" proto
          local proto=${proto:-tcp}
          if [ $fw = ufw ]; then
            ufw delete allow from "$ip"
            return
          fi
          # 檢查協議是否有效
          if [[ $proto != "tcp" && $proto != "udp" ]]; then
            echo "無效的協議類型，請使用tcp或udp"
            return 1
          else
            iptables -D INPUT -s "$ip" -p "$proto" -j ACCEPT 
            iptables -D INPUT -s "$ip" -p "$proto" -j DROP
            save_rules
          fi
        elif [[ "$ip" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]]; then
          # IPv6 處理
          read -p "要刪除的協議（預設tcp）：" proto
          local proto=${proto:-tcp}
          # 檢查協議是否有效
          if [[ $proto != "tcp" && $proto != "udp" ]]; then
            echo "無效的協議類型，請使用tcp或udp"
            break
          else
            ip6tables -D INPUT -s "$ip" -p "$proto" -j ACCEPT 
            ip6tables -D INPUT -s "$ip" -p "$proto" -j DROP
            save_rules
          fi
        else
          echo "無效的 IP 地址"
        fi
        ;;
    esac
  
}
munu_fw() {
  if [[ $fw == ufw ]]; then
    menu_ufw
  elif [[ $fw == iptables ]]; then
    menu_iptables
  fi
}

menu_ufw(){
    while true; do
        clear
        echo -e "${GREEN}UFW基礎防火牆管理${RESET}"
        echo -e "${BLUE}------------------------${RESET}"
        ufw status
        echo ""
        echo -e "${GREEN}防火牆管理${RESET}"
        echo -e "${BLUE}------------------------${RESET}"
        echo -e "${CYAN}1. 開放端口          2. 刪除端口${RESET}"
        echo ""
        echo -e "${CYAN}3. 禁止ping             4. 允許ping${RESET}"
        echo ""
        echo -e "${CYAN}5. 允許CloudFlare IP      6. 刪除CloudFlare IP${RESET}"
        echo ""
        echo -e "${CYAN}7. 阻止Censys IP訪問   8. 刪除阻止Censys IP${RESET}"
        echo -e "${BLUE}------------------------${RESET}"
        echo -e "${RED}0. 退出                  00. 更新腳本${RESET}"
        echo ""
        echo -n -e "${YELLOW}請選擇操作 [0-8]: ${RESET}"
        read -r choice
        case $choice in
        1) 
            clear
            menu_allow_port 
            ;;
        2)
            clear
            menu_del_port 
            ;;
        3)
            clear
            block_ping 
            read -p "操作完成，請按任意鍵..." -n1
            ;;
        4)
            clear
            allow_ping 
            read -p "操作完成，請按任意鍵..." -n1
            ;;
        5)
            allow_cf_ip 
            read -p "操作完成，請按任意鍵..." -n1
            ;;
        6)
            del_cf_ip 
            read -p "操作完成，請按任意鍵..." -n1
            ;;
        7)
            censys_block add
            ;;
        8)
            censys_block del
            ;;
        0)
            echo "感謝使用防火牆管理工具，再見！"
            exit 0
            ;;
        00)
            clear
            echo "更新腳本"
            echo "------------------------"
            update_script
            ;;
        *)
            echo "無效選擇，請重試"
            read -p "按任意鍵繼續..." -n1
            ;;
        esac
    done
}

menu_iptables() {
    while true; do
        port=""
        proto=""
        ip=""
        clear
        echo -e "${GREEN} iptables防火牆管理${RESET}"
        echo -e "${BLUE}------------------------${RESET}"
        echo -e "${YELLOW}此顯示防火牆規則為ipv4${RESET}"
        iptables -L INPUT
        echo ""
        echo -e "${GREEN}防火牆管理${RESET}"
        echo -e "${BLUE}------------------------${RESET}"
        echo -e "${CYAN}1. 開放端口          2. 刪除端口${RESET}"
        echo ""
        echo -e "${CYAN}3. 禁止ping             4. 允許ping${RESET}"
        echo ""
        echo -e "${BOLD_CYAN}5. 基礎設置(建議)       6. 關閉外網進入docker內部流量（建議）${RESET}"
        echo ""
        echo -e "${CYAN}7. 允許CloudFlare IP      8. 刪除CloudFlare IP${RESET}"
        echo ""
        echo -e "${CYAN}9. 阻止Censys IP訪問   10. 刪除阻止Censys IP${RESET}"
        echo ""
        echo -e "${CYAN}11. 顯示ipv6防火牆規則    12. 進階功能${RESET}"
        echo ""
        echo -e "${BLUE}------------------------${RESET}"
        echo -e "${RED}0. 退出              00. 更新腳本${RESET}"
        echo ""
        echo -n -e "${YELLOW}請選擇操作 [0-12, 00]: ${RESET}"
        read -r choice
        case $choice in
        1)
          menu_allow_port
          ;;
        2)
          menu_del_port
          ;;
        3)
          clear
          echo "禁止ping"
          echo "------------------------"
          block_ping
          read -p "按任意鍵繼續..." -n1
          ;;
        4)
          clear
          echo "允許ping"
          echo "------------------------"
          allow_ping iptables
          read -p "按任意鍵繼續..." -n1
          ;;
        5)
          clear
          echo "安全基礎設置"
          echo "------------------------"
          default_settings
          read -p "按任意鍵繼續..." -n1
          ;;
        6)
          clear
          disable_in_docker
          read -p "按任意鍵繼續..." -n1
          ;;
        7)
          clear
          allow_cf_ip 
          read -p "按任意鍵繼續..." -n1
          ;;
        8)
          clear
          del_cf_ip 
          read -p "按任意鍵繼續..." -n1
          ;;
        9)
          clear
          censys_block add
          ;;
        10)
          clear
          censys_block del
          ;;
        11)
          clear
          ip6tables -L INPUT
          read -p "操作完成，按任意鍵繼續..." -n1
          ;;
        12)
          clear
          menu_advanced
          ;;
        0)
          echo "感謝使用防火牆管理工具，再見！"
          exit 0
          ;;
        00)
          clear
          echo "更新腳本"
          echo "------------------------"
          update_script
          ;;
        *)
          echo "無效選擇，請重試"
          read -p "按任意鍵繼續..." -n1
          ;;
        esac
    done
}
menu_install_fw(){
    if [ $fw = none ]; then
        clear
        echo "1. 安裝UFW(適合純新手,不裝docker)"
        echo ""
        echo "2. 安裝iptables(適合比較進階的人,裝docker)"
        echo "-----------------"
        read -p "請選擇操作:[1-2]" comfin
        case $comfin in
        1)
          setup_ufw
          ;;
        2)
          setup_iptables
          ;;    
        esac
    fi
}
case "$1" in
  --version|-V)
    echo "Linux防火牆管理器版本$version"
    exit 0
    ;;
  help|--help|-h)
    echo "用法："
    echo "fw <open/deny/del> port <port（用空白鍵分端口，例如：10 20 30 40）> <tcp/udp>"
    echo "fw <open/deny/del> ip <ip> <tcp/udp>"
    echo "fw <open/deny/del> ip_port <ip> <port>"
    exit 0
    ;;
esac

# 初始化
check_system
check_app
check_fw
[[ ! -z $1 ]] && check_cli_fw
case "$1" in
  open|deny|del)
    act_iptables=ACCEPT
    act_ufw=allow
    [ $1 == del ] && act1_ufw=delete
    [ $1 == deny ] && act_iptable=DROP && act_ufw=deny
    if [[ $2 == port ]]; then
      original_action="$1"
      shift 2
      if [ -z "$1" ]; then
        echo "錯誤：未指定端口號"
        exit 1
      fi
      PROTO="tcp"  # 默認為tcp
      LAST_ARG="${@: -1}"  # 獲取最後一個參數
      [[ $LAST_ARG != "tcp" && $LAST_ARG != "udp" ]] && echo -e "${RED}無效的協議類型，請使用tcp或udp${RESET}" >&2 && exit 1
      if [[ "$LAST_ARG" == "tcp" || "$LAST_ARG" == "udp" ]]; then
        PROTO="$LAST_ARG"
        set -- "${@:1:$(($#-1))}"
      fi
      [ $original_action == open ] && allow_port "$PROTO" "$@"
      [ $original_action == del ] && del_port "$PROTO" "$@"
      [ $original_action == deny ] && deny_port "$PROTO" "$@"
    elif [[ $2 == ip ]]; then
      [ -z "$3" ] && fw help
      [ $fw == ufw ] && ufw $act1_ufw $act_ufw from "$3" 
      if [ $fw == iptables ]; then
        proto_cli=${4:-tcp}
        [[ $proto_cli != "tcp" && $proto_cli != "udp" ]] && echo -e "${RED}無效的協議類型，請使用tcp或udp${RESET}" >&2 && exit 1
        if [ $1 == del ]; then
          [[ "$3" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] && (iptables -D INPUT -s "$3" -p "$proto_cli" -j ACCEPT >/dev/null 2>&1 || iptables -D INPUT -s "$3" -p "$proto_cli" -j DROP >/dev/null 2>&1)
          [[ "$3" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]] && (ip6tables -D INPUT -s "$3" -p "$proto_cli" -j ACCEPT >/dev/null 2>&1 || ip6tables -D INPUT -s "$3" -p "$proto_cli" -j DROP >/dev/null 2>&1)
        else
          [[ "$3" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] && iptables -A INPUT -s "$3" -p "$proto_cli" -j $act_iptables
          [[ "$3" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]] && ip6tables -A INPUT -s "$3" -p "$proto_cli" -j $act_iptables
        fi
        save_rules
      fi
    elif [[ $2 == ip_port ]]; then
      [[ -z "$3" || -z "$4" ]] && fw help
      proto_cli=${5:-tcp}
      [[ $proto_cli != "tcp" && $proto_cli != "udp" ]] && echo -e "${RED}無效的協議類型，請使用tcp或udp${RESET}" >&2 && exit 1
      [ $fw == ufw ] && ufw $act1_ufw $act_ufw from "$3" to any port "$4" proto "$proto_cli"
      if [ $fw == iptables ]; then
        if [ $1 == del ]; then
          [[ "$3" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] && (iptables -D INPUT -p "$proto_cli" -s $3 --dport $4 -j ACCEPT >/dev/null 2>&1 || iptables -D INPUT -p "$proto_cli" -s $3 --dport $4 -j DROP >/dev/null 2>&1)
          [[ "$3" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]] && (ip6tables -D INPUT -p "$proto_cli" -s $3 --dport $4 -j ACCEPT >/dev/null 2>&1 || ip6tables -D INPUT -p "$proto_cli" -s $3 --dport $4 -j DROP >/dev/null 2>&1)
        else
          [[ "$3" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] && iptables -A INPUT -p "$proto_cli" -s "$3" --dport "$4" -j $act_iptables
          [[ "$3" =~ ^[a-fA-F0-9:]+(/[0-9]+)?$ ]] && ip6tables -A INPUT -p "$proto_cli" -s "$3" --dport "$4" -j $act_iptables
        fi
        save_rules
      fi
    fi
    exit 0
    ;;
    blockping)
      block_ping
      exit 0
      ;;
    allowping)
      allow_ping
      exit 0
      ;;
esac
menu_install_fw
munu_fw
