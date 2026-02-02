#!/bin/bash


# 定義顏色
GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BOLD_CYAN="\033[1;36;1m"
RESET="\033[0m"

version="7.0.2"

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
  local PROTO="$1"
  shift
  if [ "$#" -eq 0 ]; then
    echo -e "${RED}錯誤：未指定端口號${RESET}" >&2
    return 1
  fi
    
  [ -z "$PROTO" ] && PROTO="tcp"  
  if [ $fw = ufw ]; then  
    for PORT in "$@"; do
      if [ -z "$PORT" ]; then  
        continue
      fi  
      ufw allow $PORT/$PROTO  
    done  
    return 0  
  fi  

  for PORT in "$@"; do
    [ -z "$PORT" ] && continue

    local TARGET_CHAIN="INPUT"
    local IPT_ARGS="--dport"
    
    if ss -tulnp | grep -E "[:.]$PORT\\b" | grep -qi docker; then
      TARGET_CHAIN="DOCKER-USER"
      IPT_ARGS="-m conntrack --ctorigdstport"
    fi
    # IPv4
    if iptables -C $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null; then
      iptables -D $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null
    fi
    if ! iptables -C "$TARGET_CHAIN" -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT 2>/dev/null; then
      if iptables -I "$TARGET_CHAIN" 1 -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT; then
        echo -e "${GREEN}IPv4 $PROTO $PORT → $TARGET_CHAIN 已放行${RESET}" >&2
      else
        echo -e "${RED}IPv4 $PROTO $PORT 放行失敗${RESET}" >&2
      fi
    fi

    # IPv6
    if ip6tables -C $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null; then
      ip6tables -D $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null
    fi
    if ! ip6tables -C "$TARGET_CHAIN" -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT 2>/dev/null; then
      if ip6tables -I "$TARGET_CHAIN" 1 -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT; then
        echo -e "${GREEN}IPv6 $PROTO $PORT → $TARGET_CHAIN 已放行${RESET}" >&2
      else
        echo -e "${RED}IPv6 $PROTO $PORT 放行失敗${RESET}" >&2
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
  if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP >/dev/null; then
    iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
  else
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
  fi
  # IPv6
  if ip6tables -C INPUT -p ipv6-icmp --icmpv6-type 128 -j DROP >/dev/null; then
    ip6tables -D INPUT -p ipv6-icmp --icmpv6-type 128 -j DROP 2>/dev/null
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -j ACCEPT
  else
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -j ACCEPT
  fi
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
  if iptables -C INPUT -p icmp --icmp-type echo-request -j ACCEPT >/dev/null; then
    iptables -D INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
  else
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
  fi
  
  

  # IPv6
  if ip6tables -C INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT >/dev/null; then
    ip6tables -D INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT 2>/dev/null
    ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j DROP
  else
    ip6tables -A INPUT -p icmp --icmp-type echo-request -j DROP
  fi
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

-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
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
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
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
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
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
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

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
  if ! iptables -C DOCKER-USER -i $EXTERNAL_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; then
    iptables -A DOCKER-USER -i $EXTERNAL_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  fi
  if ! iptables -C DOCKER-USER -i "$EXTERNAL_INTERFACE" -j DROP; then
    iptables -A DOCKER-USER -i "$EXTERNAL_INTERFACE" -j DROP
    echo -e "${GREEN}關閉外網(IPv4)進入docker內部流量${RESET}。"
  fi
  if [ -f "$daemon" ] && grep -q '"ipv6": true' "$daemon"; then
    local ipv6=true
  fi
  if [[ "$ipv6" == "true" ]]; then
    if ! ip6tables -C DOCKER-USER -i $EXTERNAL_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; then
      ip6tables -A DOCKER-USER -i $EXTERNAL_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fi
    if ! ip6tables -C DOCKER-USER -i "$EXTERNAL_INTERFACE" -j DROP; then
      ip6tables -A DOCKER-USER -i "$EXTERNAL_INTERFACE" -j DROP
      echo -e "${GREEN}已關閉外網(IPv6)進入docker內部流量。${RESET}"
    fi
  fi
  save_rules
}

del_port() {
  local PROTO="$1"
  shift

  [ -z "$PROTO" ] && PROTO="tcp"

  if [ "$#" -eq 0 ]; then
    echo -e "${RED}錯誤：未指定端口號${RESET}" >&2
    return 1
  fi

  if [ "$fw" = "ufw" ]; then
    for PORT in "$@"; do
      [ -z "$PORT" ] && continue
      ufw delete allow "$PORT/$PROTO" 2>/dev/null
      ufw delete allow "$PORT" 2>/dev/null
    done
    return 0
  fi

  for PORT in "$@"; do
    [ -z "$PORT" ] && continue
    
    local TARGET_CHAIN="INPUT"
    # 自動偵測：是否屬於 Docker 容器
    if ss -tulnp | grep -E "[:.]$PORT\\b" | grep -qi docker; then
      TARGET_CHAIN="DOCKER-USER"
    fi

    local DEL_SUCCESS=0
    
    local ARGS_NORMAL="--dport $PORT"
    local ARGS_CONNTRACK="-m conntrack --ctorigdstport $PORT"
    local ARGS_LIST=("$ARGS_NORMAL")

    if [ "$TARGET_CHAIN" = "DOCKER-USER" ]; then
      ARGS_LIST=("$ARGS_CONNTRACK" "$ARGS_NORMAL")
    fi

    for MATCH_ARG in "${ARGS_LIST[@]}"; do
        # 刪除 ACCEPT 規則
        if iptables -D "$TARGET_CHAIN" -p "$PROTO" $MATCH_ARG -j ACCEPT 2>/dev/null; then
          echo -e "${GREEN}已刪除 IPv4 $PROTO $PORT ($MATCH_ARG) → $TARGET_CHAIN (ACCEPT)${RESET}" >&2
          DEL_SUCCESS=1
        fi
        
        # 刪除 DROP 規則 (如果有的話)
        if iptables -D "$TARGET_CHAIN" -p "$PROTO" $MATCH_ARG -j DROP 2>/dev/null; then
          echo -e "${GREEN}已刪除 IPv4 $PROTO $PORT ($MATCH_ARG) → $TARGET_CHAIN (DROP)${RESET}" >&2
          DEL_SUCCESS=1
        fi
    done

    # === 開始循環刪除 (IPv6) ===
    for MATCH_ARG in "${ARGS_LIST[@]}"; do
        # 刪除 ACCEPT
        if ip6tables -D "$TARGET_CHAIN" -p "$PROTO" $MATCH_ARG -j ACCEPT 2>/dev/null; then
          echo -e "${GREEN}已刪除 IPv6 $PROTO $PORT ($MATCH_ARG) → $TARGET_CHAIN (ACCEPT)${RESET}" >&2
          DEL_SUCCESS=1
        fi
        # 刪除 DROP
        if ip6tables -D "$TARGET_CHAIN" -p "$PROTO" $MATCH_ARG -j DROP 2>/dev/null; then
          echo -e "${GREEN}已刪除 IPv6 $PROTO $PORT ($MATCH_ARG) → $TARGET_CHAIN (DROP)${RESET}" >&2
          DEL_SUCCESS=1
        fi
    done

    if [ "$DEL_SUCCESS" -eq 0 ]; then
      echo -e "${RED}未找到可刪除規則：$PROTO $PORT ($TARGET_CHAIN)${RESET}" >&2
    fi
  done

  save_rules
  return 0
}
deny_port() {
  local PROTO="$1"
  shift
  if [ "$#" -eq 0 ]; then
    echo -e "${RED}錯誤：未指定端口號${RESET}" >&2
    return 1
  fi
  
  [ -z "$PROTO" ] && PROTO="tcp"
  

  for PORT in "$@"; do
    if [ -z "$PORT" ]; then
      continue  # 跳過空端口
    fi
    local TARGET_CHAIN="INPUT"
    local TARGET_ADD="-A"
    local IPT_ARGS="--dport"
    if ss -tulnp | grep -E "[:.]$PORT\\b" | grep -qi docker; then
      TARGET_CHAIN="DOCKER-USER"
      TARGET_ADD="-I"
      IPT_ARGS="-m conntrack --ctorigdstport"
    fi
    # ipv4
    if iptables -C $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT 2>/dev/null; then
      iptables -D $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT 2>/dev/null
    fi
    
    if ! iptables -C $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null; then
      if iptables $TARGET_ADD $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null; then
        echo -e "${GREEN}IPv4 $PROTO 端口 $PORT 已阻止${RESET}" >&2
      else
        echo -e "${RED}錯誤：無法阻止 IPv4 $PROTO 端口 $PORT${RESET}" >&2
      fi
    fi
    # ipv6
    if ip6tables -C $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT 2>/dev/null; then
      ip6tables -D $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j ACCEPT 2>/dev/null
    fi
    if ! ip6tables -C $TARGET_CHAIN -p "$PROTO" -$IPT_ARGS "$PORT" -j DROP 2>/dev/null; then
      if ip6tables $TARGET_ADD $TARGET_CHAIN -p "$PROTO" $IPT_ARGS "$PORT" -j DROP 2>/dev/null; then
        echo -e ${GREEN}"IPv6 $PROTO 端口 $PORT 已阻止${RESET}" >&2
      else
        echo -e "${RED}錯誤：無法阻止 IPv6 $PROTO 端口 $PORT${RESET}" >&2
      fi
    fi
  done
  save_rules
  return 0
}

install_fw() {
  local type="$1"
  if [ $type == iptables ]; then
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
        systemctl start netfilter-persistent
      fi
      ;;
    2)
      dnf update -y
      dnf install -y kernel-modules kernel-modules-extra
      local CURRENT_KERNEL=$(uname -r)
      local LATEST_KERNEL=$(rpm -q --queryformat "%{VERSION}-%{RELEASE}.%{ARCH}\n" kernel-core | sort -V | tail -n 1)
      if [ "$CURRENT_KERNEL" != "$LATEST_KERNEL" ]; then
        echo -e "${YELLOW}您好！
        因為我們檢測裝置檢測到您內核發生變化，這會導致後面配置iptables防火牆發生嚴重錯誤，請您立刻重啟系統！${RESET}"
        read -p "是否繼續？(一定要輸入Y/n)" confirm
        confirm=${confirm,,}
        confirm=${confirm:-n}
        if [[ $confirm == y ]]; then
          reboot
        else
          echo -e "${RED}終止運行${RESET}"
          exit 1
        fi
      fi
      dnf install -y iptables-services
      read -p "是否執行基礎防火牆配置？(Y/n): [預設為是]" confirm
      confirm=${confirm,,}  # 轉小寫
      confirm=${confirm:-y}
      systemctl enable ip6tables
      systemctl enable iptables
      if [[ "$confirm" == "y" || "$confirm" == "" ]]; then
        default_settings
      else
        systemctl start iptables
        systemctl start ip6tables
      fi
      ;;
    3)
      apk update
      apk add iptables ip6tables
      read -p "是否執行基礎防火牆配置？(Y/n): [預設為是]" confirm
      confirm=${confirm,,:-y}  # 轉小寫
      rc-update add iptables
      rc-update add ip6tables
      if [[ "$confirm" == "y" || "$confirm" == "" ]]; then
        default_settings
      else
        rc-service iptables start
        rc-service ip6tables start
      fi
    ;;
    esac
    check_fw
    menu_iptables
  elif [ $type == ufw ]; then
    case "$system" in
    1) 
    apt update
    apt install ufw -y
    ;;
    2)
      echo -e "${RED}您好,您的系統不支持ufw,請安裝iptables${RESET}"
      sleep 0.5
      exit 1
      ;;
    3)
      apk update
      apk add ufw
      ;;
    esac
    local ssh_port=$(grep -E '^Port ' /etc/ssh/sshd_config | awk '{print $2}')
    [[ -z "$ssh_port" ]] && ssh_port=22
    ufw allow $ssh_port/tcp
    echo "y" | ufw enable
    echo -e "${GREEN}UFW 防火牆已啟用${RESET}"
    check_fw
    menu_ufw
  fi
}

save_rules() {
  if [ $fw = ufw ]; then
    return 0
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

  wget -q "$download_url" -O "$temp_path"
  if [ $? -ne 0 ]; then
    echo -e "${RED}無法下載最新版本，請檢查網路連線。${RESET}"
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
      echo -e "${GREEN}更新成功！將自動重新啟動腳本以套用變更...${RESET}"
      sleep 1
      exec "$current_script"
    else
      echo -e "${RED}更新失敗，請確認權限。${RESET}"
    fi
  fi
  rm -f "$temp_path"
}

menu_allow_port() {
  local input clean_input items item ip port
  local proto_choice proto

  read -p "輸入 IP 或端口 (可多個，範圍80-82，用逗號/空格): " input
  [[ -z "$input" ]] && return 0

  clean_input="${input//,/ }"
  items=()

  for token in $clean_input; do
    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local s=${BASH_REMATCH[1]}
      local e=${BASH_REMATCH[2]}
      for ((p=s; p<=e; p++)); do items+=("$p"); done
    else
        items+=("$token")
    fi
  done

  for item in "${items[@]}"; do
    if [[ "$item" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] || [[ "$item" =~ : ]]; then
      ip="$item"
      read -p "開放特定端口? (輸入 0 或直接 Enter 代表全部開放): " port
            
      if [[ -z "$port" || "$port" == "0" ]]; then
        echo -e "\033[1;36m-> 僅放行 IP (All Ports)\033[0m"

        # UFW
        if [ $fw == ufw ]; then
          ufw allow from "$ip" >/dev/null
          echo -e "${GREEN}已放行 $ip${RESET}"
        elif [ $fw == iptables ]; then
          if [[ "$ip" =~ : ]]; then
            # IPv6
            ip6tables -A INPUT -s "$ip" -j ACCEPT
            echo -e "${GREEN}已放行 $ip${RESET}"
          else
            # IPv4
            iptables -A INPUT -s "$ip" -j ACCEPT
            echo -e "${GREEN}已放行 $ip${RESET}"
          fi
        fi
        continue
      fi
      local TARGET_CHAIN="INPUT"
      local TARGET_ADD="-A"
      local IPT_ARGS="--dport"
      if ss -tulnp | grep -E "[:.]$port\\b" | grep -qi docker; then
        TARGET_CHAIN="DOCKER-USER"
        TARGET_ADD="-I"
        IPT_ARGS="-m conntrack --ctorigdstport"
      fi
      printf "1) TCP [預設]\n2) UDP\n3) ALL\n"
      read -p "請選擇協議: " proto_choice
      case "$proto_choice" in
      2) proto="udp" ;;
      3) proto="all" ;;
      *) proto="tcp" ;;
      esac

      # UFW
      if [ $fw == ufw ]; then
        if [[ "$proto" == "all" ]]; then
          ufw allow from "$ip" to any port "$port" proto tcp >/dev/null
          ufw allow from "$ip" to any port "$port" proto udp >/dev/null
        else
          ufw allow from "$ip" to any port "$port" proto "$proto" >/dev/null
        fi
        echo -e "${GREEN}規則已添加${RESET}"
      elif [ $fw == iptables ]; then
        if [[ "$ip" =~ : ]]; then
          # IPv6
          if [[ "$proto" == "all" ]]; then
            ip6tables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p tcp $IPT_ARGS "$port" -j ACCEPT
            ip6tables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p udp $IPT_ARGS "$port" -j ACCEPT
          else
            ip6tables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p $proto $IPT_ARGS "$port" -j ACCEPT
          fi
        else
          if [[ "$proto" == "all" ]]; then
            iptables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p tcp $IPT_ARGS "$port" -j ACCEPT
            iptables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p udp $IPT_ARGS "$port" -j ACCEPT
          else
            iptables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p $proto $IPT_ARGS "$port" -j ACCEPT
          fi
        fi
        echo -e "${GREEN}規則已添加${RESET}"
      fi
      continue
    fi
    port="$item"
    local TARGET_CHAIN="INPUT"
    local TARGET_ADD="-A"
    local IPT_ARGS="--dport"
    if ss -tulnp | grep -E "[:.]$port\\b" | grep -qi docker; then
      TARGET_CHAIN="DOCKER-USER"
      TARGET_ADD="-I"
      IPT_ARGS="-m conntrack --ctorigdstport"
    fi
    printf "1) TCP [預設]\n2) UDP\n3) ALL\n"
    read -p "請選擇協議: " proto_choice
    case "$proto_choice" in
    2) proto="udp" ;;
    3) proto="all" ;;
    *) proto="tcp" ;;
    esac

    # UFW
    if command -v ufw >/dev/null; then
      if [[ "$proto" == "all" ]]; then
        ufw allow "$port" >/dev/null # UFW 預設 allow 80 會同時開 tcp/udp
        echo "${GREEN}端口 $port 已開放${RESET}"
      else
        ufw allow "$port"/"$proto" >/dev/null
        echo -e "${GREEN}端口 $port ($proto) 已開放${RESET}"
      fi
    elif [ $fw == iptables ]; then
      if [[ "$proto" == "all" ]]; then
        # TCP
        iptables $TARGET_ADD $TARGET_CHAIN -p tcp $IPT_ARGS "$port" -j ACCEPT
        ip6tables $TARGET_ADD $TARGET_CHAIN -p tcp $IPT_ARGS "$port" -j ACCEPT
        # UDP
        iptables $TARGET_ADD $TARGET_CHAIN -p udp $IPT_ARGS "$port" -j ACCEPT
        ip6tables $TARGET_ADD $TARGET_CHAIN -p udp --dport "$port" -j ACCEPT
      else
        iptables $TARGET_ADD $TARGET_CHAIN -p "$proto" $IPT_ARGS "$port" -j ACCEPT
        ip6tables $TARGET_ADD $TARGET_CHAIN -p "$proto" $IPT_ARGS "$port" -j ACCEPT
      fi
      echo -e "${GREEN}端口 $port ($proto) 已開放 (IPv4+IPv6)${RESET}"
    fi
    continue
  done

  save_rules
  echo -e "${GREEN}所有規則處理完畢。${RESET}"
  sleep 1.5
}

menu_del_port() {
  local input clean_input search_targets 
  local matches_ufw matches_ipt matches_ip6t display_list
  
  read -p "輸入端口或IP (0返回, 支援範圍 80-82): " input
  [[ "$input" == "0" ]] && return 0

  clean_input="${input//,/ }"
  search_targets=()
    
  for token in $clean_input; do
    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local start=${BASH_REMATCH[1]}
      local end=${BASH_REMATCH[2]}
      for ((p=start; p<=end; p++)); do search_targets+=("$p"); done
    else
        search_targets+=("$token")
    fi
  done

  for target in "${search_targets[@]}"; do
    # 判斷是否為 IP (IPv4 或 IPv6)
    # 判斷依據：符合 IPv4 格式 或 包含冒號 (IPv6 特徵)
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$target" =~ : ]]; then
      
      # 重置陣列
      matches_ufw=()
      matches_ipt=()
      matches_ip6t=()
            
      # 1. 搜 UFW (UFW 會混合顯示 v4/v6，邏輯不變)
      if command -v ufw >/dev/null; then
        while read -r line; do
          local num=$(echo "$line" | grep -oP '^\[\s*\K[0-9]+')
          matches_ufw+=("$num|$line")
        done < <(ufw status numbered 2>/dev/null | grep "$target")
      fi

      # 2. 搜 IPTables (IPv4)
      while read -r line; do
        matches_ipt+=("$line")
      done < <({ iptables -S INPUT; iptables -S DOCKER-USER; } 2>/dev/null | grep -w "$target")

      # 3. 搜 IP6Tables (IPv6) - [新增]
      if command -v ip6tables >/dev/null; then
        while read -r line; do
          matches_ip6t+=("$line")
        done < <({ ip6tables -S INPUT; ip6tables -S DOCKER-USER; } 2>/dev/null | grep -w "$target")
      fi

      local count_ufw=${#matches_ufw[@]}
      local count_ipt=${#matches_ipt[@]}
      local count_ip6t=${#matches_ip6t[@]}
      local total=$((count_ufw + count_ipt + count_ip6t))

      # 情境 1: 沒找到
      if (( total == 0 )); then
        echo -e "${RED}IP $target 未找到相關規則。${RESET}"
        continue
      fi

      # 情境 2: 只有 1 條 -> 秒刪
      if (( total == 1 )); then
        if (( count_ufw == 1 )); then
          IFS='|' read -r num text <<< "${matches_ufw[0]}"
          echo "y" | ufw delete "$num" >/dev/null 2>&1
        elif (( count_ipt == 1 )); then
          local rule="${matches_ipt[0]}"
          iptables ${rule/-A /-D } >/dev/null 2>&1
        elif (( count_ip6t == 1 )); then
          local rule="${matches_ip6t[0]}"
          ip6tables ${rule/-A /-D } >/dev/null 2>&1
        fi
        echo -e "${GREEN}已刪除規則${RESET}"
        continue 
      fi

      # 情境 3: 多條規則 -> 顯示選單
      echo -e "\033[1;33mIP $target 綁定多條規則，請選擇：\033[0m"
      display_list=()
      local idx=0
            
      # 顯示 UFW
      for item in "${matches_ufw[@]}"; do
        IFS='|' read -r num text <<< "$item"
        echo " $((idx+1))) [UFW] $text"
        display_list[$idx]="UFW|$num"
        ((idx++))
      done
      # 顯示 IPv4
      for item in "${matches_ipt[@]}"; do
        echo " $((idx+1))) [IPv4] $item"
        display_list[$idx]="IPT|$item"
        ((idx++))
      done
      # 顯示 IPv6
      for item in "${matches_ip6t[@]}"; do
        echo " $((idx+1))) [IPv6] $item"
        display_list[$idx]="IP6T|$item"
        ((idx++))
      done
      echo " $((idx+1))) 全部刪除 (ALL)"

      read -p "請選擇編號 (多選用空格): " choices
            
      # 處理 ALL
      if [[ "$choices" =~ $((idx+1)) ]]; then
        # 刪 IPT
        for rule in "${matches_ipt[@]}"; do iptables ${rule/-A /-D } >/dev/null 2>&1; done
        # 刪 IP6T
        for rule in "${matches_ip6t[@]}"; do ip6tables ${rule/-A /-D } >/dev/null 2>&1; done
        # 刪 UFW (倒序)
        if (( ${#matches_ufw[@]} > 0 )); then
          for (( i=${#matches_ufw[@]}-1; i>=0; i-- )); do
            IFS='|' read -r num text <<< "${matches_ufw[$i]}"
            echo "y" | ufw delete "$num" >/dev/null 2>&1
          done
        fi
        echo -e "\033[1;32m已全部刪除 $target 相關規則。\033[0m"
        continue
      fi

      # 處理多選
      local ufw_dels=()
      for c in $choices; do
        local arr_idx=$((c-1))
        [[ -z "${display_list[$arr_idx]}" ]] && continue
        local val="${display_list[$arr_idx]#*|}"
        local type="${display_list[$arr_idx]%%|*}"

        if [[ "$type" == "IPT" ]]; then
          iptables ${val/-A /-D } >/dev/null 2>&1
        elif [[ "$type" == "IP6T" ]]; then
          ip6tables ${val/-A /-D } >/dev/null 2>&1
        elif [[ "$type" == "UFW" ]]; then
          ufw_dels+=("$val")
        fi
      done
      # 執行 UFW 刪除 (倒序)
      if (( ${#ufw_dels[@]} > 0 )); then
        IFS=$'\n' sorted=($(sort -rn <<<"${ufw_dels[*]}"))
        unset IFS
        for n in "${sorted[@]}"; do echo "y" | ufw delete "$n" >/dev/null 2>&1; done
        echo -e "${GREEN}規則刪除完成。${RESET}"
      fi

    else 
      local deleted_count=0
      
      # 1. 清理 IPv4 iptables
      while read -r rule; do
        local del_cmd="${rule/-A /-D }"
        iptables $del_cmd >/dev/null 2>&1
        ((deleted_count++))
      done < <({ iptables -S INPUT; iptables -S DOCKER-USER; } 2>/dev/null | grep -w "$target")
      
      if command -v ip6tables >/dev/null; then
          while read -r rule; do
            local del_cmd="${rule/-A /-D }"
            ip6tables $del_cmd >/dev/null 2>&1
            ((deleted_count++))
          done < <({ ip6tables -S INPUT; ip6tables -S DOCKER-USER; } 2>/dev/null | grep -w "$target")
      fi

      # 3. 清理 UFW
      if command -v ufw >/dev/null; then
        local ufw_nums=()
        while read -r line; do
          local num=$(echo "$line" | grep -oP '^\[\s*\K[0-9]+')
          ufw_nums+=("$num")
        done < <(ufw status numbered 2>/dev/null | grep "$target")
        if (( ${#ufw_nums[@]} > 0 )); then
          # 倒序刪除
          IFS=$'\n' sorted=($(sort -rn <<<"${ufw_nums[*]}"))
          unset IFS
          for n in "${sorted[@]}"; do
            echo "y" | ufw delete "$n" >/dev/null 2>&1
            ((deleted_count++))
          done
        fi
      fi

      if (( deleted_count > 0 )); then
        echo -e "${GREEN}端口 $target 清理完畢，共刪除 $deleted_count 條規則。${RESET}"
      else
        echo -e "${RED}端口 $target 無相關規則。${RESET}"
      fi
    fi
  done
  save_rules
  sleep 1.5
}

menu_deny_port() {
  if [ $fw == ufw ]; then
    local ufw_policy=$(ufw status verbose 2>/dev/null | awk -F'[ :]*' '/Default:/ {print tolower($2)}')
    [[ "$ufw_policy" =~ ^(deny|reject)$ ]] && return 0
  elif [ $fw == iptables ]; then
    local ipt_policy=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/ {print $3}')
    [[ "$ipt_policy" =~ ^(DROP|REJECT)$ ]] && return 0
  fi
  local input clean_input items item ip port
  local proto_choice proto

  read -p "輸入 IP 或端口 (可多個，範圍80-82，用逗號/空格): " input
  [[ -z "$input" ]] && return 0

  clean_input="${input//,/ }"
  items=()

  for token in $clean_input; do
    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local s=${BASH_REMATCH[1]}
      local e=${BASH_REMATCH[2]}
      for ((p=s; p<=e; p++)); do items+=("$p"); done
    else
        items+=("$token")
    fi
  done

  for item in "${items[@]}"; do
    if [[ "$item" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] || [[ "$item" =~ : ]]; then
      ip="$item"
      read -p "開放特定端口? (輸入 0 或直接 Enter 代表全部開放): " port
            
      if [[ -z "$port" || "$port" == "0" ]]; then
        echo -e "\033[1;36m-> 僅放行 IP (All Ports)\033[0m"

        # UFW
        if [ $fw == ufw ]; then
          ufw deny from "$ip" >/dev/null
          echo -e "${GREEN}已阻斷 $ip${RESET}"
        elif [ $fw == iptables ]; then
          if [[ "$ip" =~ : ]]; then
            # IPv6
            ip6tables -A INPUT -s "$ip" -j DROP
            echo -e "${GREEN}已阻斷 $ip${RESET}"
          else
            # IPv4
            iptables -A INPUT -s "$ip" -j DROP
            echo -e "${GREEN}已阻斷 $ip${RESET}"
          fi
        fi
        continue
      fi
      local TARGET_CHAIN="INPUT"
      local TARGET_ADD="-A"
      local IPT_ARGS="--dport"
      if ss -tulnp | grep -E "[:.]$port\\b" | grep -qi docker; then
        TARGET_CHAIN="DOCKER-USER"
        TARGET_ADD="-I"
        IPT_ARGS="-m conntrack --ctorigdstport"
      fi
      printf "1) TCP [預設]\n2) UDP\n3) ALL\n"
      read -p "請選擇協議: " proto_choice
      case "$proto_choice" in
      2) proto="udp" ;;
      3) proto="all" ;;
      *) proto="tcp" ;;
      esac

      # UFW
      if [ $fw == ufw ]; then
        if [[ "$proto" == "all" ]]; then
          ufw deny from "$ip" to any port "$port" proto tcp >/dev/null
          ufw deny from "$ip" to any port "$port" proto udp >/dev/null
        else
          ufw deny from "$ip" to any port "$port" proto "$proto" >/dev/null
        fi
        echo -e "${GREEN}規則已添加${RESET}"
      elif [ $fw == iptables ]; then
        if [[ "$ip" =~ : ]]; then
          # IPv6
          if [[ "$proto" == "all" ]]; then
            ip6tables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p tcp $IPT_ARGS "$port" -j DROP
            ip6tables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p udp $IPT_ARGS "$port" -j DROP
          else
            ip6tables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p $proto $IPT_ARGS "$port" -j DROP
          fi
        else
          if [[ "$proto" == "all" ]]; then
            iptables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p tcp $IPT_ARGS "$port" -j DROP
            iptables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p udp $IPT_ARGS "$port" -j DROP
          else
            iptables $TARGET_ADD $TARGET_CHAIN -s "$ip" -p $proto $IPT_ARGS "$port" -j DROP
          fi
        fi
        echo -e "${GREEN}規則已添加${RESET}"
      fi
      continue
    fi
    port="$item"
    local TARGET_CHAIN="INPUT"
    local TARGET_ADD="-A"
    local IPT_ARGS="--dport"
    if ss -tulnp | grep -E "[:.]$port\\b" | grep -qi docker; then
      TARGET_CHAIN="DOCKER-USER"
      TARGET_ADD="-I"
      IPT_ARGS="-m conntrack --ctorigdstport"
    fi
    printf "1) TCP [預設]\n2) UDP\n3) ALL\n"
    read -p "請選擇協議: " proto_choice
    case "$proto_choice" in
    2) proto="udp" ;;
    3) proto="all" ;;
    *) proto="tcp" ;;
    esac

    # UFW
    if command -v ufw >/dev/null; then
      if [[ "$proto" == "all" ]]; then
        ufw allow "$port" >/dev/null # UFW 預設 allow 80 會同時開 tcp/udp
        echo "${GREEN}端口 $port 已阻斷${RESET}"
      else
        ufw allow "$port"/"$proto" >/dev/null
        echo -e "${GREEN}端口 $port ($proto) 已阻斷${RESET}"
      fi
    elif [ $fw == iptables ]; then
      if [[ "$proto" == "all" ]]; then
        # TCP
        iptables $TARGET_ADD $TARGET_CHAIN -p tcp $IPT_ARGS "$port" -j DROP
        ip6tables $TARGET_ADD $TARGET_CHAIN -p tcp $IPT_ARGS "$port" -j DROP
        # UDP
        iptables $TARGET_ADD $TARGET_CHAIN -p udp $IPT_ARGS "$port" -j DROP
        ip6tables $TARGET_ADD $TARGET_CHAIN -p udp $IPT_ARGS "$port" -j DROP
      else
        iptables $TARGET_ADD $TARGET_CHAIN -p "$proto" $IPT_ARGS "$port" -j DROP
        ip6tables $TARGET_ADD $TARGET_CHAIN -p "$proto" $IPT_ARGS "$port" -j DROP
      fi
      echo -e "${GREEN}端口 $port ($proto) 已阻斷 (IPv4+IPv6)${RESET}"
    fi
    continue
  done

  save_rules
  echo -e "${GREEN}所有規則處理完畢。${RESET}"
  sleep 1.5
}

change_default_policy() {
  local current=""
  local opposite=""

  # --- UFW ---
  if command -v ufw >/dev/null 2>&1; then
    current=$(ufw status verbose 2>/dev/null | awk -F'[ :]*' '/Default:/ {print tolower($2)}')
    if [[ -n "$current" ]]; then
      if [[ "$current" == "deny" || "$current" == "reject" ]]; then
        opposite="allow"
      else
        opposite="deny"
      fi
      read -p "目前 UFW 預設為 $current，是否要更改為 $opposite？(y/n): " yn
      [[ "$yn" =~ ^[Yy]$ ]] || return 0
      ufw default "$opposite" >/dev/null 2>&1
      echo -e "${YELLOW}UFW 預設規則已修改為 $opposite${RESET}" 
      return
    fi
  fi

  # --- iptables ---
  if command -v iptables >/dev/null 2>&1; then
    current=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/ {print tolower($3)}')
    if [[ -n "$current" ]]; then
      if [[ "$current" == "drop" || "$current" == "reject" ]]; then
        opposite="ACCEPT"
      else
        opposite="DROP"
      fi
      read -p "目前 iptables 預設為 $current，是否要更改為 $opposite？(y/n): " yn
      [[ "$yn" =~ ^[Yy]$ ]] || return 0
      iptables -P INPUT "$opposite" >/dev/null 2>&1
      echo -e "${YELLOW}iptables 預設規則已修改為 $opposite${RESET}" 
      return
    fi
  fi
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
    port=""
    proto=""
    ip=""
    echo -e "${BLUE}------------------------${RESET}"
    ufw status
    echo ""
    echo -e "${GREEN}防火牆管理${RESET}"
    echo -e "${BLUE}------------------------${RESET}"
    echo -e "${CYAN}1. 開放端口          2. 刪除端口${RESET}"
    echo ""
    echo -e "${CYAN}3. 阻斷端口（給預設規則為ACCEPT的）${RESET}"
    echo ""
    echo -e "${CYAN}4. 禁止ping             5. 允許ping${RESET}"
    echo ""
    echo -e "${CYAN}6. 允許CloudFlare IP      7. 刪除CloudFlare IP${RESET}"
    echo ""
    echo -e "${CYAN}8. 阻止Censys IP訪問   9. 刪除阻止Censys IP${RESET}"
    echo ""
    echo -e "${CYAN}10. 更改防火牆預設規則${RESET}"
    echo -e "${BLUE}------------------------${RESET}"
    echo -e "${RED}0. 退出                  u. 更新腳本${RESET}"
    echo ""
    echo -n -e "${YELLOW}請選擇操作 [0-10 / u]: ${RESET}"
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
      menu_deny_port
      ;;
    4)
      clear
      block_ping 
      read -p "操作完成，請按任意鍵..." -n1
      ;;
    5)
      clear
      allow_ping 
      read -p "操作完成，請按任意鍵..." -n1
      ;;
    6)
      allow_cf_ip 
      read -p "操作完成，請按任意鍵..." -n1
      ;;
    7)
      del_cf_ip 
      read -p "操作完成，請按任意鍵..." -n1
      ;;
    8)
      censys_block add
      ;;
    9)
      censys_block del
      ;;
    10)
      change_default_policy
      ;;
    0)
      echo "感謝使用防火牆管理工具，再見！"
      exit 0
      ;;
    u)
      clear
      update_script
      ;;
    *)
      echo "無效選擇，請重試"
      sleep 0.5
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
    echo -e "${BLUE}------------------------${RESET}"
    echo -e "${YELLOW}此顯示防火牆規則為ipv4${RESET}"
    iptables -L INPUT
    echo ""
    echo -e "${GREEN}防火牆管理${RESET}"
    echo -e "${BLUE}------------------------${RESET}"
    echo -e "${CYAN}1. 開放端口          2. 刪除端口${RESET}"
    echo ""
    echo -e "${CYAN}3. 阻斷端口（給預設規則為ACCEPT的）${RESET}"
    echo ""
    echo -e "${CYAN}4. 禁止ping             5. 允許ping${RESET}"
    echo ""
    echo -e "${BOLD_CYAN}6. 基礎設置(建議)       7. 關閉外網進入docker內部流量（建議）${RESET}"
    echo ""
    echo -e "${CYAN}8. 允許CloudFlare IP      9. 刪除CloudFlare IP${RESET}"
    echo ""
    echo -e "${CYAN}10. 阻止Censys IP訪問   11. 刪除阻止Censys IP${RESET}"
    echo ""
    echo -e "${CYAN}12. 顯示ipv6防火牆規則    13. 更改防火牆預設規則${RESET}"
    echo ""
    echo -e "${BLUE}------------------------${RESET}"
    echo -e "${RED}0. 退出              u. 更新腳本${RESET}"
    echo ""
    echo -n -e "${YELLOW}請選擇操作 [0-13 / u]: ${RESET}"
    read -r choice
    case $choice in
    1)
      menu_allow_port
      ;;
    2)
      menu_del_port
      ;;
    3)
      menu_deny_port
      ;;
    4)
      block_ping
      ;;
    5)
      allow_ping
      ;;
    6)
      clear
      default_settings
      read -p "按任意鍵繼續..." -n1
      ;;
    7)
      clear
      disable_in_docker
      ;;
    8)
      clear
      allow_cf_ip 
      ;;
    9)
      clear
      del_cf_ip 
      ;;
    10)
      clear
      censys_block add
      ;;
    11)
      clear
      censys_block del
      ;;
    12)
      clear
      ip6tables -L INPUT
      read -p "操作完成，按任意鍵繼續..." -n1
      ;;
    13)
      clear
      change_default_policy
      ;;
    0)
      echo "感謝使用防火牆管理工具，再見！"
      exit 0
      ;;
    u)
      clear
      update_script
      ;;
    *)
      echo -e "${RED}無效選擇，請重試${RESET}"
      sleep 0.5
      ;;
    esac
  done
}
menu_install_fw(){
  if [ $fw != none ]; then
    return 0
  fi
  while true; do
    clear
    echo "1. 安裝UFW(適合純新手,不裝docker)"
    echo ""
    echo "2. 安裝iptables(適合比較進階的人,裝docker)"
    echo "-----------------"
    read -p "請選擇操作:[1-2]" comfin
    case $comfin in
    1)
      install_fw ufw
      ;;
    2)
      install_fw iptables 
      ;;    
    esac
  done
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
[[ -z $# ]] && check_cli_fw
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
      proto_cli=${4:-tcp}
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