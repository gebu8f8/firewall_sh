#!/bin/bash


check_system(){
  if command -v apt >/dev/null 2>&1; then
    system=1
  elif command -v yum >/dev/null 2>&1; then
    system=2
  elif command -v apk >/dev/null 2>&1; then
    system=3
  fi
}

save_rules() {
  case "$system" in
    1)
      mkdir -p /etc/iptables
      iptables-save > /etc/iptables/rules.v4
      ip6tables-save > /etc/iptables/rules.v6
      ;;
    2)
      service iptables save
      service ip6tables save
      ;;
    3)
      /etc/init.d/iptables save
      /etc/init.d/ip6tables save
      ;;
  esac
}

# 偵測系統類型
check_system


while true; do
  # 標記本次迴圈是否有規則變更
  rules_changed=0

  # 1. 獲取 "事實標準"：當前所有活躍的 Docker 網路子網
  # 使用 grep '.' 過濾掉沒有子網的網路（例如 host 模式），並用 sort -u 確保唯一性
  current_subnets=$(docker network ls -q | xargs -r -n1 docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null | grep '.' | sort -u)

  # 2. 獲取 "當前配置"：從 iptables 中找出所有已配置的 Docker 子網
  # 我們可以通過 nat 表中的 MASQUERADE 規則來識別它們
  configured_subnets=$(iptables-save -t nat | grep 'MASQUERADE' | grep -o ' -s \S*/\S*' | awk '{print $2}' | sort -u)

  # 3. 遍歷當前活躍的網路，如果規則不存在就添加
  for cidr in $current_subnets; do
    # 檢查 NAT 規則是否存在
    if ! iptables -t nat -C POSTROUTING -s "$cidr" -j MASQUERADE &>/dev/null; then
      # 添加 NAT 規則
      iptables -t nat -A POSTROUTING -s "$cidr" -j MASQUERADE
      # 添加 FORWARD 規則
      iptables -A FORWARD -s "$cidr" -j ACCEPT
      iptables -A FORWARD -d "$cidr" -m state --state RELATED,ESTABLISHED -j ACCEPT
      rules_changed=1
    fi
  done

  # 4. 遍歷已配置的規則，如果對應的網路已不存在就刪除
  for cidr in $configured_subnets; do
    # 檢查這個已配置的 CIDR 是否還在活躍的網路列表中
    # 使用 grep -w 精確匹配整個單詞
    if ! echo "$current_subnets" | grep -q -w "$cidr"; then
      # 刪除 NAT 規則
      iptables -t nat -D POSTROUTING -s "$cidr" -j MASQUERADE &>/dev/null
      # 刪除 FORWARD 規則
      iptables -D FORWARD -s "$cidr" -j ACCEPT &>/dev/null
      iptables -D FORWARD -d "$cidr" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null
      rules_changed=1
    fi
  done

  # 如果本次迴圈中有任何規則被添加或刪除，才執行儲存操作
  if [ "$rules_changed" -eq 1 ]; then
    save_rules
  fi

  # 休眠 15 秒
  sleep 15
done
