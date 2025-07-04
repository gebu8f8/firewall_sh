#!/bin/bash
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
check_system
save_rules() {
  if [ "$system" -eq 1 ]; then
    echo "儲存防火牆規則中..."

    mkdir -p /etc/iptables

    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    iptables-restore < /etc/iptables/rules.v4
    ip6tables-restore < /etc/iptables/rules.v6
  elif [ "$system" -eq 2 ]; then
    # 儲存規則
    service iptables save
    service ip6tables save
  elif [ "$system" -eq 3 ]; then
    /etc/init.d/iptables save
    /etc/init.d/ip6tables save
  else
    echo "此系統目前尚未支援自動儲存規則。"
  fi
}

EXT_IF=$(ip route | grep default | grep -o 'dev [^ ]*' | cut -d' ' -f2)
[ -z "$EXT_IF" ] && EXT_IF="eth0"  # fallback 預設

while true; do
  networks=$(docker network ls -q | xargs -n1 docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')

  for cidr in $networks; do
    # NAT
    if ! iptables -t nat -C POSTROUTING -s "$cidr" -j MASQUERADE &>/dev/null; then
      iptables -t nat -A POSTROUTING -s "$cidr" -j MASQUERADE
      echo "$(date) [NAT] 加入 $cidr" >> /var/log/docker_fw.log
    fi

    # FORWARD 出
    if ! iptables -C FORWARD -s "$cidr" -j ACCEPT &>/dev/null; then
      iptables -A FORWARD -s "$cidr" -j ACCEPT
      echo "$(date) [FORWARD] 出口 $cidr" >> /var/log/docker_fw.log
    fi

    # FORWARD 回
    if ! iptables -C FORWARD -d "$cidr" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null; then
      iptables -A FORWARD -d "$cidr" -m state --state RELATED,ESTABLISHED -j ACCEPT
      echo "$(date) [FORWARD] 回應 $cidr" >> /var/log/docker_fw.log
    fi
    save_rules
  done

  sleep 15  # 每 15 秒掃描一次
done
