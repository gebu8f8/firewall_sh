#!/bin/bash

install_path="/usr/local/bin/fw"
run_cmd="fw"

echo "正在下載腳本..."
wget -qO "$install_path" https://gitlab.com/gebu8f/sh/-/raw/main/firewall/fw.sh || {
  echo "下載失敗，請檢查網址或網路狀態。"
  exit 1
}

chmod +x "$install_path"

echo
echo "腳本已成功安裝！"
echo "請輸入 '$run_cmd' 啟動面板。"

read -n 1 -s -r -p "按任意鍵立即啟動..." key
echo
"$run_cmd"