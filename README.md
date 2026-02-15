# 防火牆管理器

我整合了 **UFW** 和 **iptables**，讓你能夠輕鬆管理防火牆規則，不必再分別執行多個工具。即使是多系統環境，也能快速部署。
- 支援 UFW、iptables
- 一鍵加入或移除 Cloudflare IP 白名單
- 阻擋常見掃描器 IP
- 開啟關閉端口和IP智能化
- 支援 Debian / RHEL / Alpine
- 支援 CLI模式,參考[CLI文檔](https://blog.gebu8f.com/fw_cli/)
- 自動配置防火牆
- 可修改SSH端口和密鑰登入 (而外功能)

---

## 快速安裝

只需一行指令即可安裝：
```bash
bash <(curl -SL http://sh.gebu8f.com/fw.sh)
```
再來就可以使用fw指令開啟面板
