# abuse-geodata

**[English](#english) | [Русский](#russian)**

---

<a name="english"></a>
## English

Automated threat intelligence geodata for **Xray**, **sing-box**, and **ipset**.  
Built daily from public abuse feeds. Designed for VPN operators, hosting providers, and network administrators to protect infrastructure and reduce abuse complaints.

### Downloads

All files are published as [GitHub Releases](../../releases/latest).

| File | Format | Use case |
|------|--------|----------|
| `geoip.dat` | Xray/V2Ray | `geoip:category-*` routing rules |
| `geosite.dat` | Xray/V2Ray | `geosite:category-*` routing rules |
| `geoip.db` | MaxMind MMDB | sing-box `geoip` rules |
| `srs/category-*.srs` | sing-box | Per-category rule-sets |
| `srs/category-bundle-strict-*.srs` | sing-box | Aggregated stable categories only |
| `srs/category-bundle-full-*.srs` | sing-box | All categories including noisy |
| `txt/category-*.txt` | Plain text | ipset, hosts file, custom scripts |

### Usage

#### Xray

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:category-sinkhole",
          "geoip:category-malware-c2",
          "geoip:category-spam",
          "geoip:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "geosite:category-malware-c2",
          "geosite:category-phishing",
          "geosite:category-cryptojacking"
        ],
        "outboundTag": "block"
      }
    ]
  },
  "outbounds": [
    { "tag": "block", "protocol": "blackhole" }
  ]
}
```

Place `geoip.dat` and `geosite.dat` in your Xray assets directory (default: `/usr/local/share/xray/`).

#### sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "malware-c2-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/your-org/abuse-geodata/releases/latest/download/category-malware-c2-ip.srs",
        "update_interval": "24h"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "malware-c2-ip",
          "malware-c2-domain",
          "sinkhole",
          "phishing"
        ],
        "outbound": "block"
      }
    ]
  }
}
```

#### ipset (Linux)

```bash
ipset create abuse-block hash:net
curl -sL https://github.com/your-org/abuse-geodata/releases/latest/download/category-bundle-strict-ip.txt \
  | grep -v '^#' | xargs -I{} ipset add abuse-block {}

iptables -I FORWARD -m set --match-set abuse-block dst -j DROP
```

### Categories

| Category | Type | Description | Flags |
|----------|------|-------------|-------|
| `category-sinkhole` | IP | Known sinkhole IPs operated by security researchers | – |
| `category-malware-c2` | IP + Domain | Malware C2 servers (botnets, ransomware, trojans) | – |
| `category-phishing` | Domain | Phishing domains | ⚡ volatile |
| `category-spam` | IP | Spamhaus DROP/EDROP – hijacked IP blocks | – |
| `category-tor-exit` | IP | Tor exit nodes | ⚠️ controversial |
| `category-brute-force` | IP | IPs conducting brute-force attacks | ⚡ volatile |
| `category-cryptojacking` | IP + Domain | Cryptomining pools used for unauthorized mining | – |
| `category-dga` | Domain | DGA-generated malware domains | ⚠️ high FP, large |

#### Flag legend

| Flag | Meaning |
|------|---------|
| `high_false_positive` | Legitimate traffic may be blocked. Review before deploying. |
| `high_volatility` | List changes rapidly. IPs may be reassigned to legitimate users. |
| `controversial` | Blocking has valid counter-arguments depending on use case. |
| `large_dataset` | Large number of entries. May affect routing performance. |

#### Bundles

- **`category-bundle-strict-*`** – only categories with no `high_false_positive` or `large_dataset` flags. Safe for most deployments.
- **`category-bundle-full-*`** – all categories. Includes DGA and other noisy sets.

### Sources

| Source | URL |
|--------|-----|
| Feodo Tracker (abuse.ch) | https://feodotracker.abuse.ch |
| URLhaus (abuse.ch) | https://urlhaus.abuse.ch |
| Emerging Threats | https://rules.emergingthreats.net |
| Spamhaus DROP/EDROP | https://www.spamhaus.org/drop/ |
| Tor Project | https://check.torproject.org/torbulkexitlist |
| blocklist.de | https://www.blocklist.de |
| OpenPhish | https://openphish.com |
| brakmic/Sinkholes | https://github.com/brakmic/Sinkholes |
| Bambenek DGA feed | https://bambenekconsulting.com |

### Update schedule

Rebuilt automatically every day at **03:00 UTC** via GitHub Actions.

---

<a name="russian"></a>
## Русский

Автоматически обновляемые threat intelligence данные в форматах **Xray**, **sing-box** и **ipset**.  
Собираются ежедневно из публичных abuse-фидов. Предназначены для операторов VPN, хостинг-провайдеров и сетевых администраторов – для защиты инфраструктуры и снижения числа abuse-жалоб.

### Загрузка

Все файлы публикуются в [GitHub Releases](../../releases/latest).

| Файл | Формат | Применение |
|------|--------|------------|
| `geoip.dat` | Xray/V2Ray | Правила роутинга `geoip:category-*` |
| `geosite.dat` | Xray/V2Ray | Правила роутинга `geosite:category-*` |
| `geoip.db` | MaxMind MMDB | Правила `geoip` в sing-box |
| `srs/category-*.srs` | sing-box | Rule-set на каждую категорию |
| `srs/category-bundle-strict-*.srs` | sing-box | Агрегат – только стабильные категории |
| `srs/category-bundle-full-*.srs` | sing-box | Агрегат – все категории включая шумные |
| `txt/category-*.txt` | Обычный текст | ipset, hosts-файл, кастомные скрипты |

### Использование

#### Xray

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:category-sinkhole",
          "geoip:category-malware-c2",
          "geoip:category-spam",
          "geoip:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "geosite:category-malware-c2",
          "geosite:category-phishing",
          "geosite:category-cryptojacking"
        ],
        "outboundTag": "block"
      }
    ]
  },
  "outbounds": [
    { "tag": "block", "protocol": "blackhole" }
  ]
}
```

Положи `geoip.dat` и `geosite.dat` в директорию ресурсов Xray (по умолчанию `/usr/local/share/xray/`).

#### sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "malware-c2-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/your-org/abuse-geodata/releases/latest/download/category-malware-c2-ip.srs",
        "update_interval": "24h"
      }
    ],
    "rules": [
      {
        "rule_set": ["malware-c2-ip", "malware-c2-domain", "sinkhole", "phishing"],
        "outbound": "block"
      }
    ]
  }
}
```

#### ipset (Linux)

```bash
ipset create abuse-block hash:net
curl -sL https://github.com/your-org/abuse-geodata/releases/latest/download/category-bundle-strict-ip.txt \
  | grep -v '^#' | xargs -I{} ipset add abuse-block {}

iptables -I FORWARD -m set --match-set abuse-block dst -j DROP
```

### Категории

| Категория | Тип | Описание | Флаги |
|-----------|-----|----------|-------|
| `category-sinkhole` | IP | Известные sinkhole IP исследователей безопасности | – |
| `category-malware-c2` | IP + Domain | C2-серверы малвари (ботнеты, ransomware, трояны) | – |
| `category-phishing` | Domain | Фишинговые домены | ⚡ волатильный |
| `category-spam` | IP | Spamhaus DROP/EDROP – захваченные спамерами блоки | – |
| `category-tor-exit` | IP | Exit-ноды сети Tor | ⚠️ спорный |
| `category-brute-force` | IP | IP-адреса, ведущие брутфорс-атаки | ⚡ волатильный |
| `category-cryptojacking` | IP + Domain | Майнинг-пулы для несанкционированного майнинга | – |
| `category-dga` | Domain | DGA-домены малвари | ⚠️ высокий FP, большой |

#### Описание флагов

| Флаг | Значение |
|------|----------|
| `high_false_positive` | Возможна блокировка легитимного трафика. Проверь перед деплоем. |
| `high_volatility` | Список меняется часто. IP могут быть переназначены легитимным пользователям. |
| `controversial` | У блокировки есть весомые контраргументы в зависимости от контекста использования. |
| `large_dataset` | Большое число записей. Может влиять на производительность роутинга. |

#### Бандлы

- **`category-bundle-strict-*`** – только категории без флагов `high_false_positive` и `large_dataset`. Безопасен для большинства деплоев.
- **`category-bundle-full-*`** – все категории, включая DGA и другие шумные наборы.

### Источники

| Источник | URL |
|----------|-----|
| Feodo Tracker (abuse.ch) | https://feodotracker.abuse.ch |
| URLhaus (abuse.ch) | https://urlhaus.abuse.ch |
| Emerging Threats | https://rules.emergingthreats.net |
| Spamhaus DROP/EDROP | https://www.spamhaus.org/drop/ |
| Tor Project | https://check.torproject.org/torbulkexitlist |
| blocklist.de | https://www.blocklist.de |
| OpenPhish | https://openphish.com |
| brakmic/Sinkholes | https://github.com/brakmic/Sinkholes |
| Bambenek DGA feed | https://bambenekconsulting.com |

### Расписание обновлений

Пересборка автоматически каждый день в **03:00 UTC** через GitHub Actions.

---

## Contributing

PRs welcome. To add a new source – добавь запись в соответствующий `sources/category-*.yml` или создай новый файл по образцу существующих.
