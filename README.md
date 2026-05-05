# abuse-geodata

**[English](#english) | [Русский](#russian) | [中文](#chinese)**

---

<a name="english"></a>
## English

Automated threat intelligence geodata for **Xray**, **sing-box**, and **ipset**.  
Built daily from public abuse feeds. Designed for VPN operators, hosting providers, and network administrators to protect infrastructure and reduce abuse complaints.

### Downloads

All files are published as [GitHub Releases](../../releases/latest).

| File | Format | Use case |
|:-----|:-------|:---------|
| `abuse-geoip.dat` | Xray/V2Ray | `ext:abuse-geoip.dat:category-*` rules |
| `abuse-geosite.dat` | Xray/V2Ray | `ext:abuse-geosite.dat:category-*` rules |
| `abuse-geoip.db` | MaxMind MMDB | sing-box geoip rules |
| `abuse-category-*.srs` | sing-box | Per-category rule-sets |
| `abuse-category-bundle-strict-*.srs` | sing-box | Stable categories only |
| `abuse-category-bundle-full-*.srs` | sing-box | All categories |
| `abuse-category-*.txt` | Plain text | ipset, hosts, scripts |

### Usage

#### Xray

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "ext:abuse-geoip.dat:category-sinkhole",
          "ext:abuse-geoip.dat:category-malware-c2",
          "ext:abuse-geoip.dat:category-spam",
          "ext:abuse-geoip.dat:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "ext:abuse-geosite.dat:category-malware-c2",
          "ext:abuse-geosite.dat:category-phishing"
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

Place `abuse-geoip.dat` and `abuse-geosite.dat` in your Xray assets directory (default: `/usr/local/share/xray/`).

#### Remnawave/Remnanode (Docker)

1. Create the assets directory and download the files:

```bash
mkdir -p /opt/remnanode/xray/share

curl -sLo /opt/remnanode/xray/share/abuse-geoip.dat \
  https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geoip.dat

curl -sLo /opt/remnanode/xray/share/abuse-geosite.dat \
  https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geosite.dat
```

2. Mount the files in `docker-compose.yml` (remnanode service):

```yaml
volumes:
  - /opt/remnanode/xray/share/abuse-geoip.dat:/usr/local/bin/abuse-geoip.dat:ro
  - /opt/remnanode/xray/share/abuse-geosite.dat:/usr/local/bin/abuse-geosite.dat:ro
```

3. Add routing rules in Xray config (via Remnawave panel or config file):

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "ext:abuse-geoip.dat:category-sinkhole",
          "ext:abuse-geoip.dat:category-malware-c2",
          "ext:abuse-geoip.dat:category-spam",
          "ext:abuse-geoip.dat:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "ext:abuse-geosite.dat:category-malware-c2",
          "ext:abuse-geosite.dat:category-phishing"
        ],
        "outboundTag": "block"
      }
    ]
  }
}
```

4. Auto-update (optional) — add to crontab:

```bash
0 4 * * * curl -sLo /opt/remnanode/xray/share/abuse-geoip.dat https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geoip.dat && curl -sLo /opt/remnanode/xray/share/abuse-geosite.dat https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geosite.dat && docker restart remnanode
```

#### sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "malware-c2-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-category-malware-c2-ip.srs",
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
curl -sL https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-category-spam-ip.txt \
  | grep -v '^#' | xargs -I{} ipset add abuse-block {}

iptables -I FORWARD -m set --match-set abuse-block dst -j DROP
```

### Categories

| Category | Type | Description | Flags |
|:---------|:-----|:------------|:------|
| `category-sinkhole` | IP | Known sinkhole IPs operated by security researchers | – |
| `category-sinkhole-domain` | Domain | Sinkhole domains seized by CERT.PL | large |
| `category-malware-c2` | IP + Domain | Malware C2 servers (botnets, ransomware, trojans) | – |
| `category-phishing` | Domain | Phishing domains | volatile |
| `category-spam` | IP | Spamhaus DROP/EDROP – hijacked IP blocks | – |
| `category-tor-exit` | IP | Tor exit nodes | controversial |
| `category-brute-force` | IP | IPs conducting brute-force attacks | volatile |
| `category-torrent` | Domain | Torrent sites and piracy resources (legal excluded) | controversial, large |
| `category-torrent-legal` | Domain | Legitimate torrent services (Linux distros, archives, FOSS) | – |
| `category-torrent-announce` | IP + Domain | BitTorrent tracker announce servers | controversial |
| `category-threatview` | Domain | Threatview.io aggregated malware/phishing domains | large |
| `category-dga` | Domain | DGA-generated malware domains | high FP, large |

#### Flag legend

| Flag | Meaning |
|:-----|:--------|
| `high_false_positive` | Legitimate traffic may be blocked. Review before deploying. |
| `high_volatility` | List changes rapidly. IPs may be reassigned to legitimate users. |
| `controversial` | Blocking has valid counter-arguments depending on use case. |
| `large_dataset` | Large number of entries. May affect routing performance. |

#### Bundles

- **`category-bundle-strict-*`** – only categories with no `high_false_positive` or `large_dataset` flags. Safe for most deployments.
- **`category-bundle-full-*`** – all categories. Includes DGA and other noisy sets.

### Sources

| Source | URL |
|:-------|:----|
| Feodo Tracker (abuse.ch) | https://feodotracker.abuse.ch |
| URLhaus (abuse.ch) | https://urlhaus.abuse.ch |
| ThreatFox full export (abuse.ch) | https://threatfox.abuse.ch |
| Emerging Threats | https://rules.emergingthreats.net |
| C2IntelFeeds | https://github.com/drb-ra/C2IntelFeeds |
| Threatview.io | https://threatview.io |
| Disconnect.me | https://disconnect.me |
| CyberHost Malware | https://cyberhost.uk |
| ShadowWhisperer | https://github.com/ShadowWhisperer/BlockLists |
| Spamhaus DROP/EDROP | https://www.spamhaus.org/drop/ |
| Tor Project | https://check.torproject.org/torbulkexitlist |
| blocklist.de | https://www.blocklist.de |
| OpenPhish | https://openphish.com |
| brakmic/Sinkholes | https://github.com/brakmic/Sinkholes |
| CERT.PL Sinkhole | https://hole.cert.pl |
| Bambenek DGA feed | https://bambenekconsulting.com |
| blocklistproject Torrent | https://github.com/blocklistproject/Lists |
| hagezi Anti-Piracy | https://github.com/hagezi/dns-blocklists |
| ngosang Trackers | https://github.com/ngosang/trackerslist |

### Testing

Each build runs `scripts/test.py` to validate all output files:

- `.dat` files exist and have minimum expected size
- `.db` (MMDB) has valid MaxMind metadata structure
- `.srs` files decompile successfully with sing-box
- `.txt` files contain only valid IPs/domains
- Every source category has corresponding output files
- txt/srs entry counts are consistent

```bash
# test current build output
python scripts/test.py

# test a downloaded release in another directory
python scripts/test.py /path/to/release-dir
```

The release directory should have the same structure: `output/`, `output/srs/`, `output/txt/`, `sources/`, and optionally `tools/sing-box`.

### Update schedule

Rebuilt automatically every day at **03:00 UTC** via GitHub Actions.

### Telegram bot

Subscribe to [@abuse_geodata_bot](https://t.me/abuse_geodata_bot) to get notifications about new releases with per-category stats and delta from the previous build.

---

<a name="russian"></a>
## Русский

Автоматически обновляемые threat intelligence данные в форматах **Xray**, **sing-box** и **ipset**.  
Собираются ежедневно из публичных abuse-фидов. Предназначены для операторов VPN, хостинг-провайдеров и сетевых администраторов – для защиты инфраструктуры и снижения числа abuse-жалоб.

### Загрузка

Все файлы публикуются в [GitHub Releases](../../releases/latest).

| Файл | Формат | Применение |
|:-----|:-------|:-----------|
| `abuse-geoip.dat` | Xray/V2Ray | Правила `ext:abuse-geoip.dat:category-*` |
| `abuse-geosite.dat` | Xray/V2Ray | Правила `ext:abuse-geosite.dat:category-*` |
| `abuse-geoip.db` | MaxMind MMDB | sing-box geoip правила |
| `abuse-category-*.srs` | sing-box | Rule-set на каждую категорию |
| `abuse-category-bundle-strict-*.srs` | sing-box | Только стабильные категории |
| `abuse-category-bundle-full-*.srs` | sing-box | Все категории |
| `abuse-category-*.txt` | Текст | ipset, hosts, скрипты |

### Использование

#### Xray

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "ext:abuse-geoip.dat:category-sinkhole",
          "ext:abuse-geoip.dat:category-malware-c2",
          "ext:abuse-geoip.dat:category-spam",
          "ext:abuse-geoip.dat:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "ext:abuse-geosite.dat:category-malware-c2",
          "ext:abuse-geosite.dat:category-phishing"
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

Положи `abuse-geoip.dat` и `abuse-geosite.dat` в директорию ресурсов Xray (по умолчанию `/usr/local/share/xray/`).

#### Remnawave/Remnanode (Docker)

1. Создай директорию и скачай файлы:

```bash
mkdir -p /opt/remnanode/xray/share

curl -sLo /opt/remnanode/xray/share/abuse-geoip.dat \
  https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geoip.dat

curl -sLo /opt/remnanode/xray/share/abuse-geosite.dat \
  https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geosite.dat
```

2. Примонтируй файлы в `docker-compose.yml` (сервис remnanode):

```yaml
volumes:
  - /opt/remnanode/xray/share/abuse-geoip.dat:/usr/local/bin/abuse-geoip.dat:ro
  - /opt/remnanode/xray/share/abuse-geosite.dat:/usr/local/bin/abuse-geosite.dat:ro
```

3. Добавь правила маршрутизации в конфиг Xray (через панель Remnawave или конфиг-файл):

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "ext:abuse-geoip.dat:category-sinkhole",
          "ext:abuse-geoip.dat:category-malware-c2",
          "ext:abuse-geoip.dat:category-spam",
          "ext:abuse-geoip.dat:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "ext:abuse-geosite.dat:category-malware-c2",
          "ext:abuse-geosite.dat:category-phishing"
        ],
        "outboundTag": "block"
      }
    ]
  }
}
```

4. Автообновление (опционально) — добавь в crontab:

```bash
0 4 * * * curl -sLo /opt/remnanode/xray/share/abuse-geoip.dat https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geoip.dat && curl -sLo /opt/remnanode/xray/share/abuse-geosite.dat https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geosite.dat && docker restart remnanode
```

#### sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "malware-c2-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-category-malware-c2-ip.srs",
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
curl -sL https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-category-spam-ip.txt \
  | grep -v '^#' | xargs -I{} ipset add abuse-block {}

iptables -I FORWARD -m set --match-set abuse-block dst -j DROP
```

### Категории

| Категория | Тип | Описание | Флаги |
|:----------|:----|:---------|:------|
| `category-sinkhole` | IP | Известные sinkhole IP исследователей безопасности | – |
| `category-sinkhole-domain` | Domain | Sinkhole-домены, перехваченные CERT.PL | большой |
| `category-malware-c2` | IP + Domain | C2-серверы малвари (ботнеты, ransomware, трояны) | – |
| `category-phishing` | Domain | Фишинговые домены | волатильный |
| `category-spam` | IP | Spamhaus DROP/EDROP – захваченные спамерами блоки | – |
| `category-tor-exit` | IP | Exit-ноды сети Tor | спорный |
| `category-brute-force` | IP | IP-адреса, ведущие брутфорс-атаки | волатильный |
| `category-torrent` | Domain | Торрент-сайты и пиратские ресурсы (без легальных) | спорный, большой |
| `category-torrent-legal` | Domain | Легитимные торрент-сервисы (Linux-дистрибутивы, архивы, FOSS) | – |
| `category-torrent-announce` | IP + Domain | Announce-серверы BitTorrent-трекеров | спорный |
| `category-dga` | Domain | DGA-домены малвари | высокий FP, большой |

#### Описание флагов

| Флаг | Значение |
|:-----|:---------|
| `high_false_positive` | Возможна блокировка легитимного трафика. Проверь перед деплоем. |
| `high_volatility` | Список меняется часто. IP могут быть переназначены легитимным пользователям. |
| `controversial` | У блокировки есть весомые контраргументы в зависимости от контекста использования. |
| `large_dataset` | Большое число записей. Может влиять на производительность роутинга. |

#### Бандлы

- **`category-bundle-strict-*`** – только категории без флагов `high_false_positive` и `large_dataset`. Безопасен для большинства деплоев.
- **`category-bundle-full-*`** – все категории, включая DGA и другие шумные наборы.

### Источники

| Источник | URL |
|:---------|:----|
| Feodo Tracker (abuse.ch) | https://feodotracker.abuse.ch |
| URLhaus (abuse.ch) | https://urlhaus.abuse.ch |
| ThreatFox full export (abuse.ch) | https://threatfox.abuse.ch |
| Emerging Threats | https://rules.emergingthreats.net |
| C2IntelFeeds | https://github.com/drb-ra/C2IntelFeeds |
| Threatview.io | https://threatview.io |
| Disconnect.me | https://disconnect.me |
| CyberHost Malware | https://cyberhost.uk |
| ShadowWhisperer | https://github.com/ShadowWhisperer/BlockLists |
| Spamhaus DROP/EDROP | https://www.spamhaus.org/drop/ |
| Tor Project | https://check.torproject.org/torbulkexitlist |
| blocklist.de | https://www.blocklist.de |
| OpenPhish | https://openphish.com |
| brakmic/Sinkholes | https://github.com/brakmic/Sinkholes |
| CERT.PL Sinkhole | https://hole.cert.pl |
| Bambenek DGA feed | https://bambenekconsulting.com |
| blocklistproject Torrent | https://github.com/blocklistproject/Lists |
| hagezi Anti-Piracy | https://github.com/hagezi/dns-blocklists |
| ngosang Trackers | https://github.com/ngosang/trackerslist |

### Тестирование

Каждый билд запускает `scripts/test.py` для валидации всех выходных файлов:

- `.dat` файлы существуют и имеют минимальный ожидаемый размер
- `.db` (MMDB) имеет валидную структуру метаданных MaxMind
- `.srs` файлы успешно декомпилируются sing-box
- `.txt` файлы содержат только валидные IP/домены
- Каждая категория из sources имеет соответствующие выходные файлы
- Количество записей в txt и srs консистентно

```bash
# тест текущего билда
python scripts/test.py

# тест скачанного релиза в другой директории
python scripts/test.py /path/to/release-dir
```

Директория релиза должна иметь структуру: `output/`, `output/srs/`, `output/txt/`, `sources/`, и опционально `tools/sing-box`.

### Расписание обновлений

Пересборка автоматически каждый день в **03:00 UTC** через GitHub Actions.

### Telegram-бот

Подпишись на [@abuse_geodata_bot](https://t.me/abuse_geodata_bot), чтобы получать уведомления о новых релизах со статистикой по категориям и дельтой от предыдущей сборки.

---

<a name="chinese"></a>
## 中文

自动化威胁情报地理数据，支持 **Xray**、**sing-box** 和 **ipset**。  
每日从公开 abuse 数据源构建。专为 VPN 运营商、主机托管商和网络管理员设计，用于保护基础设施、减少滥用投诉。

### 下载

所有文件发布在 [GitHub Releases](../../releases/latest)。

| 文件 | 格式 | 用途 |
|:-----|:-----|:-----|
| `abuse-geoip.dat` | Xray/V2Ray | `ext:abuse-geoip.dat:category-*` 规则 |
| `abuse-geosite.dat` | Xray/V2Ray | `ext:abuse-geosite.dat:category-*` 规则 |
| `abuse-geoip.db` | MaxMind MMDB | sing-box geoip 规则 |
| `abuse-category-*.srs` | sing-box | 按类别的规则集 |
| `abuse-category-bundle-strict-*.srs` | sing-box | 仅稳定类别 |
| `abuse-category-bundle-full-*.srs` | sing-box | 所有类别 |
| `abuse-category-*.txt` | 纯文本 | ipset、hosts、脚本 |

### 使用方法

#### Xray

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "ext:abuse-geoip.dat:category-sinkhole",
          "ext:abuse-geoip.dat:category-malware-c2",
          "ext:abuse-geoip.dat:category-spam",
          "ext:abuse-geoip.dat:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "ext:abuse-geosite.dat:category-malware-c2",
          "ext:abuse-geosite.dat:category-phishing"
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

将 `abuse-geoip.dat` 和 `abuse-geosite.dat` 放入 Xray 资源目录（默认：`/usr/local/share/xray/`）。

#### Remnawave/Remnanode (Docker)

1. 创建资源目录并下载文件：

```bash
mkdir -p /opt/remnanode/xray/share

curl -sLo /opt/remnanode/xray/share/abuse-geoip.dat \
  https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geoip.dat

curl -sLo /opt/remnanode/xray/share/abuse-geosite.dat \
  https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geosite.dat
```

2. 在 `docker-compose.yml` 中挂载文件（remnanode 服务）：

```yaml
volumes:
  - /opt/remnanode/xray/share/abuse-geoip.dat:/usr/local/bin/abuse-geoip.dat:ro
  - /opt/remnanode/xray/share/abuse-geosite.dat:/usr/local/bin/abuse-geosite.dat:ro
```

3. 在 Xray 配置中添加路由规则（通过 Remnawave 面板或配置文件）：

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "ext:abuse-geoip.dat:category-sinkhole",
          "ext:abuse-geoip.dat:category-malware-c2",
          "ext:abuse-geoip.dat:category-spam",
          "ext:abuse-geoip.dat:category-brute-force"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "ext:abuse-geosite.dat:category-malware-c2",
          "ext:abuse-geosite.dat:category-phishing"
        ],
        "outboundTag": "block"
      }
    ]
  }
}
```

4. 自动更新（可选）— 添加到 crontab：

```bash
0 4 * * * curl -sLo /opt/remnanode/xray/share/abuse-geoip.dat https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geoip.dat && curl -sLo /opt/remnanode/xray/share/abuse-geosite.dat https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-geosite.dat && docker restart remnanode
```

#### sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "malware-c2-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-category-malware-c2-ip.srs",
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
curl -sL https://github.com/velvet-rnd/abuse-geodata/releases/latest/download/abuse-category-spam-ip.txt \
  | grep -v '^#' | xargs -I{} ipset add abuse-block {}

iptables -I FORWARD -m set --match-set abuse-block dst -j DROP
```

### 类别

| 类别 | 类型 | 说明 | 标记 |
|:-----|:-----|:-----|:-----|
| `category-sinkhole` | IP | 安全研究人员运营的已知 sinkhole 服务器 | – |
| `category-sinkhole-domain` | Domain | CERT.PL 接管的 sinkhole 域名 | 大型 |
| `category-malware-c2` | IP + Domain | 恶意软件 C2 服务器（僵尸网络、勒索软件、木马） | – |
| `category-phishing` | Domain | 钓鱼域名 | 高波动 |
| `category-spam` | IP | Spamhaus DROP/EDROP — 被劫持的 IP 段 | – |
| `category-tor-exit` | IP | Tor 出口节点 | 争议性 |
| `category-brute-force` | IP | 暴力破解攻击源 IP | 高波动 |
| `category-torrent` | Domain | 盗版种子站点（已排除合法站点） | 争议性、大型 |
| `category-torrent-legal` | Domain | 合法种子服务（Linux 发行版、归档站、FOSS） | – |
| `category-torrent-announce` | IP + Domain | BitTorrent Tracker Announce 服务器 | 争议性 |
| `category-dga` | Domain | 恶意软件 DGA 生成域名 | 高误报、大型 |

#### 标记说明

| 标记 | 含义 |
|:-----|:-----|
| `high_false_positive` | 可能误拦合法流量，部署前请审查。 |
| `high_volatility` | 列表变化频繁，IP 可能被重新分配给合法用户。 |
| `controversial` | 根据使用场景，封锁存在合理的反对意见。 |
| `large_dataset` | 条目数量大，可能影响路由性能。 |

#### 聚合包

- **`category-bundle-strict-*`** — 仅包含无 `high_false_positive` 和 `large_dataset` 标记的类别。适用于大多数部署。
- **`category-bundle-full-*`** — 所有类别，包括 DGA 等高噪声数据集。

### 数据源

| 数据源 | URL |
|:-------|:----|
| Feodo Tracker (abuse.ch) | https://feodotracker.abuse.ch |
| URLhaus (abuse.ch) | https://urlhaus.abuse.ch |
| ThreatFox full export (abuse.ch) | https://threatfox.abuse.ch |
| Emerging Threats | https://rules.emergingthreats.net |
| C2IntelFeeds | https://github.com/drb-ra/C2IntelFeeds |
| Threatview.io | https://threatview.io |
| Disconnect.me | https://disconnect.me |
| CyberHost Malware | https://cyberhost.uk |
| ShadowWhisperer | https://github.com/ShadowWhisperer/BlockLists |
| Spamhaus DROP/EDROP | https://www.spamhaus.org/drop/ |
| Tor Project | https://check.torproject.org/torbulkexitlist |
| blocklist.de | https://www.blocklist.de |
| OpenPhish | https://openphish.com |
| brakmic/Sinkholes | https://github.com/brakmic/Sinkholes |
| CERT.PL Sinkhole | https://hole.cert.pl |
| Bambenek DGA feed | https://bambenekconsulting.com |
| blocklistproject Torrent | https://github.com/blocklistproject/Lists |
| hagezi Anti-Piracy | https://github.com/hagezi/dns-blocklists |
| ngosang Trackers | https://github.com/ngosang/trackerslist |

### 测试

每次构建运行 `scripts/test.py` 验证所有输出文件：

- `.dat` 文件存在且达到最小预期大小
- `.db`（MMDB）具有有效的 MaxMind 元数据结构
- `.srs` 文件可被 sing-box 成功反编译
- `.txt` 文件仅包含有效的 IP/域名
- 每个源类别都有对应的输出文件
- txt/srs 条目数量一致

```bash
# 测试当前构建输出
python scripts/test.py

# 测试下载到其他目录的发布版本
python scripts/test.py /path/to/release-dir
```

发布目录需具有以下结构：`output/`、`output/srs/`、`output/txt/`、`sources/`，以及可选的 `tools/sing-box`。

### 更新计划

通过 GitHub Actions 每天 **03:00 UTC** 自动重新构建。

### Telegram 机器人

订阅 [@abuse_geodata_bot](https://t.me/abuse_geodata_bot) 以获取新版本通知，包含各类别统计信息和与上次构建的差异。

---

## Contributing

PRs welcome. To add a new source – добавь запись в соответствующий `sources/category-*.yml` или создай новый файл по образцу существующих.
