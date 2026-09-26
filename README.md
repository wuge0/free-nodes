# free-nodes

用 **GitHub Actions** 定时测节点 —— 从多个公共源抓取候选节点，起一个真实的 mihomo 进程逐个实测，**只保留活跃节点**，再生成可直接订阅的 clash yaml。

产出的是"此刻真的能连上"的节点，不是源列表的搬运。

## 订阅地址

```
# 全部活跃节点（按 GitHub 可达优先排序）
https://raw.githubusercontent.com/wuge0/free-nodes/main/output/clash.yaml

# 仅保留实测能访问 GitHub 的节点（推荐，节点少但每个都能用）
https://raw.githubusercontent.com/wuge0/free-nodes/main/output/github.yaml
```

`output/status.json` 记录本次采集统计（候选数 / 活跃数 / GitHub 可达数 / 协议分布 / 最快的 20 个节点）。

## 怎么测的

两轮实测，避免"节点活着但访问不了 GitHub"这个坑：

| 轮次 | 目的 | 探测目标 | 并发 | 超时 |
|---|---|---|---|---|
| **L1** | 节点是否存活 | `http://www.gstatic.com/generate_204` | 64 | 5s |
| **L2** | 节点能否访问 GitHub | `https://api.github.com/zen` | 16 | 8s |

L1 遍历全部候选（默认上限 3500），L2 只测 L1 里最快的 60 个 —— 全量测 GitHub 太慢且没必要。
最终排序：**GitHub 实测通的排前面**（按 L2 延迟），其余活跃节点按 L1 延迟排在后面。

为什么不用 url-test 一把梭：`url-test` 只反映节点存活，经常选出一个活着但访问不了 GitHub 的节点。

## 定时

每 3 小时跑一次（`cron: 17 */3 * * *`），也可在 Actions 页面手动 `Run workflow`。
单次约 3–6 分钟，主要耗时在 L1 并发探测。

只在确实产出有效节点时才会提交，不会把能用的订阅刷成空的。

## 本地跑

```bash
pip install -r requirements.txt
python harvest.py
```

可调环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `MAX_NODES` | `3500` | 候选节点上限 |
| `PER_SRC` | `1500` | 单个源最多取多少个 |
| `L1_C` / `L1_T` | `64` / `5000` | L1 并发 / 超时(ms) |
| `L2_KEEP` / `L2_C` / `L2_T` | `60` / `16` / `8000` | L2 精测数量 / 并发 / 超时 |
| `SMOKE` / `GH` | gstatic / api.github.com | 两轮探测目标 |
| `LIMIT_SRC` | `0` | >0 时只取前 N 个源，方便本地快速冒烟 |

脚本会自己下载 mihomo `v1.19.31` 到 `/tmp/harvest`，并自动挑空闲端口，不占用已有服务。

## 文件

```
harvest.py                    采集 + 实测 + 生成
sources.txt                   节点源列表（一行一个，# 注释）
requirements.txt              PyYAML
.github/workflows/harvest.yml Actions 定时流水线
output/clash.yaml             全部活跃节点
output/github.yaml            实测可访问 GitHub 的节点
output/status.json            本次统计
```

## 加自己的源

往 `sources.txt` 里加一行 URL 即可，支持 clash yaml（含 `proxies:`）、明文 URI 列表、base64 订阅三种形态。
单个源挂了会自动跳过，不影响整体。

节点名里含"剩余流量/到期/官网/付费/电报"等广告词的会被过滤掉。

## 协议支持

vmess、vless（含 reality）、ss（SIP002，带 plugin 的跳过）、trojan、hysteria2、tuic。
