# AnySentry Observer Linux 4.19 ARM64 热修复替换说明

本热修复只替换 `/opt/anysentry/observer/bin/a3s-observer-collector`。不要停止或
重启 ClickHouse 和 AnySentry API。

以下命令假定热修复目录上传到了：

```bash
export HOTFIX_DIR=/opt/shannon/anysentry/v0.1.0/anysentry-observer-linux-4.19-arm64-hotfix2
export PACKAGE_DIR=/opt/shannon/anysentry/v0.1.0/anysentry-security-suite-0.1.0-compat1-uos20-arm64
cd "$HOTFIX_DIR"
```

如果实际上传或解压路径不同，只修改上面两个变量。

## 1. 校验文件和 ABI

```bash
sha256sum --check SHA256SUMS
file a3s-observer-collector
./a3s-observer-collector --version
```

预期版本输出包含：

```text
backend=perf-kprobe-legacy
```

## 2. 不替换文件，先直接验证探针

当前主机的 Observer unit 已经不在 systemd 中，`reset-failed` 返回
`Unit ... not loaded` 是预期现象。先直接运行新 collector：

```bash
systemctl stop anysentry-observer.service 2>/dev/null || true

run_id=$$
heartbeat=/tmp/anysentry-observer-hotfix-$run_id.alive
stdout=/tmp/anysentry-observer-hotfix-$run_id.stdout
stderr=/tmp/anysentry-observer-hotfix-$run_id.stderr

A3S_OBSERVER_JSON=1 \
A3S_OBSERVER_FILES=1 \
A3S_OBSERVER_HEARTBEAT="$heartbeat" \
  "$HOTFIX_DIR/a3s-observer-collector" >"$stdout" 2>"$stderr" &
collector_pid=$!

for i in $(seq 1 15); do
  test -f "$heartbeat" && break
  kill -0 "$collector_pid" 2>/dev/null || break
  sleep 1
done

/bin/sh -c 'echo anysentry-observer-hotfix-smoke >/dev/null'
/usr/bin/env >/dev/null
sleep 3

if kill -0 "$collector_pid" 2>/dev/null; then
  kill -TERM "$collector_pid"
  wait "$collector_pid"
  collector_rc=$?
else
  wait "$collector_pid"
  collector_rc=$?
fi

echo "collector_exit_code=$collector_rc"
sed -n '1,160p' "$stderr"
sed -n '1,20p' "$stdout"
```

通过条件：

- collector 在主动发送 `TERM` 前没有退出；
- stderr 出现 `legacy Observer probes attached`；
- stderr 不再出现 `BPF_BTF_LOAD`、`BPF_PROG_LOAD` 或
  `no effective legacy probes attached`；
- stdout 至少包含 collector heartbeat，触发命令后应出现 exec 事件。

如果本步骤失败，不要替换正式文件，请把 stderr 全部发回开发机分析。

## 3. 备份并原子替换 collector

```bash
install -d -m 0755 /opt/anysentry/observer/bin
backup=/opt/anysentry/observer/bin/a3s-observer-collector.before-linux419-hotfix.$(date +%Y%m%d%H%M%S)
cp -a /opt/anysentry/observer/bin/a3s-observer-collector "$backup"
echo "backup=$backup"

install -o root -g root -m 0755 \
  "$HOTFIX_DIR/a3s-observer-collector" \
  /opt/anysentry/observer/bin/a3s-observer-collector.hotfix-new
mv -f \
  /opt/anysentry/observer/bin/a3s-observer-collector.hotfix-new \
  /opt/anysentry/observer/bin/a3s-observer-collector

/opt/anysentry/observer/bin/a3s-observer-collector --version
```

## 4. 恢复丢失的 systemd unit 并启动

先确认解压安装包中存在 Observer unit：

```bash
test -f "$PACKAGE_DIR/systemd/anysentry-observer.service"
```

恢复并启动：

```bash
install -o root -g root -m 0644 \
  "$PACKAGE_DIR/systemd/anysentry-observer.service" \
  /etc/systemd/system/anysentry-observer.service

systemctl daemon-reload
systemctl reset-failed anysentry-observer.service 2>/dev/null || true
systemctl enable --now anysentry-observer.service
sleep 8

systemctl status anysentry-observer.service --no-pager -l
journalctl -b -u anysentry-observer.service -n 160 --no-pager -o cat
```

必须看到 `Active: active (running)` 和 `legacy Observer probes attached`。

## 5. 端到端验证

```bash
/bin/sh -c 'echo anysentry-observer-end-to-end-smoke >/dev/null'
sleep 5

systemctl is-active anysentry-clickhouse.service
systemctl is-active anysentry.service
systemctl is-active anysentry-observer.service
curl -fsS http://127.0.0.1:8123/ping
curl -fsS http://127.0.0.1:29653/security-center/healthz
/opt/anysentry/verify.sh
```

三个 service 都应返回 `active`，ClickHouse 返回 `Ok.`，API health 返回
`status: ok`。API health 中 `events.total` 应在触发测试命令后增加。

## 回滚

默认选择最新的一份第 3 步备份；执行前检查打印的路径是否正确：

```bash
backup=$(ls -1t /opt/anysentry/observer/bin/a3s-observer-collector.before-linux419-hotfix.* 2>/dev/null | head -n 1)
export backup
echo "rollback_backup=$backup"

systemctl stop anysentry-observer.service 2>/dev/null || true
test -x "$backup"
install -o root -g root -m 0755 \
  "$backup" \
  /opt/anysentry/observer/bin/a3s-observer-collector.rollback-new
mv -f \
  /opt/anysentry/observer/bin/a3s-observer-collector.rollback-new \
  /opt/anysentry/observer/bin/a3s-observer-collector
systemctl daemon-reload
systemctl start anysentry-observer.service
systemctl status anysentry-observer.service --no-pager -l
```

旧 collector 在这台 Linux 4.19 主机上仍会发生原来的 eBPF 加载失败；回滚的
主要作用是恢复文件，而不是解决原始兼容性问题。如需保持 ClickHouse/API 可用并
停止重启循环，可执行：

```bash
systemctl disable --now anysentry-observer.service
```
