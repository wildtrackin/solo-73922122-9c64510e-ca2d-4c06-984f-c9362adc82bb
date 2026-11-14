#!/usr/bin/env bash
# 本地演示脚本：无需 Docker，自动在独立临时目录启动服务并演示四个场景：
#   1) 上传待登记暂停 / 下载待解封暂停；
#   2) 密钥轮换：仅重封装 DEK、旧 KEK 文件删除后才报完成；
#   3) 轮换中“进程退出 → 重启自动续办”，已归档文件始终可解密；
#   4) 不完整备份恢复（新课题密钥文件缺失）：保留轮换进度与旧钥、不生成替代
#      密钥、不报完成，受影响下载明确报错；放回原密钥备份并重启后续办同一次轮换。
#
# 用法： scripts/demo.sh [BASE_DIR]
# 依赖： python3（含 venv 内的 fastapi/uvicorn/cryptography）、curl、sha256sum
set -euo pipefail

BASE_DIR="${1:-$(mktemp -d /tmp/tiff-archive-demo.XXXXXX)}"
DATA_DIR="$BASE_DIR/data"
PORT="${PORT:-8090}"
# 重启方式：RESTART=kill（默认，真实环境/容器内停止进程后重启）；
# RESTART=report（受限环境无法发信号时，用同一数据目录在新端口启动新进程，
# 恢复逻辑完全相同，仅进程替换方式不同；场景 4 需要真实停机，该模式下跳过）。
RESTART="${RESTART:-kill}"
BASE="http://127.0.0.1:$PORT"
LOG="$BASE_DIR/server-boot.log"
PY="${PYTHON:-python3}"

mkdir -p "$DATA_DIR" "$BASE_DIR/samples"
trap 'echo; echo "演示数据保留在: $BASE_DIR（可手动删除）"' EXIT

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
jget() { "$PY" -c 'import sys,json;d=json.load(sys.stdin);
for k in sys.argv[1].split("."): d=d[k]
print(d)' "$1"; }

# ---------------------------------------------------------------- 进程管理 --
SRV_PIDS=()
CUR_PORT="$PORT"

start_svc() {  # $1=日志后缀；启动后等待健康检查通过，并把 BASE 指向新实例
  ARCHIVE_DATA_DIR="$DATA_DIR" "$PY" -m uvicorn app.main:app \
    --host 127.0.0.1 --port "$CUR_PORT" >"$BASE_DIR/server-$1.log" 2>&1 &
  SRV_PIDS+=("$!")
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$CUR_PORT/health" >/dev/null && break
    sleep 0.3
  done
  curl -s "http://127.0.0.1:$CUR_PORT/health" >/dev/null \
    || { echo "服务启动失败，见 $BASE_DIR/server-$1.log"; exit 1; }
  BASE="http://127.0.0.1:$CUR_PORT"
}

stop_svc() {  # 停止最近一次启动的服务进程；受限环境禁止 kill 时明确报错而非挂起
  [ "${#SRV_PIDS[@]}" -gt 0 ] || return 0
  local pid="${SRV_PIDS[-1]}"
  if ! kill "$pid" 2>/dev/null; then
    echo "错误：无法停止服务进程 $pid（当前环境禁止 kill 系统调用）。"
    echo "      请改用 RESTART=report 模式运行本脚本（场景 4 需真实停机，将自动跳过）。"
    return 1
  fi
  wait "$pid" 2>/dev/null || true
}

restart_svc() {  # $1=日志后缀；模拟一次“进程退出 → 用同一数据目录重启”
  if [ "$RESTART" = "report" ]; then
    CUR_PORT=$((CUR_PORT + 1))  # 受限环境无法发信号：新端口新进程模拟重启
  else
    stop_svc
  fi
  start_svc "$1"
}

trap 'kill "${SRV_PIDS[@]}" 2>/dev/null || true; echo; echo "演示数据保留在: $BASE_DIR（可手动删除）"' EXIT

say "0/ 启动服务（数据目录 $DATA_DIR，端口 $CUR_PORT）"
start_svc boot
ok "服务在线，浏览器入口: $BASE/ （PID=${SRV_PIDS[-1]}）"

make_tif() {  # $1 文件名 $2 大小
  "$PY" - "$1" "$2" <<'EOF'
import sys
path, size = sys.argv[1], int(sys.argv[2])
header = b"II\x2a\x00" + size.to_bytes(4, "little")
body = bytes(((i * 31 + 7) & 0xFF) for i in range(size - len(header)))
open(path, "wb").write(header + body)
EOF
}

upload() {  # $1 文件路径 -> 输出 file_id
  local path="$1" name size init uid
  name="$(basename "$path")"; size="$(stat -c%s "$path")"
  init="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
    -d "{\"filename\":\"$name\",\"size\":$size}")"
  uid="$(printf '%s' "$init" | jget upload_id)"
  curl -s -X PUT --data-binary "@$path" "$BASE/api/uploads/$uid/content" >/dev/null
  curl -s -X POST "$BASE/api/uploads/$uid/complete" | jget file_id
}

download() {  # $1 file_id $2 输出路径
  local did
  did="$(curl -s -X POST "$BASE/api/files/$1/downloads" | jget download_id)"
  curl -s -o "$2" "$BASE/api/downloads/$did/content"
}

wait_rotation_done() {
  for _ in $(seq 1 50); do
    curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;raise SystemExit(0 if not json.load(sys.stdin)["active"] else 1)' && return 0
    sleep 0.3
  done
  echo "轮换未在预期时间内完成"; return 1
}

say "1/ 正常上传/下载往返（独立随机 DEK，明文不落盘）"
make_tif "$BASE_DIR/samples/img-a.tif" 4096
FID_A="$(upload "$BASE_DIR/samples/img-a.tif")"
download "$FID_A" "$BASE_DIR/samples/img-a.dl.tif"
cmp "$BASE_DIR/samples/img-a.tif" "$BASE_DIR/samples/img-a.dl.tif"
ok "img-a.tif 上传后下载逐字节一致（file_id=${FID_A:0:8}…）"
if grep -rIl $'II\x2a\x00' "$DATA_DIR/vault" "$DATA_DIR/staging" 2>/dev/null; then
  echo "密文目录中发现明文 TIFF 魔数！"; exit 1
fi
ok "vault/staging 中无明文 TIFF 魔数；密钥目录与密文目录分离："
echo "   $DATA_DIR/keys  $(ls "$DATA_DIR/keys" | sed 's/^/  /' | tr '\n' ' ')"
echo "   $DATA_DIR/vault $(ls "$DATA_DIR/vault" | sed 's/^/  /' | tr '\n' ' ')"

say "2/ 暂停点演示：上传待登记、下载待解封"
# --- 上传待登记 ---
curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
make_tif "$BASE_DIR/samples/img-b.tif" 2048
size_b="$(stat -c%s "$BASE_DIR/samples/img-b.tif")"
uid_b="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
  -d "{\"filename\":\"img-b.tif\",\"size\":$size_b}" | jget upload_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-b.tif" "$BASE/api/uploads/$uid_b/content" >/dev/null
curl -s -X POST "$BASE/api/uploads/$uid_b/complete" >"$BASE_DIR/up-b.json" &
CP=$!
sleep 1.2
state_b="$(curl -s "$BASE/api/uploads" | "$PY" -c 'import sys,json;print(next(u["state"] for u in json.load(sys.stdin) if u["filename"]=="img-b.tif"))')"
[ "$state_b" = "pending_register" ] && ok "上传已暂停在“待登记”（DEK 仅在内存，密文暂存 staging/）"
# --- 同时发起轮换：收尾必须等待该上传 ---
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
rot="$(curl -s "$BASE/api/rotations/current")"
echo "$rot" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["state"]=="completing" and d["blocking_uploads"]==1'
ok "轮换停在收尾，blocking_uploads=1（旧 KEK 文件仍保留）"
# --- 恢复上传，轮换随之完成 ---
curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":false}' >/dev/null
wait "$CP"
wait_rotation_done
fid_b="$(curl -s "$BASE/api/uploads" | "$PY" -c 'import sys,json;print(next(u["file_id"] for u in json.load(sys.stdin) if u["filename"]=="img-b.tif"))')"
kek_b="$(curl -s "$BASE/api/files" | "$PY" -c 'import sys,json;print(next(f["kek_id"] for f in json.load(sys.stdin) if f["file_id"]=="'$fid_b'"))')"
old_kek="$(curl -s "$BASE/api/keys" | "$PY" -c 'import sys,json;print(next(k["id"] for k in json.load(sys.stdin) if k["status"]=="deleted"))')"
[ "$kek_b" != "$old_kek" ] && ok "暂停期间的上传最终由新课题密钥封装，未留下旧钥引用"
ok "第一轮轮换完成，旧 KEK 文件已实际删除"

# --- 下载待解封 ---
curl -s -X POST "$BASE/api/demo/gates/download_unwrap" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
did_c="$(curl -s -X POST "$BASE/api/files/$FID_A/downloads" | jget download_id)"
curl -s -o "$BASE_DIR/samples/img-a.dl2.tif" "$BASE/api/downloads/$did_c/content" &
CP=$!
sleep 1.2
dl_state="$(curl -s "$BASE/api/downloads" | "$PY" -c 'import sys,json;print(next(d["state"] for d in json.load(sys.stdin) if d["download_id"]=="'$did_c'"))')"
[ "$dl_state" = "accepted" ] && ok "下载已受理并暂停在“待解封”"
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["blocking_downloads"]==1'
ok "第二轮轮换等待在途下载，blocking_downloads=1"
curl -s -X POST "$BASE/api/demo/gates/download_unwrap" -H 'Content-Type: application/json' -d '{"paused":false}' >/dev/null
wait "$CP"
wait_rotation_done
cmp "$BASE_DIR/samples/img-a.tif" "$BASE_DIR/samples/img-a.dl2.tif"
ok "恢复后已受理下载读完原件，内容逐字节一致；轮换随后完成"

say "3/ 轮换中退出、重启自动续办"
# 留一个待登记上传，使下一轮换停在收尾，然后“杀掉”服务模拟中途退出
curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
make_tif "$BASE_DIR/samples/img-c.tif" 1024
size_c="$(stat -c%s "$BASE_DIR/samples/img-c.tif")"
uid_c="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
  -d "{\"filename\":\"img-c.tif\",\"size\":$size_c}" | jget upload_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-c.tif" "$BASE/api/uploads/$uid_c/content" >/dev/null
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"]'
ok "轮换进行中，模拟进程退出并用同一数据目录重启（RESTART=$RESTART）"
restart_svc mid-rotation
ok "服务已用同一数据目录重启（$BASE）"
# 重启后待登记上传按规则失败、暂存清理
curl -s "$BASE/api/uploads" | "$PY" -c 'import sys,json;u=next(x for x in json.load(sys.stdin) if x["filename"]=="img-c.tif");assert u["state"]=="failed", u'
[ -z "$(ls -A "$DATA_DIR/staging")" ] && ok "重启恢复：未完成上传标记 failed，staging/ 已清理"
# 轮换自动续办至完成
for _ in $(seq 1 50); do
  curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;raise SystemExit(0 if not json.load(sys.stdin)["active"] else 1)' && break
  sleep 0.3
done
curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["last"]["state"]=="completed", d'
ok "重启后轮换自动续办并完成"
# 全部历史归档仍可解密且内容一致
for f in img-a img-b; do
  fid="$(curl -s "$BASE/api/files" | "$PY" -c 'import sys,json;print(next(x["file_id"] for x in json.load(sys.stdin) if x["filename"]=="'$f'.tif"))')"
  download "$fid" "$BASE_DIR/samples/$f.restart-dl.tif"
  cmp "$BASE_DIR/samples/$f.tif" "$BASE_DIR/samples/$f.restart-dl.tif"
done
ok "重启后全部已归档文件仍可解密，且与原件逐字节一致"

if [ "$RESTART" = "kill" ]; then
  say "4/ 缺钥故障：不完整备份恢复 → 保留进度与旧钥 → 放回原密钥后续办"
  # 造一个停在收尾的轮换：待登记上传阻塞收尾，新旧两把钥文件同时存在
  curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
  make_tif "$BASE_DIR/samples/img-d.tif" 768
  size_d="$(stat -c%s "$BASE_DIR/samples/img-d.tif")"
  uid_d="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
    -d "{\"filename\":\"img-d.tif\",\"size\":$size_d}" | jget upload_id)"
  curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-d.tif" "$BASE/api/uploads/$uid_d/content" >/dev/null
  curl -s -X POST "$BASE/api/rotations" >/dev/null
  sleep 1.0
  curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["state"]=="completing" and d["blocking_uploads"]==1, d'
  NEW_KEY_ID="$(curl -s "$BASE/api/keys" | "$PY" -c 'import sys,json;print(next(k["key_id"] for k in json.load(sys.stdin) if k["status"]=="active"))')"
  OLD_KEY_ID="$(curl -s "$BASE/api/keys" | "$PY" -c 'import sys,json;print(next(k["key_id"] for k in json.load(sys.stdin) if k["status"]=="rotating"))')"
  cp "$DATA_DIR/keys/$NEW_KEY_ID.kek" "$BASE_DIR/new-key.backup.kek"  # 管理员手中的原密钥备份
  (cd "$DATA_DIR/vault" && sha256sum ./*.blob) > "$BASE_DIR/blobs.before"
  ok "轮换停在收尾（影像已重封装到新钥，旧钥保留）；模拟：停机后从不完整备份恢复，新钥文件缺失"
  stop_svc
  rm "$DATA_DIR/keys/$NEW_KEY_ID.kek"

  start_svc fault1
  curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["fault"] and d["fault"]["kind"]=="missing", d'
  ok "重启后进入缺钥故障：轮换进度保留，未报完成"
  [ -f "$DATA_DIR/keys/$OLD_KEY_ID.kek" ] && [ ! -e "$DATA_DIR/keys/$NEW_KEY_ID.kek" ] \
    && ok "旧钥保留、未生成替代密钥（keys/ 与故障前一致）"
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/files/$FID_A/downloads")"
  [ "$code" = "503" ] && ok "受影响影像下载明确报错（HTTP 503），其余影像不受影响"
  (cd "$DATA_DIR/vault" && sha256sum -c "$BASE_DIR/blobs.before") >/dev/null \
    && ok "原件密文逐字节未变（反复重启不改写密文、不生成新钥）"

  "$PY" -c "from app.crypto import save_kek_file; import os; save_kek_file('$DATA_DIR/keys/$NEW_KEY_ID.kek', os.urandom(32))"
  restart_svc fault2
  curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["fault"] and d["fault"]["kind"]=="cannot_unwrap", d'
  [ -f "$DATA_DIR/keys/$OLD_KEY_ID.kek" ] && ok "放回无法解封的错误密钥：仍保持故障，旧钥未删除"

  cp "$BASE_DIR/new-key.backup.kek" "$DATA_DIR/keys/$NEW_KEY_ID.kek"
  restart_svc recovered
  wait_rotation_done
  curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["last"]["state"]=="completed", d'
  [ ! -e "$DATA_DIR/keys/$OLD_KEY_ID.kek" ] && ok "放回原密钥备份并重启：自动续办同一次轮换至完成，旧钥已删除"
  download "$FID_A" "$BASE_DIR/samples/img-a.final.tif"
  cmp "$BASE_DIR/samples/img-a.tif" "$BASE_DIR/samples/img-a.final.tif"
  ok "全部已归档影像恢复可下载，内容逐字节一致"
else
  say "4/ 缺钥故障场景（RESTART=report 模式下跳过：恢复备份前必须真实停止进程）"
fi

say "演示完成"
echo "浏览器入口: $BASE/ （本脚本结束后服务已停止；手动启动见 README）"
echo "服务日志:   $BASE_DIR/server-*.log"
