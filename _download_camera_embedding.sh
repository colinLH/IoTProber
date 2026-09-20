#!/bin/bash
# Parallel ranged download with priority: chunks 0-1 first (demo subset), then the rest.
set -u
URL="https://huggingface.co/datasets/IoTProber/raw_dataset/resolve/main/platform_data/rag/embedding_local/ipraw_CAMERA_embedding.csv"
OUT_DIR="platform_data/csv/local/1/embedding_local"
TMP_DIR="/tmp/camera_emb_chunks"
mkdir -p "$TMP_DIR" "$OUT_DIR"

SIZE=$(curl -sIL "$URL" | grep -i '^content-length:' | tail -1 | tr -dc '0-9')
if [ -z "$SIZE" ] || [ "$SIZE" -lt 1000000000 ]; then
  echo "FATAL: could not resolve file size (got: '$SIZE')"; exit 1
fi
echo "total size: $SIZE bytes ($(numfmt --to=iec $SIZE))"

N=16
CHUNK=$(( (SIZE + N - 1) / N ))

dl_chunk() {
  local i=$1 start=$2 end=$3
  local f="$TMP_DIR/chunk_$(printf '%02d' $i)"
  local want=$((end - start + 1))
  for attempt in $(seq 1 40); do
    local have=0
    [ -f "$f" ] && have=$(stat -c %s "$f")
    if [ "$have" -eq "$want" ]; then return 0; fi
    if [ "$have" -gt "$want" ]; then rm -f "$f"; have=0; fi
    curl -sL --speed-time 45 --speed-limit 50000 \
         -r $((start + have))-${end} "$URL" >> "$f" || true
  done
  have=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$have" -eq "$want" ] || { echo "chunk $i FAILED ($have/$want)"; return 1; }
}

# Phase 1: chunks 0-1 (demo subset) in parallel, wait
P1=()
for i in 0 1; do
  START=$((i * CHUNK)); END=$(( (i+1) * CHUNK - 1 ))
  dl_chunk $i $START $END & P1+=($!)
done
for p in "${P1[@]}"; do wait $p; done
echo "PHASE1_DONE chunks 0-1"
ls -la "$TMP_DIR"/chunk_00 "$TMP_DIR"/chunk_01

# Phase 2: remaining chunks
P2=()
for i in $(seq 2 $((N-1))); do
  START=$((i * CHUNK)); END=$(( (i+1) * CHUNK - 1 ))
  [ $END -ge $SIZE ] && END=$((SIZE - 1))
  dl_chunk $i $START $END & P2+=($!)
done
FAIL=0
for p in "${P2[@]}"; do wait $p || FAIL=1; done
[ $FAIL -eq 1 ] && { echo "some phase-2 chunks failed"; exit 1; }

cat $(for i in $(seq 0 $((N-1))); do printf "$TMP_DIR/chunk_%02d " $i; done) > "$OUT_DIR/ipraw_CAMERA_embedding.csv"
FINAL=$(stat -c %s "$OUT_DIR/ipraw_CAMERA_embedding.csv")
echo "assembled: $FINAL bytes"
if [ "$FINAL" -eq "$SIZE" ]; then
  rm -rf "$TMP_DIR"; echo "DOWNLOAD OK"
else
  echo "SIZE MISMATCH: $FINAL != $SIZE"; exit 1
fi
