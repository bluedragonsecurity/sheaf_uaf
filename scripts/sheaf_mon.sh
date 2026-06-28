while true; do
  echo "=== $(date +%H:%M:%S.%3N) ==="
  sudo drgn sheaf.py
  sleep 0.5
done | tee /tmp/sheaf.log
