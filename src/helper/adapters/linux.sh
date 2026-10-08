# Fixed collector. Only the Rust builder supplies the three strictly validated literals above.
set -u
read_cpu() {
    awk '/^cpu / { total=0; for(i=2;i<=NF;i++) total+=$i; printf "%.0f %.0f\n", $5, total; exit }' /proc/stat 2>/dev/null || true
}
read_interface() {
    if [ -n "$interface" ]; then
        cat "/sys/class/net/$interface/statistics/rx_bytes" "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null | paste -sd' ' -
    fi
}
before_ms=$(date +%s%3N 2>/dev/null || true)
cpu_before=$(read_cpu)
interface_before=$(read_interface)
memory=$(awk '/^MemTotal:/ {total=$2} /^MemAvailable:/ {available=$2} END {if(total>0 && available>=0) print total-available, total}' /proc/meminfo 2>/dev/null || true)
commit=$(awk '/^Committed_AS:/ {used=$2} /^CommitLimit:/ {total=$2} END {if(total>0 && used>=0) print used, total}' /proc/meminfo 2>/dev/null || true)
disk=$(df -Pk "$mount" 2>/dev/null | awk 'NR==2 && $2>0 {print $3, $2}' || true)
process_count=''
if processes=$(ps -e -o pid= 2>/dev/null); then
    process_count=$(printf '%s\n' "$processes" | awk 'NF {count++} END {print count+0}')
fi
service_state=''
if [ -n "$service" ]; then
    if service_info=$(systemctl show --property=LoadState --property=ActiveState "$service" 2>/dev/null); then
        load_state=$(printf '%s\n' "$service_info" | awk -F= '$1=="LoadState" {print $2}')
        if [ "$load_state" = 'loaded' ]; then
            service_state=$(printf '%s\n' "$service_info" | awk -F= '$1=="ActiveState" {print $2}')
        fi
    fi
fi
sleep 0.25
after_ms=$(date +%s%3N 2>/dev/null || true)
cpu_after=$(read_cpu)
interface_after=$(read_interface)
printf 'schema=1\nstart_ms=%s\nend_ms=%s\n' "$before_ms" "$after_ms"
printf 'cpu_before=%s\ncpu_after=%s\ninterface_before=%s\ninterface_after=%s\n' "$cpu_before" "$cpu_after" "$interface_before" "$interface_after"
printf 'memory=%s\ndisk=%s\nprocess_count=%s\nservice_state=%s\n' "$memory" "$disk" "$process_count" "$service_state"
printf 'commit=%s\nerror_count=\nevents_truncated=false\n' "$commit"
