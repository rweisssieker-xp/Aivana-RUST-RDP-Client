# Fixed, read-only Linux collector. The validated prelude supplies selectors as data.
read_cpu() {
    awk '/^cpu / { total=0; for(i=2;i<=NF;i++) total+=$i; printf "%.0f %.0f\n", $5, total; exit }' /proc/stat 2>/dev/null || true
}
read_interface() {
    if [ -n "$interface" ]; then
        rx=$(cat "/sys/class/net/$interface/statistics/rx_bytes" 2>/dev/null) || return
        tx=$(cat "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null) || return
        printf '%s %s\n' "$rx" "$tx"
    fi
}
read_interface_extra() {
    if [ -n "$interface" ]; then
        for counter in rx_errors tx_errors rx_dropped tx_dropped; do
            cat "/sys/class/net/$interface/statistics/$counter" 2>/dev/null || return
        done | paste -sd' ' -
    fi
}
read_tcp() {
    awk '$1=="Tcp:" { if (!seen++) { for(i=2;i<=NF;i++) key[i]=$i } else {
        for(i=2;i<=NF;i++) value[key[i]]=$i;
        if(value["CurrEstab"] ~ /^[0-9]+$/ && value["RetransSegs"] ~ /^[0-9]+$/)
            print value["CurrEstab"], value["RetransSegs"];
        exit
    }}' /proc/net/snmp 2>/dev/null || true
}
before_ms=$(date +%s%3N 2>/dev/null || true)
cpu_before=$(read_cpu)
interface_before=$(read_interface)
tcp_before=$(read_tcp)
memory=$(awk '/^MemTotal:/ {total=$2} /^MemAvailable:/ {available=$2} END {if(total>0 && available>=0) print total-available, total}' /proc/meminfo 2>/dev/null || true)
commit=$(awk '/^Committed_AS:/ {used=$2} /^CommitLimit:/ {total=$2} END {if(total>0 && used>=0) print used, total}' /proc/meminfo 2>/dev/null || true)
disk=$(df -Pk "$mount" 2>/dev/null | awk 'NR==2 {for (i=1; i<=NF-3; i++) if ($i ~ /^[0-9]+$/ && $(i+1) ~ /^[0-9]+$/ && $(i+2) ~ /^[0-9]+$/ && $(i+3) ~ /^[0-9]+%$/ && $i>0) {print $(i+1), $i; exit}}' || true)
process_count=$(ps -e -o pid= 2>/dev/null | awk 'NF {count++} END {if(NR>0) print count+0}' || true)
processes=$(ps -eo comm=,rss=,time= --sort=-rss 2>/dev/null | awk '
    NR<=5 && $2 ~ /^[0-9]+$/ {
        name=$1; gsub(/[^A-Za-z0-9_.-]/,"_",name); name=substr(name,1,64);
        parts=split($3,t,":"); seconds=0; for(i=1;i<=parts;i++) seconds=seconds*60+t[i];
        printf "%s,%d,%d;",name,$2*1024,seconds
    }' || true)
os_version=$(awk -F= '$1=="VERSION_ID" {gsub(/"/,"",$2); gsub(/[^A-Za-z0-9._-]/,"",$2); print substr($2,1,48); exit}' /etc/os-release 2>/dev/null || true)
os_name=$(awk 'NR==1 {gsub(/[^A-Za-z0-9_.-]/,"",$0); print substr($0,1,255); exit}' /proc/sys/kernel/hostname 2>/dev/null || true)
uptime_seconds=$(awk 'NR==1 && $1>=0 {printf "%.0f",$1; exit}' /proc/uptime 2>/dev/null || true)
load_one=$(awk 'NR==1 && $1>=0 {print $1; exit}' /proc/loadavg 2>/dev/null || true)
listening_tcp=$(awk 'FNR>1 && $4=="0A" {count++} END {if(NR>0) print count+0}' /proc/net/tcp /proc/net/tcp6 2>/dev/null || true)
service_state=''
service_dependencies=''
service_dependencies_truncated=false
if [ -n "$service" ]; then
    service_info=$(systemctl show --property=LoadState --property=ActiveState --property=Requires "$service" 2>/dev/null || true)
    load_state=$(printf '%s\n' "$service_info" | awk -F= '$1=="LoadState" {print $2}')
    if [ "$load_state" = 'loaded' ]; then
        service_state=$(printf '%s\n' "$service_info" | awk -F= '$1=="ActiveState" {print $2}')
        service_dependencies=$(printf '%s\n' "$service_info" | awk -F= '$1=="Requires" {n=split($2,a," "); for(i=1;i<=n && i<=16;i++) {gsub(/[^A-Za-z0-9_.@-]/,"_",a[i]); if(a[i]!="") printf "%s;",substr(a[i],1,80)}}')
        service_dependencies_truncated=$(printf '%s\n' "$service_info" | awk -F= '$1=="Requires" {if(split($2,a," ")>16) print "true"; else print "false"}')
        [ -n "$service_dependencies_truncated" ] || service_dependencies_truncated=false
        [ -n "$service_dependencies" ] || service_dependencies='-'
    fi
fi
sleep 0.25
after_ms=$(date +%s%3N 2>/dev/null || true)
cpu_after=$(read_cpu)
interface_after=$(read_interface)
interface_extra=$(read_interface_extra)
tcp_after=$(read_tcp)
printf 'schema=1\nstart_ms=%s\nend_ms=%s\ncpu_before=%s\ncpu_after=%s\ninterface_before=%s\ninterface_after=%s\nmemory=%s\ncommit=%s\ndisk=%s\nerror_count=\nevents_truncated=false\nevents_metadata_truncated=false\nprocess_count=%s\nservice_state=%s\nos_version=%s\nos_name=%s\nuptime_seconds=%s\nload_one=%s\nprocesses=%s\nservice_dependencies=%s\nservice_dependencies_truncated=%s\nevents=\ninterface_extra=%s\ntcp_before=%s\ntcp_after=%s\nlistening_tcp=%s\n' \
    "$before_ms" "$after_ms" "$cpu_before" "$cpu_after" "$interface_before" "$interface_after" \
    "$memory" "$commit" "$disk" "$process_count" "$service_state" "$os_version" "$os_name" \
    "$uptime_seconds" "$load_one" "$processes" "$service_dependencies" "$service_dependencies_truncated" "$interface_extra" \
    "$tcp_before" "$tcp_after" "$listening_tcp"
