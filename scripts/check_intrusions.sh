#!/usr/bin/env bash
#
#  check_intrusions.sh
#  ---------------------
#  A lightweight Bash script that runs on a Windows machine (via WSL or Git‑Bash)
#  to gather basic intrusion‑related information:
#    • Running processes
#    • Running services
#    • Open TCP ports
#    • Scheduled tasks
#    • Registry Run keys
#  The output is appended to a log file with a timestamp.
#
#  Usage:
#    ./scripts/check_intrusions.sh
#
#  Requirements:
#    * PowerShell (available on Windows by default)
#    * netstat (available via Windows command line)
#    * WSL or Git‑Bash for Bash execution
#
#  Author: GreyNOC
#  Date: 2026-10-22
#

# Ensure the log directory exists
mkdir -p logs

# Timestamp for the log entry
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Log file path
LOGFILE="logs/intrusions.log"

# Append header
printf "\n===== Intrusion Check: %s =====\n" "$TIMESTAMP" >> "$LOGFILE"

# 1. Running processes
printf "\n-- Running Processes --\n" >> "$LOGFILE"
powershell -Command "Get-Process | Select-Object -Property Id,ProcessName,CPU,WorkingSet | Format-Table" >> "$LOGFILE"

# 2. Running services
printf "\n-- Running Services --\n" >> "$LOGFILE"
powershell -Command "Get-Service | Where-Object { \$_.Status -eq 'Running' } | Select-Object -Property Name,Status,StartType | Format-Table" >> "$LOGFILE"

# 3. Open TCP ports
printf "\n-- Open TCP Ports --\n" >> "$LOGFILE"
netstat -an | grep LISTENING >> "$LOGFILE"

# 4. Scheduled tasks
printf "\n-- Scheduled Tasks --\n" >> "$LOGFILE"
powershell -Command "Get-ScheduledTask | Where-Object { \$_.State -eq 'Ready' } | Select-Object -Property TaskName,State,LastRunTime | Format-Table" >> "$LOGFILE"

# 5. Registry Run keys
printf "\n-- Registry Run Keys --\n" >> "$LOGFILE"
powershell -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Select-Object -Property PSPath,PSChildName,PSChildType | Format-Table" >> "$LOGFILE"

# End of script
printf "\n===== End of Check =====\n" >> "$LOGFILE"

# Make the script executable (if not already)
chmod +x scripts/check_intrusions.sh

# Notify completion
echo "Intrusion check completed. Log written to $LOGFILE"
