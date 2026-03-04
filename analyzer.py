# analyzer.py
import re
import sys
from collections import Counter
from rich import print
from rich.table import Table

# -----------------------------
# Regex pattern for Apache/Nginx logs
# -----------------------------
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s.*?'
    r'\[(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s[+\-]\d{4}\]\s'
    r'"(?P<method>GET|POST|PUT|DELETE)\s(?P<endpoint>.*?)\sHTTP/.*?"\s'
    r'(?P<status>\d{3})'
)

# -----------------------------
# Stream and analyze logs line by line
# -----------------------------
def stream_analyze(file_path):
    total_requests = 0
    status_counts = Counter()
    ip_counts = Counter()
    consecutive_500 = 0
    max_500_spike = 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                match = LOG_PATTERN.search(line)
                if match:
                    data = match.groupdict()
                    total_requests += 1
                    status = data['status']
                    ip = data['ip']

                    status_counts[status] += 1
                    ip_counts[ip] += 1

                    # Detect consecutive 500 error spikes
                    if status == '500':
                        consecutive_500 += 1
                        if consecutive_500 > max_500_spike:
                            max_500_spike = consecutive_500
                    else:
                        consecutive_500 = 0

    except FileNotFoundError:
        print("[red]Error: File not found[/red]")
        sys.exit(1)
    except Exception as e:
        print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)

    # -----------------------------
    # CSV export for GB logs
    # -----------------------------
    try:
        with open("analysis_output.csv", "w") as csvfile:
            csvfile.write("Metric,Value\n")
            csvfile.write(f"Total Requests,{total_requests}\n")
            for status, count in status_counts.items():
                csvfile.write(f"Status {status},{count}\n")
            for ip, count in ip_counts.most_common(5):
                csvfile.write(f"Top IP {ip},{count}\n")
            csvfile.write(f"Max Consecutive 500 Errors,{max_500_spike}\n")
    except Exception as e:
        print(f"[red]Failed to write CSV: {e}[/red]")

    return total_requests, status_counts, ip_counts, max_500_spike

# -----------------------------
# Print summary in terminal
# -----------------------------
def print_summary(total_requests, status_counts, ip_counts, max_500_spike):
    table = Table(title="Log Analysis Summary (Streaming)")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Total Requests", str(total_requests))

    for status, count in status_counts.items():
        table.add_row(f"Status {status}", str(count))

    top_ips = ip_counts.most_common(5)
    for ip, count in top_ips:
        table.add_row(f"Top IP {ip}", str(count))

    table.add_row("Max Consecutive 500 Errors", str(max_500_spike))

    print(table)

# -----------------------------
# Main entry
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[red]Usage: python analyzer.py logs/sample.log[/red]")
        sys.exit(1)

    file_path = sys.argv[1]
    total_requests, status_counts, ip_counts, max_500_spike = stream_analyze(file_path)
    print_summary(total_requests, status_counts, ip_counts, max_500_spike)