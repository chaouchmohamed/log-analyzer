import re
import sys
import pandas as pd
from collections import Counter
from rich import print
from rich.table import Table

# -----------------------------
# Regex pattern to parse Apache-style logs
# -----------------------------
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s.*?'  # IP address
    r'\[(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s[+\-]\d{4}\]\s'  # Timestamp
    r'"(?P<method>GET|POST|PUT|DELETE)\s(?P<endpoint>.*?)\sHTTP/.*?"\s'  # Method + Endpoint
    r'(?P<status>\d{3})'  # Status code
)

# -----------------------------
# Parse a single line
# -----------------------------
def parse_line(line):
    match = LOG_PATTERN.search(line)
    if match:
        return match.groupdict()
    return None

# -----------------------------
# Analyze the log file
# -----------------------------
def analyze_log(file_path):
    parsed_data = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                result = parse_line(line)
                if result:
                    parsed_data.append(result)
    except FileNotFoundError:
        print("[red]Error: File not found.[/red]")
        sys.exit(1)
    except Exception as e:
        print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)

    df = pd.DataFrame(parsed_data)

    # Export to CSV
    df.to_csv("analysis_output.csv", index=False)

    return df

# -----------------------------
# Print summary table
# -----------------------------
def print_summary(df):
    table = Table(title="Log Analysis Summary")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Total Requests", str(len(df)))

    if "status" in df.columns:
        status_counts = Counter(df["status"])
        for status, count in status_counts.items():
            table.add_row(f"Status {status}", str(count))

    if "ip" in df.columns:
        top_ips = Counter(df["ip"]).most_common(5)
        for ip, count in top_ips:
            table.add_row(f"Top IP {ip}", str(count))

    print(table)

# -----------------------------
# Main entry point
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[red]Usage: python analyzer.py logs/sample.log[/red]")
        sys.exit(1)

    file_path = sys.argv[1]
    df = analyze_log(file_path)
    print_summary(df)