import re
import sys
import pandas as pd
from collections import Counter
from datetime import datetime
from rich import print
from rich.table import Table


LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)?'
    r'.*?'
    r'(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})?'
    r'.*?'
    r'"(?P<method>GET|POST|PUT|DELETE)?'
    r'\s?(?P<endpoint>.*?)\s?HTTP/.*?"?'
    r'\s(?P<status>\d{3})?'
)


def parse_line(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    return match.groupdict()


def analyze_log(file_path):
    parsed_data = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            result = parse_line(line)
            if result:
                parsed_data.append(result)

    df = pd.DataFrame(parsed_data)
    df.to_csv("analysis_output.csv", index=False)

    return df


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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[red]Usage: python analyzer.py logs/sample.log[/red]")
        sys.exit(1)

    file_path = sys.argv[1]
    df = analyze_log(file_path)
    print_summary(df)