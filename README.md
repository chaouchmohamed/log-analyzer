# Log Analyzer

A Python-based **streaming log analyzer** designed for **large log files (GB scale)**.  
Supports line-by-line processing, detects **500-error spikes**, tracks **top IPs**, and exports results to CSV.

## Features
- Processes logs **line by line** → low memory usage
- Tracks total requests, status codes, and top 5 IPs
- Detects **maximum consecutive 500 errors**
- Exports summary to `analysis_output.csv`
- Compatible with Apache/Nginx log format

## Usage

```bash
python analyzer.py logs/sample.log