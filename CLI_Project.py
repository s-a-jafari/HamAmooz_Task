import sys
import argparse
import re
import gzip
import json
import time
from collections import Counter
from datetime import datetime

LOG_PATTERN = re.compile(
    r"""
    ^(?P<ip>\S+)                   
    \s+\S+\s+\S+\s+            
    \[(?P<time>[^\]]+)\]\s+       
    "(?P<method>\S+)?\s* 
    (?P<path>[^\s"]+)?\s*          
    [^"]*"\s+                     
    (?P<status>\d{3})\s+           
    (?P<size>\S+)                  
    (?:\s+"(?P<referrer>[^"]*)")?  
    (?:\s+"(?P<user_agent>[^"]*)")?
""",
    re.VERBOSE,
)


def parse_log_line(line):
    try:
        match = LOG_PATTERN.search(line)
        if match:
            return match.groupdict()
        else:
            return None
    except Exception:
        return None


def process_file(file_path, top_n, json_output):
    start_time = time.time()
    total_requests = 0
    failed_lines = 0

    unique_ips = set()
    suspicious_ips = Counter()

    endpoints_counter = Counter()
    error_count = 0
    time_distribution = Counter()
    hourly_5xx_errors = Counter()

    try:
        if file_path.endswith(".gz"):
            file_opener = gzip.open(file_path, "rt", encoding="utf-8")
        else:
            file_opener = open(file_path, "r", encoding="utf-8")

        with file_opener as file:
            for line in file:
                parsed_data = parse_log_line(line)

                if not parsed_data:
                    failed_lines += 1
                    continue

                total_requests += 1
                unique_ips.add(parsed_data["ip"])

                if parsed_data["path"] and "login" in parsed_data["path"].lower():
                    if parsed_data["status"] == "401":
                        suspicious_ips[parsed_data["ip"]] += 1

                if parsed_data["path"]:
                    endpoints_counter[parsed_data["path"]] += 1

                if parsed_data["status"].startswith("4") or parsed_data[
                    "status"
                ].startswith("5"):
                    error_count += 1

                try:
                    clean_time_str = parsed_data["time"].replace(" ", "")
                    dt_obj = datetime.strptime(clean_time_str, "%d/%b/%Y:%H:%M:%S%z")

                    hour_key = dt_obj.strftime("%Y-%m-%d %H:00")
                    time_distribution[hour_key] += 1

                    if parsed_data["status"].startswith("5"):
                        hourly_5xx_errors[hour_key] += 1

                except ValueError:
                    pass

        highest_error_rate = 0
        worst_hour = None

        for hour, total_reqs in time_distribution.items():
            if total_reqs > 10:
                errors = hourly_5xx_errors[hour]
                rate = (errors / total_reqs) * 100

                if rate > highest_error_rate and rate > 5.0:
                    highest_error_rate = rate
                    worst_hour = hour

        print("\n" + "=" * 40)
        execution_time = time.time() - start_time
        error_rate = (error_count / total_requests) * 100 if total_requests > 0 else 0

        if json_output:
            report_data = {
                "execution_time_seconds": round(execution_time, 2),
                "basic_statistics": {
                    "total_requests": total_requests,
                    "unique_ips": len(unique_ips),
                    "failed_lines": failed_lines,
                    "error_rate_percent": round(error_rate, 2),
                },
                "top_endpoints": dict(endpoints_counter.most_common(top_n)),
                "suspicious_ips": {
                    ip: count for ip, count in suspicious_ips.items() if count > 5
                },
                "error_spike": {
                    "worst_hour": worst_hour,
                    "highest_error_rate": round(highest_error_rate, 2)
                    if worst_hour
                    else 0,
                },
            }
            print(json.dumps(report_data, indent=4))

        else:
            print("\n" + "=" * 40)
            print("BASIC LOG REPORT")
            print("=" * 40)
            print(f"Total Requests: {total_requests}")
            print(f"Unique IPs: {len(unique_ips)}")
            print(f"Failed/Skipped Lines: {failed_lines}")
            print(f"Error Rate (4xx & 5xx): {error_rate:.2f}%\n")

            print(f"TOP {top_n} ENDPOINTS")
            print("-" * 20)
            for path, count in endpoints_counter.most_common(top_n):
                print(f"{count:>8} requests -> {path}")

            print("\nHOURLY TRAFFIC (Histogram)")
            print("-" * 40)
            if time_distribution:
                max_traffic = max(time_distribution.values())
                for hour in sorted(time_distribution.keys()):
                    count = time_distribution[hour]
                    bar_length = int((count / max_traffic) * 50)
                    bar = "█" * bar_length
                    print(f"{hour} | {count:>6} | {bar}")
            print("=" * 40 + "\n")

            print("\nSUSPICIOUS ACTIVITY (Brute-Force Attempts)")
            print("-" * 40)
            suspicious_found = False
            for ip, count in suspicious_ips.items():
                if count > 5:
                    print(f"[WARNING] IP: {ip} -> {count} failed login attempts!")
                    suspicious_found = True
            if not suspicious_found:
                print("No suspicious login activity detected. Systems normal.")

            print("\n5xx ERROR SPIKE DETECTION")
            print("-" * 40)
            if worst_hour:
                print(f"[CRITICAL] Error spike detected at {worst_hour}!")
                print(f"-> 5xx Error Rate jumped to {highest_error_rate:.1f}%")
            else:
                print("No significant 5xx error spikes detected.")

            print("\n" + "=" * 40)
            print(f"Execution Time: {execution_time:.2f} seconds")
            print("=" * 40)

    except FileNotFoundError:
        print(f"[Error] The file '{file_path}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="A CLI tool to analyze access logs.")

    parser.add_argument("filepath", help="Path to the access log file")

    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top endpoints to show (default: 10)",
    )

    parser.add_argument(
        "--json", action="store_true", help="Output the report in JSON format"
    )

    args = parser.parse_args()

    process_file(args.filepath, args.top, args.json)


if __name__ == "__main__":
    main()
