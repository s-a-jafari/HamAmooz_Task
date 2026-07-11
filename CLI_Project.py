import sys
import argparse
import re
import gzip
from collections import Counter
from datetime import datetime

LOG_PATTERN = re.compile(r"""
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
""", re.VERBOSE)

def parse_log_line(line):
    try:
        match = LOG_PATTERN.search(line)
        if match:
            return match.groupdict()
        else:
            return None
    except Exception:
        return None


def process_file(file_path):

    total_requests = 0
    failed_lines = 0

    unique_ips = set()
    suspicious_ips = Counter()  

    endpoints_counter = Counter() 
    error_count = 0         
    time_distribution = Counter()
    hourly_5xx_errors = Counter()

    try:
        if file_path.endswith('.gz'):
            file_opener = gzip.open(file_path, 'rt', encoding='utf-8')
        else:
            file_opener = open(file_path, 'r', encoding='utf-8')

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
                
                if parsed_data["status"].startswith('4') or parsed_data["status"].startswith('5'):
                    error_count += 1
                
                try:
                    clean_time_str = parsed_data["time"].replace(" ", "")
                    dt_obj = datetime.strptime(clean_time_str, "%d/%b/%Y:%H:%M:%S%z")

                    hour_key = dt_obj.strftime("%Y-%m-%d %H:00")
                    time_distribution[hour_key] += 1

                    if parsed_data["status"].startswith('5'):
                        hourly_5xx_errors[hour_key] += 1

                except ValueError:
                    pass

        print("\n" + "="*40)
        print("BASIC LOG REPORT")
        print("="*40)
        print(f"Total Requests: {total_requests}")
        print(f"Unique IPs: {len(unique_ips)}")
        print(f"Failed/Skipped Lines: {failed_lines}")
        

        error_rate = (error_count / total_requests) * 100 if total_requests > 0 else 0
        print(f"Error Rate (4xx & 5xx): {error_rate:.2f}%\n")
        
        print("TOP 10 ENDPOINTS")
        print("-" * 20)
        for path, count in endpoints_counter.most_common(10):
            print(f"{count:>8} requests -> {path}")

        print("\nHOURLY TRAFFIC (Histogram)")
        print("-" * 40)
        if time_distribution:
            max_traffic = max(time_distribution.values())
            for hour in sorted(time_distribution.keys()):
                count = time_distribution[hour]
                bar_length = int((count / max_traffic) * 50)
                bar = '█' * bar_length
                print(f"{hour} | {count:>6} | {bar}")
        
        print("="*40 + "\n")

        print("\nSUSPICIOUS ACTIVITY (Brute-Force Attempts)")
        print("-" * 40)
        suspicious_found = False
        
        for ip, count in suspicious_ips.items():
            if count > 5: 
                print(f"[WARNING] IP: {ip} -> {count} failed login attempts!")
                suspicious_found = True
        
        if not suspicious_found:
            print("No suspicious login activity detected. Systems normal.")

        print("\n 5xx ERROR SPIKE DETECTION")
        print("-" * 40)
        
        highest_error_rate = 0
        worst_hour = None
        
        for hour, total_reqs in time_distribution.items():
            if total_reqs > 10: 
                errors = hourly_5xx_errors[hour]
                rate = (errors / total_reqs) * 100
                
                if rate > highest_error_rate and rate > 5.0:
                    highest_error_rate = rate
                    worst_hour = hour
                    
        if worst_hour:
            print(f"[CRITICAL] Error spike detected at {worst_hour}!")
            print(f"-> 5xx Error Rate jumped to {highest_error_rate:.1f}% ({hourly_5xx_errors[worst_hour]} errors out of {time_distribution[worst_hour]} requests)")
        else:
            print("No significant 5xx error spikes detected (All hours are under 5% error rate).")    
            

    except FileNotFoundError:
        print(f"[Error] The file '{file_path}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")
        sys.exit(1)    


def main():
    parser = argparse.ArgumentParser(description="A CLI tool to analyze access logs.")
    
    parser.add_argument("filepath", help="Path to the access log file")
    
    args = parser.parse_args()
    
    process_file(args.filepath)

if __name__ == "__main__":
    main()
