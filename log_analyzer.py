"""!
@file: log_analyzer.py
@brief: reads server access logs and statuses. Writes a security report
@author: Jose Hernandez Olarte
@date: November 17, 2026
"""

def analyze_logs(filename) -> tuple | None:
    """"
    @brief:
    :param filename: path to log file
    :return: tuple of (total_attempts, failed_count, locked_count),
    or none if no logs found
    """
    total_attempts = 0
    failed_count = 0
    locked_count = 0

    try:
        with open(filename, "r", encoding="utf-8") as in_file:
            for line in in_file:
                clean_line = line.strip()
                if not clean_line:
                    continue #skips blank lines

                timestamp, username, ip_address, status = clean_line.split()
                total_attempts += 1

                if status.upper() == "FAILED":
                    failed_count += 1
                    print(f"[WARNING] Failed login for {username} from {ip_address} at {timestamp}")
                elif status.upper() == "LOCKED":
                    locked_count += 1
                    print(f"[CRITICAL] Account Locked for {username} from {ip_address} at {timestamp}")

    except FileNotFoundError:
        print("Error: Could not find the log file '{filename}'. Check your working directory.")
        return None

    return total_attempts, failed_count, locked_count
