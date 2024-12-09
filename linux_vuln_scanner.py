import os
import subprocess
import requests
import threading
import platform

# Mutex for thread-safe print/logging
from threading import Lock
lock = Lock()

def get_system_info():
    """Retrieve basic system information."""
    uname = platform.uname()
    return {
        "OS": uname.system,
        "Node Name": uname.node,
        "Release": uname.release,
        "Version": uname.version,
        "Machine": uname.machine,
        "Processor": uname.processor,
    }

def get_installed_packages():
    """Retrieve a list of installed packages using the package manager."""
    try:
        result = subprocess.run(['dpkg-query', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print("Error fetching package list:", result.stderr)
            return None
    except Exception as e:
        print(f"Error running command: {e}")
        return None

def fetch_cve_database():
    """Fetch the latest CVE database from a public source."""
    url = "https://cve.mitre.org/data/downloads/allitems.csv"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            with open("cve_database.csv", "w") as file:
                file.write(response.text)
            print("CVE database downloaded successfully.")
            return "cve_database.csv"
        else:
            print(f"Failed to download CVE database. HTTP Status: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error fetching CVE database: {e}")
        return None

def scan_package_for_vulnerabilities(package_name, cve_data, results):
    """Scan a single package against the CVE database."""
    found_vulnerabilities = []
    for line in cve_data:
        if package_name in line:
            found_vulnerabilities.append(line.strip())
    with lock:
        results[package_name] = found_vulnerabilities

def scan_for_vulnerabilities(package_list, cve_database_path):
    """Scan installed packages against the CVE database."""
    try:
        with open(cve_database_path, "r") as cve_file:
            cve_data = cve_file.readlines()
        
        results = {}
        threads = []
        
        for package in package_list.split("\n"):
            if not package.startswith("ii "):  # 'ii ' denotes installed packages in dpkg
                continue
            package_name = package.split()[1]
            thread = threading.Thread(target=scan_package_for_vulnerabilities, args=(package_name, cve_data, results))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        return results
    except Exception as e:
        print(f"Error scanning vulnerabilities: {e}")
        return {}

def save_to_log(data, log_file="vulnerability_scan.log"):
    """Save scan results to a log file."""
    try:
        with open(log_file, "w") as file:
            file.write(data)
        print(f"Results saved to {log_file}")
    except Exception as e:
        print(f"Error saving log: {e}")

def main():
    print("Gathering system information...")
    system_info = get_system_info()
    for key, value in system_info.items():
        print(f"{key}: {value}")
    
    print("\nFetching installed packages...")
    package_list = get_installed_packages()
    if not package_list:
        return
    
    print("\nDownloading CVE database...")
    cve_database_path = fetch_cve_database()
    if not cve_database_path:
        return
    
    print("\nScanning for vulnerabilities...")
    vulnerabilities = scan_for_vulnerabilities(package_list, cve_database_path)
    
    log_data = f"System Info:\n{system_info}\n\n"
    log_data += "Vulnerabilities Found:\n"
    vulnerable_packages = 0
    for package, vulns in vulnerabilities.items():
        if vulns:
            vulnerable_packages += 1
            log_data += f"\nPackage: {package}\n"
            for vuln in vulns:
                log_data += f"  {vuln}\n"
    
    if vulnerable_packages > 0:
        print(f"\nFound {vulnerable_packages} vulnerable packages. Check the log for details.")
    else:
        print("\nNo vulnerabilities found.")
    
    save_to_log(log_data)

if __name__ == "__main__":
    main()
