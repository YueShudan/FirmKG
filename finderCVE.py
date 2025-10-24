# The implementation has enabled the identification of vulnerabilities corresponding to versions in CSV files
'Firmware Name', 'Binary Name', 'Component Name', 'Component Version', 
                      'CVE ID', 'Description', 'CVSS v3 Score', 'CVSS v3 Severity', 
                      'CVSS v2 Score', 'CVSS v2 Severity'
"""
import csv
import requests
import time
import re
import os
from datetime import datetime, timedelta
from packaging import version

def parse_version(ver_str):
    """Parse the version number into a comparable format"""
    try:
        if not ver_str or ver_str.lower() in ('none', 'unknown', 'null', ''):
            return None
            
        # Remove common version prefixes and suffixes
        ver_str = re.sub(r'^v', '', str(ver_str), flags=re.IGNORECASE)
        ver_str = re.sub(r'^.*[:/]', '', ver_str)
        ver_str = ver_str.strip()
        
        # Process special formats
        ver_str = ver_str.replace('_', '.')
        
        # Remove any characters that are not related to the version number
        ver_str = re.sub(r'[^0-9.]', '', ver_str)
        
        # Ensure the version number format is correct
        if not re.match(r'^\d+(\.\d+)*$', ver_str):
            return None
            
        # Try to convert to a version object
        return version.parse(ver_str)
    except:
        return None

def extract_version_constraints(text):
    """Extract version constraints from text"""
    if not text:
        return []
    
    constraints = []
    text_lower = text.lower()
    
    # Common version range description patterns
    patterns = [
        # "before X.X.X" or "prior to X.X.X"
        (r'(?:before|prior to|until|through|up to|older than)\s+([\d._]+)', '<'),
        # "X.X.X and earlier" or "X.X.X or earlier"
        (r'([\d._]+)(?:\s+and\s+earlier|\s+or\s+earlier|\s+and\s+before|\s+or\s+before)', '<='),
        # "after X.X.X" or "later than X.X.X"
        (r'(?:after|later than|newer than)\s+([\d._]+)', '>'),
        # "X.X.X and later" or "X.X.X or later"
        (r'([\d._]+)(?:\s+and\s+later|\s+or\s+later)', '>='),
        # "between X.X.X and Y.Y.Y"
        (r'between\s+([\d._]+)\s+and\s+([\d._]+)', 'between'),
        # "version X.X.X"
        (r'version\s+([\d._]+)', '=='),
        # "affects X.X.X" 
        (r'affects\s+([\d._]+)', '=='),
        # "fixed in X.X.X" or "patched in X.X.X"
        (r'(?:fixed|patched)\s+in\s+([\d._]+)', '>='),
        # "vulnerable up to X.X.X"
        (r'vulnerable\s+up\s+to\s+([\d._]+)', '<=')
    ]
    
    for pattern, op in patterns:
        matches = re.finditer(pattern, text_lower)
        for match in matches:
            if op == 'between':
                v1 = parse_version(match.group(1))
                v2 = parse_version(match.group(2))
                if v1 and v2:
                    constraints.append(('>=', v1))
                    constraints.append(('<=', v2))
            else:
                v = parse_version(match.group(1))
                if v:
                    constraints.append((op, v))
    
    return constraints

def version_matches_constraints(ver_str, constraints):
    """Check if the version satisfies the constraints"""
    if not constraints:
        return False
        
    ver = parse_version(ver_str)
    if not ver:
        return False
    
    for op, constraint_ver in constraints:
        try:
            if op == '<' and not (ver < constraint_ver):
                return False
            elif op == '<=' and not (ver <= constraint_ver):
                return False
            elif op == '>' and not (ver > constraint_ver):
                return False
            elif op == '>=' and not (ver >= constraint_ver):
                return False
            elif op == '==' and not (ver == constraint_ver):
                return False
        except:
            continue
    
    return True

def version_appears_in_text(version, text):
    """Check if the version number appears in the text, using a more flexible match"""
    if not text:
        return False
    
    # First try direct matching
    version_str = normalize_version(version)
    if version_str.lower() in text.lower():
        return True
    
    # Extract version constraints and check
    constraints = extract_version_constraints(text)
    if constraints and version_matches_constraints(version, constraints):
        return True
    
    return False

def normalize_version(version):
    """Normalize the version number, removing unnecessary characters"""
    if not version:  # Handle None values
        return ""
        
    # Remove common version prefixes
    version = re.sub(r'^v', '', str(version), flags=re.IGNORECASE)
    # Remove the separator between the package name and the version
    version = re.sub(r'^.*[:/]', '', version)
    # Replace underscores with dots
    version = version.replace('_', '.')
    # Remove whitespace characters
    version = version.strip()
    # Remove special markers
    version = re.sub(r'[-_](release|alpha|beta|rc|dev|snapshot|stable|final).*$', '', version, flags=re.IGNORECASE)
    # Remove build numbers and revision numbers (if they exist)
    version = re.sub(r'[-+]build\d+', '', version, flags=re.IGNORECASE)
    version = re.sub(r'[-+]rev\d+', '', version, flags=re.IGNORECASE)
    return version

def get_package_names(binary):
    """Get possible package names"""
    # Common package name mappings
    package_map = {
        'brctl': ['bridge-utils', 'brctl'],
        'busybox': ['busybox'],
        'dnsmasq': ['dnsmasq'],
        'flash': ['flash-plugin', 'flashcp'],
        'http': ['lighttpd', 'httpd', 'web'],
        'hostap': ['hostapd', 'hostap_cli', 'hostapd-utils'],
        'iptable': ['iptables', 'iptable', 'ip'],
        'ntfs': ['ntfs-3g', 'ntfs3g', 'ntfsprogs'],
        'pppd': ['ppp', 'pppd'],
        'pptp': ['pptp', 'pptp-linux'],
        'privoxy': ['privoxy'],
        'tc': ['iproute2', 'tc'],
        'upnp': ['miniupnpd', 'miniupnpd-utils'],
        'ulogd': ['ulogd', 'ulogd2'],

    }
    
    # Return the list of mapped names, if no mapping is found, return the original name
    return package_map.get(binary, [binary])

def get_cvss_scores(metrics):
    """Get CVSS scores and severity levels"""
    result = {
        'v3': {'score': '', 'severity': ''},
        'v2': {'score': '', 'severity': ''}
    }
    
    try:
        # CVSS v3.x
        if 'cvssMetricV31' in metrics:
            v3 = metrics['cvssMetricV31'][0]
            result['v3']['score'] = str(v3.get('cvssData', {}).get('baseScore', ''))
            result['v3']['severity'] = str(v3.get('cvssData', {}).get('baseSeverity', ''))
        elif 'cvssMetricV30' in metrics:
            v3 = metrics['cvssMetricV30'][0]
            result['v3']['score'] = str(v3.get('cvssData', {}).get('baseScore', ''))
            result['v3']['severity'] = str(v3.get('cvssData', {}).get('baseSeverity', ''))
            
        # CVSS v2.0
        if 'cvssMetricV2' in metrics:
            v2 = metrics['cvssMetricV2'][0]
            result['v2']['score'] = str(v2.get('cvssData', {}).get('baseScore', ''))
            result['v2']['severity'] = str(v2.get('cvssData', {}).get('baseSeverity', ''))
            
    except Exception as e:
        print(f"Error parsing CVSS scores: {str(e)}")
        
    return result

def search_nvd_api(keyword):
    """Use the NVD API to search for vulnerabilities"""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Get the API key (if any)
    api_key = os.environ.get('NVD_API_KEY')
    
    # Set the search parameters
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 100,  # Number of results per page
        'startIndex': 0
    }
    
    all_vulnerabilities = []
    total_results = None
    max_retries = 3  # Maximum number of retries
    retry_delay = 60  # Retry wait time (seconds)
    
    while True:
        # Set the request headers
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        
        for retry_count in range(max_retries):
            try:
                print(f"    Requesting data (第 {retry_count + 1} 次尝试)...")
                response = requests.get(base_url, params=params, headers=headers, timeout=30)
                
                # Check if the rate limit is reached
                if response.status_code == 403:
                    print(f"    Warning: API rate limit reached, waiting {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
                    
                # Check other error status codes
                if response.status_code != 200:
                    print(f"    Error: HTTP status code {response.status_code}")
                    if retry_count < max_retries - 1:
                        print(f"    Waiting {retry_delay} seconds before retrying...")
                        time.sleep(retry_delay)
                        continue
                    break
                
                data = response.json()
                
                # Get the total number of results
                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    print(f"    Total number of potential vulnerabilities found: {total_results}")
                
                # Add the vulnerabilities on the current page
                if 'vulnerabilities' in data:
                    all_vulnerabilities.extend(data['vulnerabilities'])
                    print(f"    Number of results obtained: {len(all_vulnerabilities)}/{total_results}")
                
                # Check if the next page needs to be fetched
                if len(all_vulnerabilities) >= total_results or not data.get('vulnerabilities'):
                    break
                
                # Update the starting index
                params['startIndex'] += len(data.get('vulnerabilities', []))
                
                # After successfully obtaining data, wait for a period of time before requesting the next page
                if api_key:
                    time.sleep(0.6)  # Wait time when there is an API key
                else:
                    time.sleep(6)  # Wait time when there is no API key
                
                break  # Successfully obtained data, exit the retry loop
                
            except requests.exceptions.Timeout:
                print("    Error: Request timed out")
                if retry_count < max_retries - 1:
                    print(f"    Waiting {retry_delay} seconds before retrying...")
                    time.sleep(retry_delay)
                    continue
                break
                
            except requests.exceptions.RequestException as e:
                print(f"    API request failed: {str(e)}")
                if hasattr(e.response, 'text'):
                    print(f"    Error details: {e.response.text}")
                if retry_count < max_retries - 1:
                    print(f"    Waiting {retry_delay} seconds before retrying...")
                    time.sleep(retry_delay)
                    continue
                break
                
            except Exception as e:
                print(f"    Unknown error occurred: {str(e)}")
                if retry_count < max_retries - 1:
                    print(f"    Waiting {retry_delay} seconds before retrying...")
                    time.sleep(retry_delay)
                    continue
                break
        
        # If all retries fail, exit the loop
        if not all_vulnerabilities and params['startIndex'] == 0:
            print("    Unable to get data, skipping this search")
            break
            
        # If all data has been obtained or no more data can be obtained, exit the loop
        if len(all_vulnerabilities) >= total_results or not data.get('vulnerabilities'):
            break
    
    return {'vulnerabilities': all_vulnerabilities} if all_vulnerabilities else None

def try_read_csv(file_path, encodings=['utf-8', 'gbk', 'gb2312', 'gb18030', 'big5']):
    """Try to read the CSV file using different encodings"""
    for encoding in encodings:
        try:
            with open(file_path, mode='r', newline='', encoding=encoding) as file:
                reader = csv.reader(file)
                data = list(reader)  # Read all data
                return data, encoding
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError(f"Unable to read the file using the following encodings: {encodings}")

def check_version_in_range(current_version, cpe_match):
    """Check if the version is within the specified range"""
    try:
        if not current_version:
            return False
            
        # Check the version range
        if 'versionStartIncluding' in cpe_match:
            start_ver = parse_version(cpe_match['versionStartIncluding'])
            if start_ver and current_version < start_ver:
                return False
                
        if 'versionStartExcluding' in cpe_match:
            start_ver = parse_version(cpe_match['versionStartExcluding'])
            if start_ver and current_version <= start_ver:
                return False
                
        if 'versionEndIncluding' in cpe_match:
            end_ver = parse_version(cpe_match['versionEndIncluding'])
            if end_ver and current_version > end_ver:
                return False
                
        if 'versionEndExcluding' in cpe_match:
            end_ver = parse_version(cpe_match['versionEndExcluding'])
            if end_ver and current_version >= end_ver:
                return False
                
        # If there is no version range limit, check if there is an exact version match
        if not any(key in cpe_match for key in ['versionStartIncluding', 'versionStartExcluding', 
                                              'versionEndIncluding', 'versionEndExcluding']):
            if 'criteria' in cpe_match:
                cpe_version = cpe_match['criteria'].split(':')[5]
                cpe_ver = parse_version(cpe_version)
                if cpe_ver:
                    return str(current_version) == str(cpe_ver)
            return False
            
        return True
    except Exception as e:
        print(f"    Error checking the version range: {str(e)}")
        return False

def check_cpe_match(cpe_match, package, version):
    """Check if the CPE match item matches the given package name and version"""
    try:
        if not cpe_match or 'criteria' not in cpe_match:
            return False
            
        criteria = cpe_match['criteria'].lower()
        
        # Parse the CPE string
        # Format: cpe:2.3:a:vendor:product:version:...
        parts = criteria.split(':')
        if len(parts) < 6:
            return False
            
        cpe_vendor = parts[3].lower()  # Vendor name
        cpe_product = parts[4].lower()  # Product name
        
        # Check if the package name matches exactly (considering the vendor and product names)
        package_lower = package.lower()
        package_alternatives = get_package_names(package)
        
        # More strict package name matching
        package_match = False
        for name in [package_lower] + [alt.lower() for alt in package_alternatives]:
            # Check for exact match
            if name == cpe_product or name == cpe_vendor:
                package_match = True
                break
                
            # Check if it is a sub-component (e.g., openssl-dev matches openssl)
            if name.startswith(cpe_product + '-') or cpe_product.startswith(name + '-'):
                package_match = True
                break
        
        if not package_match:
            return False
        
        # Parse the current version
        current_version = parse_version(version)
        if not current_version:
            return False
            
        # Check if the version is within the range
        return check_version_in_range(current_version, cpe_match)
        
    except Exception as e:
        print(f"    Error comparing versions: {str(e)}")
        return False

def is_relevant_vulnerability(cve, package, version):
    """Check if the CVE is relevant to the given package and version"""
    if not cve or not package or not version:
        return False
        
    # Parse the version
    parsed_version = parse_version(version)
    if not parsed_version:
        return False
    
    # Check the configuration information
    version_match_found = False
    
    if 'configurations' in cve:
        for config in cve['configurations']:
            for node in config.get('nodes', []):
                # Check the operator of the node
                operator = node.get('operator', 'OR')
                matches = []
                
                for cpe_match in node.get('cpeMatch', []):
                    match_result = check_cpe_match(cpe_match, package, version)
                    matches.append(match_result)
                
                # Evaluate the results based on the operator
                if operator == 'AND' and matches and all(matches):
                    version_match_found = True
                    break
                elif operator == 'OR' and any(matches):
                    version_match_found = True
                    break
            
            if version_match_found:
                break
    
    # If no version match is found, check the description information
    if not version_match_found:
        descriptions = cve.get('descriptions', [])
        desc_text = ' '.join(d['value'].lower() for d in descriptions if d['lang'] == 'en')
        
        if not desc_text:
            return False
        
        # Ensure that the description clearly mentions the package name
        package_lower = package.lower()
        package_alternatives = get_package_names(package)
        
        # More strict package name matching
        package_mentioned = False
        for name in [package_lower] + [alt.lower() for alt in package_alternatives]:
            # Ensure that the package name appears as a standalone word
            pattern = r'\b' + re.escape(name) + r'\b'
            if re.search(pattern, desc_text):
                package_mentioned = True
                break
        
        if not package_mentioned:
            return False
        
        # Check the version constraints
        constraints = extract_version_constraints(desc_text)
        if constraints:
            version_match_found = version_matches_constraints(version, constraints)
    
    return version_match_found

def is_valid_package_name(pkg_name):
    """
    Check if the package name is valid, filtering out short names that may cause false positives
    
    Args:
        pkg_name: Package name
        
    Returns:
        bool: Whether the package name is valid
    """
    if not pkg_name:
        return False
        
    # Remove whitespace characters
    pkg_name = pkg_name.strip()
    
    # Ignore too short package names (2 characters or less)
    if len(pkg_name) <= 2:
        return False
        
    # Ignore common short names that may cause false positives
    ignored_names = {
        'wl', 'tc', 'ip', 'id', 'if', 'cp', 'mv', 'rm', 'ls', 'tr',
        'awk', 'sed', 'cat', 'top', 'ps', 'wc', 'dd', 'df'
    }
    
    if pkg_name.lower() in ignored_names:
        return False
        
    # Ignore package names that are purely numeric
    if pkg_name.isdigit():
        return False
        
    # Ignore package names that only contain special characters
    if not any(c.isalnum() for c in pkg_name):
        return False
        
    return True

def process_single_file(input_file, output_file):
    """Process a single CSV file"""
    try:
        # Read the CSV file and automatically detect the encoding
        data, detected_encoding = try_read_csv(input_file)
        print(f"Successfully read the file using {detected_encoding} encoding")
        
        # Prepare the list to store the results
        vulnerabilities = []
        skipped_packages = []  # Store the packages that were skipped and the reasons
        
        # Calculate the total number of rows (excluding the header row)
        total_packages = len(data) - 1
        
        # Write to the output file
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write the header row
            headers = ['Firmware Name', 'Binary Name', 'Component Name', 'Component Version', 
                      'CVE ID', 'Description', 'CVSS v3 Score', 'CVSS v3 Severity', 
                      'CVSS v2 Score', 'CVSS v2 Severity']
            writer.writerow(headers)
            
            # Skip the header row, process the data
            for index, row in enumerate(data[1:], 1):
                try:
                    # Ensure that the row has at least four columns
                    if len(row) < 4:
                        skipped_packages.append((str(row), "Row data is incomplete"))
                        continue
                        
                    firmware_name = row[0].strip()
                    binary_name = row[1].strip()
                    component_name = row[2].strip()
                    component_version = row[3].strip()
                    
                        print(f"\nProcessing progress: {index}/{total_packages}")
                    
                    if not component_name or not component_version or component_version.lower() in ('none', 'unknown', 'null', ''):
                        skipped_packages.append((component_name, "Component name or version is empty or invalid"))
                        continue
                        
                    # Check if the component name is valid
                    if not is_valid_package_name(component_name):
                        skipped_packages.append((component_name, "Component name is too short or invalid"))
                        continue
                        
                    # Check if the version number is valid
                    if not parse_version(component_version):
                        skipped_packages.append((f"{component_name} {component_version}", "Version number format is invalid"))
                        continue
                        
                    print(f"Searching for vulnerabilities for {component_name} {component_version}...")
                    
                    # Use the NVD API to search
                    results = search_nvd_api(component_name)
                    if not results or 'vulnerabilities' not in results:
                        continue
                        
                    vuln_count = 0
                    for vuln in results['vulnerabilities']:
                        try:
                            cve = vuln['cve']
                            
                            # Use the relevance check function
                            if is_relevant_vulnerability(cve, component_name, component_version):
                                # Get the necessary fields
                                cve_id = str(cve['id']).strip()
                                descriptions = cve.get('descriptions', [])
                                description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '').strip()
                                
                                # Get the CVSS scores
                                metrics = cve.get('metrics', {})
                                cvss_scores = get_cvss_scores(metrics)
                                
                                # Ensure that all fields are of string type and do not contain line breaks
                                entry = [
                                    firmware_name,
                                    binary_name,
                                    component_name,
                                    component_version,
                                    cve_id,
                                    description.replace('\n', ' ').replace('\r', ''),  # Remove line breaks
                                    cvss_scores['v3']['score'],
                                    cvss_scores['v3']['severity'],
                                    cvss_scores['v2']['score'],
                                    cvss_scores['v2']['severity']
                                ]
                                
                                # Verify that all fields conform to the expected format
                                if all(isinstance(field, str) for field in entry) and \
                                   len(entry) == len(headers) and \
                                   all(field.strip() for field in [entry[0], entry[1], entry[2], entry[3], entry[4]]):  # Key fields cannot be empty
                                    # Check if an identical entry already exists
                                    if entry not in vulnerabilities:
                                        vulnerabilities.append(entry)
                                        writer.writerow(entry)
                                        vuln_count += 1
                                        print(f"    Found vulnerability: {cve_id} (CVSS v3: {cvss_scores['v3']['score']}, CVSS v2: {cvss_scores['v2']['score']})")
                                
                        except Exception as e:
                            print(f"    Error processing vulnerability: {str(e)}")
                            continue
                            
                    if vuln_count == 0:
                        print(f"    No relevant vulnerabilities found")
                        
                except Exception as e:
                    print(f"Error processing row {index}: {str(e)}")
                    skipped_packages.append((str(row), f"Error processing: {str(e)}"))
                    continue
                    
        # Print the statistics
        print("\nProcessing completed!")
        print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        if skipped_packages:
            print("\nThe following components were skipped:")
            for pkg, reason in skipped_packages:
                print(f"  - {pkg}: {reason}")
                
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        raise

def main():
    # Specify the input and output directories
    csv_dir = 'csv'
    results_dir = 'Results'

    # Ensure that the output directory exists
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    # Process all CSV files in the csv directory
    for filename in os.listdir(csv_dir):
        if filename.endswith('.csv'):
            input_file = os.path.join(csv_dir, filename)
            output_file = os.path.join(results_dir, filename.replace('.csv', '_cve.csv'))
            
            # If the output file already exists, skip processing
            if os.path.exists(output_file):
                print(f"Skipping existing file: {filename}")
                continue
                
            process_single_file(input_file, output_file)

if __name__ == '__main__':
    main()
