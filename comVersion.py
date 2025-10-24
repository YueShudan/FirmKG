# Given the firmware, analyze the number of binary programs, then analyze the versions of the binary programs, and provide json and csv
import os
import time
import json
from binaryai import BinaryAI
import csv
import struct  # Add struct import for binary file analysis
# from dotenv import load_dotenv

# Load environment variables
# load_dotenv()

# bin_and_version = os.path.join(os.path.dirname(os.path.abspath(__file__)), "XX/bin_and_version.csv")
# Open the file in append mode (note that using 'newline='' avoids blank lines)
# global writer
# fp = open(bin_and_version, 'a', newline='', encoding='utf-8')
# writer = csv.writer(fp)
# writer.writerow(['binary', 'version'])


def append_to_csv(writer, data):
    writer.writerow(data)

    # writer.writerow(new_row)  
def get_binaryai_client():
    """
    Initialize BinaryAI client with proper error handling
    """
    try:
        secret_id = 'AKIDfSM5ZRnuSya'
        secret_key = 'bwxx3x4flbcMWMCzrDi'

        return BinaryAI(secret_id=secret_id, secret_key=secret_key)
    except Exception as e:
        print(f"Error initializing BinaryAI client: {str(e)}")
        print("Please ensure your credentials are correct and you have internet connectivity")
        return None


def save_to_json(component, json_file):
    """
    Save component information to JSON and CSV files
    """
    try:
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(json_file), exist_ok=True)
        
        # Process the JSON file
        existing_data = []
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: The JSON file {json_file} is formatted incorrectly, a new file will be created")
                existing_data = []

        # Add new data to JSON
        existing_data.append(component)

        # Write to JSON file
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)

        # Generate the corresponding CSV file path
        csv_file = json_file.rsplit('.', 1)[0] + '.csv'

        # Check if the CSV file exists, if not, write the header
        csv_exists = os.path.exists(csv_file)
        
        # Open the CSV file (append mode)
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # If the file does not exist, write the header
            if not csv_exists:
                writer.writerow([
                    'Firmware Name',
                    'Binary Name',
                    'Component Name',
                    'Component Version'
                ])
            
            # Write component data (only include the specified columns)
            writer.writerow([
                component['firmware_name'],
                component['bin_name'],
                component['component_name'],
                component['component_version']
            ])

        print(f"Successfully saved component information: {component['bin_name']} - {component['firmware_name']}")
        print(f"JSON saved location: {os.path.abspath(json_file)}")
        print(f"CSV saved location: {os.path.abspath(csv_file)}")

    except Exception as e:
        print(f"Error saving data: {str(e)}")
        print(f"Attempt to save the JSON path: {os.path.abspath(json_file)}")
        print(f"Component data: {json.dumps(component, indent=2, ensure_ascii=False)}")


def binaryAnalyse(so_files, output_file):
    """
    Analyze binary files and save results to JSON and CSV files 
    """
    # Initialize BinaryAI client
    bai = get_binaryai_client()
    if not bai:
        print("Unable to initialize BinaryAI client, please check credentials and network connection")
        # Even if initialization fails, create an empty JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    count = 1
    all_results = []
    print("Length of so_files: ", len(so_files))

    # Create an empty JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump([], f, indent=2, ensure_ascii=False)

    for file in so_files:
        print(f"The {count}th file to be analyzed: {file}")
        # Extract the name of the app - use os.path to process the path
        # Normalize the path, replace all backslashes with forward slashes
        normalized_path = file.replace('\\', '/')
        parts = normalized_path.split('/')
        # Get the app name from the part after firmSet
        app_name = None
        for i in range(len(parts)):
            if parts[i] == 'firmSet' and i + 1 < len(parts):
                app_name = parts[i + 1]
                break
        
        if not app_name:
            # If firmSet is not found, use the name of the last 4th layer directory (assuming the structure is .../app_name/squashfs-root/bin/file)
            if len(parts) >= 4:
                app_name = parts[-4]
            else:
                app_name = "unknown"
                
        # Extract the file name
        file_name = os.path.basename(file)

        try:
            # Upload the file and get the SHA-256
            sha256 = bai.upload(file)
            print(f"File upload successful: {file_name}")
            # Wait for the analysis to complete
            print("Waiting for analysis to complete...")
            bai.wait_until_analysis_done(sha256, timeout=90)

            # Get the analysis results
            sca_res = bai.get_sca_result(sha256)
            if sca_res:
                # Store the result data
                for result in sca_res:
                    component = {
                        'firmware_name': app_name,
                        'bin_name': file_name,
                        'component_name': result.name if result.name else 'none',
                        'component_version': result.version if result.version else 'none',
                        'component_description': result.description if result.description else 'none',
                        'component_source_code_url': result.source_code_url if result.source_code_url else 'none',
                        'component_summary': result.summary if result.summary else 'none'
                    }

                    save_to_json(component, output_file)
                    all_results.append(component)

                print(f"Successfully analyzed file: {file_name}")
            else:
                print(f"No results found for {file_name}")
                # Record the case where there are no results
                component = {
                    'firmware_name': app_name,
                    'bin_name': file_name,
                    'component_name': 'none',
                    'component_version': 'none',
                    'component_description': 'No results found',
                    'component_source_code_url': 'none',
                    'component_summary': 'none'
                }

                save_to_json(component, output_file)
                all_results.append(component)

        except Exception as e:
            print(f"Error processing file {file_name}: {str(e)}")
            if str(e).__contains__('analysis still not in finished result after timeout'):
                print('Analysis timed out, waiting 5 seconds before continuing...')
                time.sleep(5)
            elif str(e).__contains__('Moderate Failed'):
                print('Analysis failed, waiting 5 seconds before continuing...')
                time.sleep(5)
            else:
                time.sleep(30)

            # Record the error case
            component = {
                'firmware_name': app_name,
                'bin_name': file_name,
                'component_name': 'none',
                'component_version': 'none',
                'component_description': f'Error: {str(e)}',
                'component_source_code_url': 'none',
                'component_summary': 'none'
            }
            
            save_to_json(component, output_file)
            all_results.append(component)

        count += 1
        print(f"Completed: {count - 1}/{len(so_files)}")

    return all_results


def find_binary_files(directory):
    """
    Recursively find binary files in the directory
    """
    binary_files = []
    
    def is_binary_executable(file_path):
        """
        Check if the file is a binary executable file
        """
        try:
            # Exclude soft links
            if os.path.islink(file_path):
                return False
            # Exclude dynamic link library files (.so or .dll files)
            if file_path.endswith(('.so', '.dll')):
                return False
            # Try to open the file and read the first few bytes
            with open(file_path, 'rb') as f:
                header = f.read(4)
                # Check if the file header conforms to common binary executable formats
                if header[:2] == b'MZ':  # Windows executable file (PE)
                    return True
                elif header[:4] == b'\x7fELF':  # ELF file (Linux)
                    # Further check if it is an EXEC type
                    f.seek(0)  # Move the file pointer to the beginning of the file
                    elf_header = f.read(52)  # The ELF header is usually 52 bytes long
                    if len(elf_header) < 52:
                        return False
                    # Parse the e_type field in the ELF header (starting from the 16th byte, 2 bytes long)
                    e_type = struct.unpack('H', elf_header[16:18])[0]
                    # e_type is 2 represents the EXEC type
                    if e_type == 2:
                        return True
        except Exception as e:
            # Catch the exception, ensure the function does not interrupt due to an exception
            print(f"Error checking file {file_path}: {e}")
            return False
        return False

    # Traverse the directory
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_binary_executable(file_path):
                binary_files.append(file_path)

    return binary_files


def main(input_dir:str, output_file):
    try:
        # Find all binary files
        binary_files = find_binary_files(input_dir)
        binary_count = len(binary_files)
        print(f"Found {binary_count} binary files")

        # Analyze the binary files
        results = binaryAnalyse(binary_files, output_file)

        # Check if the file was successfully generated
        if os.path.exists(output_file):
            print(f"\nAnalysis completed, results saved to: {output_file}")
            print(f"File size: {os.path.getsize(output_file)} bytes")
        else:
            print(f"\nWarning: Unable to find the output file: {output_file}")

        print(f"Total files analyzed: {len(results)}")
        return binary_count

    except Exception as e:
        print(f"Error during execution: {str(e)}")
        return 0


def iterator_dirs(root_dir:str):
    return [os.path.join(root_dir, d)
            for d in os.listdir(root_dir)
            if os.path.isdir(os.path.join(root_dir, d))]

    # return dirs

if __name__ == "__main__":
    # Ensure the Results directory exists
    os.makedirs("Results", exist_ok=True)
    
    # Create the total statistics CSV file
    summary_csv = os.path.join('Results', 'firmware_summary.csv')
    summary_exists = os.path.exists(summary_csv)
    
    with open(summary_csv, 'a', newline='', encoding='utf-8') as fp:
        writer = csv.writer(fp)
        if not summary_exists:
            writer.writerow(['Firmware Name', 'Binary Files Count', 'Analysis Time'])
    
    dirs = iterator_dirs('.\\firmSet')
    for dir in dirs:
        # Get the firmware name
        firmware_name = os.path.basename(dir)
        
        # Create the output file path
        json_file = os.path.join('Results', f"{firmware_name}.json")
        
        try:
            # Record the start time
            start_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Execute the analysis and get the number of binary files
            binary_count = main(dir, json_file)
            
            # Write the results to the total statistics file
            with open(summary_csv, 'a', newline='', encoding='utf-8') as fp:
                writer = csv.writer(fp)
                writer.writerow([firmware_name, binary_count, start_time])
                
        except Exception as e:
            print(f"Error processing directory {dir}: {str(e)}")
            # Record the error case
            with open(summary_csv, 'a', newline='', encoding='utf-8') as fp:
                writer = csv.writer(fp)
                writer.writerow([firmware_name, 0, start_time])
            continue
