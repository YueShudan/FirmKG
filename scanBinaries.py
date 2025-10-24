# Scan the binary files in the firmware and generate a CSV file
import os
import csv
import struct


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
                # Check if the file header conforms to the common binary executable format
                if header[:2] == b'MZ':  # Windows executable file (PE)
                    return True
                elif header[:4] == b'\x7fELF':  # ELF file (Linux)
                    # Further check if it is an EXEC type
                    f.seek(0)  # Move the file pointer to the beginning of the file
                    elf_header = f.read(52)  # The length of the ELF header is usually 52 bytes
                    if len(elf_header) < 52:
                        return False
                    # Parse the e_type field in the ELF header (starting from the 16th byte, 2 bytes long)
                    e_type = struct.unpack('H', elf_header[16:18])[0]
                    # e_type is 2 represents the EXEC type
                    if e_type == 2:
                        return True
        except Exception as e:
            # Catch the exception, ensure that the function does not interrupt due to an exception
            print(f"Error checking file {file_path}: {e}")
            return False
        return False

    # Traverse the directory
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_binary_executable(file_path):
                # Only return the file name, not the path
                binary_files.append(file)

    return binary_files

def process_firmware(firmware_dir, firmware_path):
    """
    Process a single firmware and generate the corresponding CSV file
    """
    results = []
    binary_id = 1
    found_binaries = set()  # Used to remove duplicates
    
    # Directly scan the entire firmware directory
    print(f"Scanning the firmware directory...")
    binaries = find_binary_files(firmware_path)
    
    # Record the found binary files
    for binary in binaries:
        if binary not in found_binaries:
            results.append([binary_id, binary])
            found_binaries.add(binary)
            binary_id += 1
    
    if results:
        print(f"Found {len(results)} binary files in {firmware_dir}")
        
        # Create the output directory (if it does not exist)
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate the CSV file for the firmware
        output_file = os.path.join(output_dir, f"{firmware_dir}.csv")
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Binary Name'])
            writer.writerows(results)
        print(f"Results saved to {output_file}")
    else:
        print(f"Warning: No binary files found in {firmware_dir}")

def main():
    firmware_root = "firmSet"
    
    # Traverse the firmware directory
    for firmware_dir in os.listdir(firmware_root):
        firmware_path = os.path.join(firmware_root, firmware_dir)
        if os.path.isdir(firmware_path):
            print(f"\nScanning firmware {firmware_dir}...")
            process_firmware(firmware_dir, firmware_path)
    
    print("\nScan completed!")

if __name__ == "__main__":
    main() 