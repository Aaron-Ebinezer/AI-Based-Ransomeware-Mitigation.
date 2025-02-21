import re
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from joblib import load
import pefile
import math
import magic  # For file signature analysis
from backup import backup_files
from encryption import encrypt_pe_file_inplace

# Load the AI model
model = load(r"AI-Based-Ransomeware-Mitigation\ai_model\svm_model.joblib")

def metadata_extraction(file_path):
    try:
        pe = pefile.PE(file_path)
        metadata = {
            "Machine": pe.FILE_HEADER.Machine,
            "DebugSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
            "DebugRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
            "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
            "MajorOSVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "ExportRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
            "ExportSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
            "IatVRA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
            "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "ResourceSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
            "BitcoinAddresses": extract_bitcoin_addresses(file_path)
        }
        pe.close()
        return metadata
    except pefile.PEFormatError:
        print(f"[ERROR] Not a valid PE file: {file_path}")
        return {}
    except Exception as e:
        print(f"[ERROR] Metadata extraction failed for {file_path}: {e}")
        return {}

def extract_bitcoin_addresses(file_path):
    bitcoin_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
    addresses = []
    try:
        with open(file_path, 'rb') as file:
            content = file.read().decode(errors='ignore')
            addresses = re.findall(bitcoin_pattern, content)
    except Exception as e:
        print(f"[ERROR] Failed to extract Bitcoin addresses: {e}")
    return ','.join(addresses) if addresses else 'None'

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    except Exception as e:
        print(f"[ERROR] Failed to calculate entropy for {file_path}: {e}")
        return 0

def is_pe_file(file_path):
    try:
        file_type = magic.from_file(file_path)
        return "PE32" in file_type or "PE64" in file_type
    except Exception as e:
        print(f"[ERROR] Failed to determine file type: {e}")
        return False

def detect_ransomware(file_path):
    try:
        # Step 1: Check if the file is still a valid PE file
        if is_pe_file(file_path):
            # Step 2: Extract metadata and use the AI model
            metadata = metadata_extraction(file_path)
            if metadata:
                required_features = [
                    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
                    "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
                    "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize", "BitcoinAddresses"
                ]
                raw_features = []
                for key in required_features:
                    value = metadata.get(key, 0)
                    raw_features.append(float(value) if isinstance(value, (int, float, str)) and str(value).replace('.', '', 1).isdigit() else 0.0)
                
                # Make prediction using the AI model
                prediction = model.predict([raw_features])
                return "Ransomware" if prediction[0] == 1 else "Benign"
        
        # Step 3: If the file is not a valid PE file, use entropy and behavioral analysis
        entropy = calculate_entropy(file_path)
        print(f"[INFO] Entropy for {file_path}: {entropy:.2f}")
        
        # High entropy indicates possible encryption
        if entropy > 7:  # Adjust threshold as needed
            print(f"[ALERT] High entropy detected! Possible encrypted file: {file_path}")
            return "Ransomware"
        else:
            return "Benign"
    
    except Exception as e:
        print(f"[ERROR] Could not analyze file {file_path}: {e}")
        return "Unknown"

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.analyzed_files = set()

    def on_created(self, event):
        if not event.is_directory:
            print(f"[ALERT] File created: {event.src_path}")
            self.analyze(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and event.src_path not in self.analyzed_files:
            print(f"[ALERT] File modified: {event.src_path}")
            self.analyze(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[ALERT] File deleted: {event.src_path}")

    def analyze(self, file_path):
        self.analyzed_files.add(file_path)
        result = detect_ransomware(file_path)
        if result == "Ransomware":
            print(f"[CRITICAL] Ransomware detected in {file_path}!")
            self.isolate_system()
            backup_files(directory_to_monitor, backup_directory)
        elif result == "Benign":
            print(f"[INFO] File {file_path} is benign.")

    def isolate_system(self):
        try:
            os.system("netsh advfirewall set allprofiles state off")
            print("[ACTION] System isolated to prevent further damage.")
        except Exception as e:
            print(f"[ERROR] Failed to isolate system: {e}")

def start_monitoring(folder_to_monitor):
    file_path = r"C:\mini project\test\minimal_valid.exe"
    print(f"[INFO] Starting monitoring for {folder_to_monitor}")
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=folder_to_monitor, recursive=True)
    observer.start()
    encrypt_pe_file_inplace(file_path)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("[INFO] Stopping monitoring.")
    observer.join()

if __name__ == "__main__":
    directory_to_monitor = r"C:\\mini project\\test"
    backup_directory = r"C:\\mini project\\test1"

    if os.path.exists(directory_to_monitor):
        start_monitoring(directory_to_monitor)
    else:
        print(f"[ERROR] Directory {directory_to_monitor} does not exist.")