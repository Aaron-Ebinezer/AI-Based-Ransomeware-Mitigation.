import re
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pandas as pd
import os
from joblib import load
import pefile
import math
from backup import backup_files
from encryption import encrypt_pe_file

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    data_size = len(data)
    freq_dict = {}

    for byte in data:
        freq_dict[byte] = freq_dict.get(byte, 0) + 1

    for freq in freq_dict.values():
        p_x = freq / data_size
        entropy += -p_x * math.log2(p_x)

    return entropy

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


def detect_ransomware(file_path):
    try:
        all_features = metadata_extraction(file_path)

        if all_features:
            required_features = [
                "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
                "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
                "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize", "BitcoinAddresses"
            ]

            raw_features = []
            for key in required_features:
                value = all_features.get(key, 0)
                raw_features.append(float(value) if isinstance(value, (int, float, str)) and str(value).replace('.', '', 1).isdigit() else 0.0)

            model = load(r"AI-Based-Ransomeware-Mitigation\ai_model\svm_model.joblib")
            prediction = model.predict([raw_features])
            return "Ransomware" if prediction[0] == 1 else "Benign"

        else:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            entropy = calculate_entropy(file_data)
            print(f"[INFO] Entropy for {file_path}: {entropy:.2f}")

            if entropy > 6:
                print(f"[ALERT] High entropy detected! Possible encrypted file: {file_path}")
                return "Ransomware"
            else:
                return "Benign"

    except Exception as e:
        print(f"[ERROR] Could not analyze file {file_path}: {e}")
        return "Unknown"

class RansomwareEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"[ALERT] File created: {event.src_path}")
            self.analyze(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"[ALERT] File modified: {event.src_path}")
            self.analyze(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[ALERT] File deleted: {event.src_path}")

    def analyze(self, file_path):
        result = detect_ransomware(file_path)
        if result == "Ransomware":
            print(f"[CRITICAL] Ransomware detected in {file_path}!")
            self.isolate_system()
            backup_files(directory_to_monitor, backup_directory)
        elif result == "Benign":
            print(f"[INFO] File {file_path} is benign.")

    def isolate_system(self):
        os.system("netsh advfirewall set allprofiles state off")
        print("[ACTION] System isolated to prevent further damage.")

def start_monitoring(folder_to_monitor):
    input_pe_file = r"C:\mini project\test\minimal.exe"
    encrypted_file = r"C:\mini project\test\minimal.locked"
    print(f"[INFO] Starting monitoring for {folder_to_monitor}")
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=folder_to_monitor, recursive=True)
    observer.start()

    encrypt_pe_file(input_pe_file, encrypted_file)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("[INFO] Stopping monitoring.")
    observer.join()

if __name__ == "__main__":
    directory_to_monitor = r"C:\mini project\test"
    backup_directory = r"C:\mini project\test1"

    if os.path.exists(directory_to_monitor):
        start_monitoring(directory_to_monitor)
    else:
        print(f"[ERROR] Directory {directory_to_monitor} does not exist.")
