import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tensorflow.keras.models import load_model
import pandas as pd
import os
import joblib
import pefile

def metadata_extraction(file_path):
    try:
        pe = pefile.PE(file_path)

        metadata = {
            "Machine": pe.FILE_HEADER.Machine,
            "DebugRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
            "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
            "MajorOSVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "ExportRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,  # Export Table
            "ExportSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
            "IatVRA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,  # Import Address Table
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
            "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        }

        pe.close()
        return metadata

    except pefile.PEFormatError:
        print(f"[ERROR] Not a valid PE file: {file_path}")
        return {}
    except Exception as e:
        print(f"[ERROR] Metadata extraction failed for {file_path}: {e}")
        return {}

def detect_ransomware(file_path):
    try:

        all_features = metadata_extraction(file_path)

        required_features = [
            "Machine",  "DebugRVA", "MajorImageVersion", "MajorOSVersion",
            "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", 
            "MinorLinkerVersion", "NumberOfSections", "SizeOfStackReserve", 
            "DllCharacteristics", 
        ]

        raw_features = []
        for key in required_features:
            value = all_features.get(key, 0)
            if isinstance(value, (int, float, str)):
                raw_features.append(float(value))
            else:
                print(f"[WARNING] Feature '{key}' has invalid type: {type(value)}. Using 0 as default.")
                raw_features.append(0.0)

        pca = joblib.load(r"AI-Based-Ransomeware-Mitigation\ai_model\pca_model.pkl")
        transformed_features = pca.transform([raw_features])

        model = load_model(r"AI-Based-Ransomeware-Mitigation\ai_model\ransomeware_prediction_model.h5")

        prediction = model.predict(transformed_features)
        return "Ransomware" if prediction[0][0] < 0.5 else "Benign"  # Adjust threshold if needed

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
        elif result == "Benign":
            print(f"[INFO] File {file_path} is benign.")

    def isolate_system(self):
        os.system("netsh advfirewall set allprofiles state off")
        print("[ACTION] System isolated to prevent further damage.")


def start_monitoring(folder_to_monitor):
    print(f"[INFO] Starting monitoring for {folder_to_monitor}")
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=folder_to_monitor, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("[INFO] Stopping monitoring.")
    observer.join()


if __name__ == "__main__":
    directory_to_monitor = r"C:\mini project\test"
    if os.path.exists(directory_to_monitor):
        start_monitoring(directory_to_monitor)
    else:
        print(f"[ERROR] Directory {directory_to_monitor} does not exist.")