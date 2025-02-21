import os
import shutil
from datetime import datetime


def backup_files(source_dir, backup_dir):
    try:
        
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = os.path.join(backup_dir, f"backup_{timestamp}")
        os.makedirs(backup_subdir)

        for root, dirs, files in os.walk(source_dir):
            for file in files:
                source_file = os.path.join(root, file)
                relative_path = os.path.relpath(source_file, source_dir)
                dest_file = os.path.join(backup_subdir, relative_path)

                dest_dir = os.path.dirname(dest_file)
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)

                shutil.copy2(source_file, dest_file)
                print(f"[INFO] Backed up: {source_file} -> {dest_file}")

        print(f"[SUCCESS] Backup completed at {backup_subdir}")
        return backup_subdir

    except Exception as e:
        print(f"[ERROR] Backup failed: {e}")


if __name__ == "__main__":
    
    source_directory = r"C:\mini project\test"
    backup_directory = r"C:\mini project\test1"

    if os.path.exists(source_directory):
        backup_files(source_directory, backup_directory)
    else:
        print(f"[ERROR] Source directory {source_directory} does not exist.")