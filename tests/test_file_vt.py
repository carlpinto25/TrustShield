import os
import sys
import hashlib

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.tools.virustotal_tools import scan_file_virustotal

def test_file_scan_hash():
    # EICAR test file content (standard for testing antivirus)
    eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    print(f"Testing VT for EICAR file hash: {hashlib.sha256(eicar_content).hexdigest()}")
    result = scan_file_virustotal(eicar_content, "eicar.com")
    print("VT Result (EICAR):")
    import json
    print(json.dumps(result, indent=2))

def test_file_scan_upload():
    # A unique small file to trigger upload
    import time
    unique_content = f"This is a unique test file created at {time.time()}".encode()
    print(f"\nTesting VT for unique file upload (hash: {hashlib.sha256(unique_content).hexdigest()})")
    result = scan_file_virustotal(unique_content, "test.txt")
    print("VT Result (Unique Upload):")
    import json
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_file_scan_hash()
    test_file_scan_upload()
