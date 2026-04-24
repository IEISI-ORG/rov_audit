import os
import json
import glob
import gzip
import time

DIR_PARSED = "data/parsed"
OUTPUT_FILE = "data/as_data.jsonl.gz"

def pack_data():
    files = glob.glob(os.path.join(DIR_PARSED, "as_*.json"))
    print(f"Packing {len(files)} files into {OUTPUT_FILE}...")
    
    start_time = time.time()
    count = 0
    with gzip.open(OUTPUT_FILE, 'wt', encoding='utf-8') as f_out:
        for f in files:
            try:
                with open(f, 'r') as f_in:
                    data = json.load(f_in)
                    f_out.write(json.dumps(data) + "\n")
                    count += 1
            except Exception as e:
                print(f"Error packing {f}: {e}")
            
            if count % 10000 == 0:
                print(f"  Processed {count}...")

    duration = time.time() - start_time
    print(f"Done! Packed {count} ASNs in {duration:.2f} seconds.")
    print(f"Output size: {os.path.getsize(OUTPUT_FILE) / (1024*1024):.2f} MB")

if __name__ == "__main__":
    pack_data()
