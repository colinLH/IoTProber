import os
import json
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAG_DEVICES_PATH = os.path.join(BASE_DIR, '..', '..', '..', '..', 'rag_devices.json')
KNOWN_DIR = BASE_DIR
OUTPUT_CSV = os.path.join(BASE_DIR, 'vendor_summary_rag_devices.csv')

with open(RAG_DEVICES_PATH, 'r', encoding='utf-8') as f:
    rag_devices = json.load(f)

device_types = []
for category, types in rag_devices.items():
    device_types.extend(types)

print(f"Device types from rag_devices.json: {device_types}\n")

results = []

for device_type in device_types:
    csv_path = os.path.join(KNOWN_DIR, f'label_nonempty_{device_type}.csv')
    if not os.path.exists(csv_path):
        print(f"[WARN] File not found: {csv_path}")
        continue

    df = pd.read_csv(csv_path)

    if 'vendor' not in df.columns:
        print(f"[WARN] No 'vendor' column in {csv_path}")
        continue

    vendors = (
        df['vendor']
        .dropna()
        .str.strip()
        .replace('', pd.NA)
        .dropna()
    )
    vendors = vendors[vendors.str.lower() != 'unknown']

    unique_vendors = sorted(vendors.unique().tolist())
    vendor_count = len(unique_vendors)

    results.append({
        'device_type': device_type,
        'unique_vendor_count': vendor_count,
        'vendors': '; '.join(unique_vendors),
    })

    print(f"{'='*60}")
    print(f"Device Type : {device_type}")
    print(f"Vendor Count: {vendor_count}")
    print(f"Vendors     : {', '.join(unique_vendors)}")
    print()

summary_df = pd.DataFrame(results)
summary_df.to_csv(OUTPUT_CSV, index=False)
print(f"\nSummary saved to: {OUTPUT_CSV}")

print("\n" + "="*60)
print("OVERALL SUMMARY")
print("="*60)
print(f"{'Device Type':<25} {'Vendor Count':>12}")
print("-"*40)
for row in results:
    print(f"{row['device_type']:<25} {row['unique_vendor_count']:>12}")
