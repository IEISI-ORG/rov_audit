import pandas as pd
import numpy as np
import sys
import os

# Check for command line argument
if len(sys.argv) < 2:
    print("Usage: python script.py <csv_file>")
    print("Example: python script.py network_data.csv")
    sys.exit(1)

csv_file = sys.argv[1]

# Check if file exists
if not os.path.exists(csv_file):
    print(f"Error: File '{csv_file}' not found.")
    sys.exit(1)

# Load data from CSV file
try:
    df = pd.read_csv(csv_file)
    initial_count = len(df)
    print(f"Successfully loaded {initial_count} records from '{csv_file}'")
    
    # Drop records with country code "XX" (not yet scanned)
    if 'cc' in df.columns:
        xx_count = (df['cc'] == 'XX').sum()
        if xx_count > 0:
            df = df[df['cc'] != 'XX'].copy()
            print(f"Dropped {xx_count} records with cc='XX' (not yet scanned)")
            print(f"Remaining records: {len(df)}")
    print()
except Exception as e:
    print(f"Error reading CSV file: {e}")
    sys.exit(1)

print("=" * 80)
print("STATISTICAL SUMMARY OF NETWORK DATA")
print("=" * 80)
print()

# Key Independent Factors Analysis
print("KEY INDEPENDENT FACTORS")
print("-" * 80)
print()

# Country Code (CC) Analysis
print("1. COUNTRY CODE (CC) DISTRIBUTION")
print(f"   Unique Countries: {df['cc'].nunique()}")
print(f"   Total Records: {len(df)}")
print()
cc_counts = df['cc'].value_counts()
print("   Distribution:")
for cc, count in cc_counts.items():
    pct = (count / len(df)) * 100
    print(f"      {cc}: {count:2d} ({pct:5.1f}%)")
print()

# Verdict Analysis
print("2. VERDICT DISTRIBUTION")
print(f"   Unique Verdicts: {df['verdict'].nunique()}")
print()
verdict_counts = df['verdict'].value_counts()
print("   Distribution:")
for verdict, count in verdict_counts.items():
    pct = (count / len(df)) * 100
    print(f"      {verdict}: {count:2d} ({pct:5.1f}%)")
print()

# ASN Analysis
print("=" * 80)
print("ASN (AUTONOMOUS SYSTEM NUMBER) ANALYSIS")
print("-" * 80)
print(f"   Total Unique ASNs: {df['asn'].nunique()}")
print(f"   ASN Range: {df['asn'].min()} to {df['asn'].max()}")
print()

# AS Cone Analysis
print("=" * 80)
print("AS CONE STATISTICS")
print("-" * 80)
print(f"   Count: {df['cone'].count()}")
print(f"   Mean: {df['cone'].mean():,.2f}")
print(f"   Median: {df['cone'].median():,.2f}")
print(f"   Std Dev: {df['cone'].std():,.2f}")
print(f"   Min: {df['cone'].min():,}")
print(f"   Max: {df['cone'].max():,}")
print()
print("   Quartiles:")
print(f"      25th percentile: {df['cone'].quantile(0.25):,.2f}")
print(f"      50th percentile: {df['cone'].quantile(0.50):,.2f}")
print(f"      75th percentile: {df['cone'].quantile(0.75):,.2f}")
print()

# Top 5 by Cone
print("   Top 5 Networks by AS Cone:")
top5_cone = df.nlargest(5, 'cone')[['name', 'cc', 'cone', 'verdict']]
for idx, row in top5_cone.iterrows():
    print(f"      {row['cone']:6,} - {row['name'][:40]} ({row['cc']})")
print()

# APNIC Score Analysis
print("=" * 80)
print("APNIC SCORE (RPKI Invalid Route Blocking)")
print("-" * 80)

# Filter out -1.0 values for meaningful statistics
valid_scores = df[df['apnic_score'] >= 0]['apnic_score']
all_scores = df['apnic_score']

print(f"   Total Records: {len(all_scores)}")
print(f"   Records with -1.0 (no data): {(all_scores == -1.0).sum()}")
print(f"   Valid Score Records: {len(valid_scores)}")
print()
print("   Statistics (excluding -1.0 values):")
print(f"      Mean: {valid_scores.mean():.2f}%")
print(f"      Median: {valid_scores.median():.2f}%")
print(f"      Std Dev: {valid_scores.std():.2f}")
print(f"      Min: {valid_scores.min():.2f}%")
print(f"      Max: {valid_scores.max():.2f}%")
print()
print("   Distribution:")
perfect = (valid_scores == 100.0).sum()
high = ((valid_scores >= 90) & (valid_scores < 100)).sum()
medium = ((valid_scores >= 50) & (valid_scores < 90)).sum()
low = (valid_scores < 50).sum()
print(f"      Perfect (100%): {perfect} ({perfect/len(valid_scores)*100:.1f}%)")
print(f"      High (90-99%): {high} ({high/len(valid_scores)*100:.1f}%)")
print(f"      Medium (50-89%): {medium} ({medium/len(valid_scores)*100:.1f}%)")
print(f"      Low (<50%): {low} ({low/len(valid_scores)*100:.1f}%)")
print()

# Dirty Peers Analysis
print("=" * 80)
print("DIRTY PEERS (Networks Not Filtering)")
print("-" * 80)
print(f"   Mean: {df['dirty'].mean():.2f}")
print(f"   Median: {df['dirty'].median():.2f}")
print(f"   Std Dev: {df['dirty'].std():.2f}")
print(f"   Min: {df['dirty'].min()}")
print(f"   Max: {df['dirty'].max()}")
print()
zero_dirty = (df['dirty'] == 0).sum()
has_dirty = (df['dirty'] > 0).sum()
print(f"   Networks with 0 dirty peers: {zero_dirty} ({zero_dirty/len(df)*100:.1f}%)")
print(f"   Networks with >0 dirty peers: {has_dirty} ({has_dirty/len(df)*100:.1f}%)")
print()

# Networks with most dirty peers
if has_dirty > 0:
    print("   Top 5 Networks by Dirty Peers:")
    top5_dirty = df.nlargest(5, 'dirty')[['name', 'dirty', 'total', 'verdict']]
    for idx, row in top5_dirty.iterrows():
        pct = (row['dirty'] / row['total'] * 100) if row['total'] > 0 else 0
        print(f"      {row['dirty']:2d}/{row['total']:2d} ({pct:5.1f}%) - {row['name'][:40]}")
print()

# Cross-tabulation Analysis
print("=" * 80)
print("CROSS-TABULATION: VERDICT BY COUNTRY")
print("-" * 80)
crosstab = pd.crosstab(df['cc'], df['verdict'])
print(crosstab)
print()

print("=" * 80)
print("SUMMARY COMPLETE")
print("=" * 80)
