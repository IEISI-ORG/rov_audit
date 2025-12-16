# Processing Full BGP Table for AS Relationship Analysis

Complete guide to downloading and analyzing BGP routing data to calculate left/right (upstream/downstream) AS relationships.

## Quick Start

### 1. Download Latest BGP Table Dump

```bash
# Download from RIPE RIS (single collector)
wget http://data.ris.ripe.net/rrc00/latest-bview.gz

# Or download from a specific time (format: YYYY.MM)
wget https://data.ris.ripe.net/rrc00/2024.12/bview.20241215.0000.gz

# File sizes: ~200-400 MB compressed, ~2-4 GB uncompressed
```

**Available collectors:** rrc00, rrc01, rrc02, ... rrc26 (see [full list](https://ris.ripe.net/docs/route-collectors/))

### 2. Install BGP Parser Tools

```bash
# Option 1: bgpdump (C, fast, traditional)
git clone https://github.com/RIPE-NCC/bgpdump.git
cd bgpdump
./bootstrap.sh
make
sudo make install

# Option 2: bgpscanner (C, fastest)
# Download from https://isolario.it/software.php

# Option 3: BGPKit monocle (Rust, modern)
cargo install monocle

# Option 4: Python (easiest for analysis)
pip install mrtparse
pip install pybgpstream
```

### 3. Parse and Extract AS Paths

```bash
# Using bgpdump - outputs machine-readable format
bgpdump -m latest-bview.gz > bgp-table.txt

# Output format:
# TABLE_DUMP2|timestamp|B|peer_ip|peer_as|prefix|as_path|origin|...
# Example:
# TABLE_DUMP2|1702742400|B|80.77.16.114|34549|1.0.0.0/24|34549 13335|IGP|...
```

## Python Script: Calculate Left/Right Relationships

```python
#!/usr/bin/env python3
"""
Process BGP table dump to calculate AS neighbor relationships.
Determines "left" (upstream) and "right" (downstream) neighbors for each ASN.
"""

import gzip
import sys
from collections import defaultdict
from typing import Dict, Set, Tuple

def parse_as_path(path_str: str) -> list:
    """Parse AS path string, handling AS sets and removing duplicates."""
    asns = []
    for segment in path_str.split():
        # Remove AS sets (curly braces) and take first ASN
        segment = segment.strip('{}')
        if segment.isdigit():
            asns.append(int(segment))
    
    # Remove consecutive duplicates (AS path prepending)
    deduped = []
    prev = None
    for asn in asns:
        if asn != prev:
            deduped.append(asn)
            prev = asn
    
    return deduped

def process_bgp_dump(filename: str) -> Dict[int, Dict[str, Set[int]]]:
    """
    Process BGP dump and extract AS relationships.
    
    Returns dict: {asn: {'left': set(), 'right': set()}}
    where 'left' = upstream/providers, 'right' = downstream/customers
    """
    relationships = defaultdict(lambda: {'left': set(), 'right': set()})
    
    open_func = gzip.open if filename.endswith('.gz') else open
    
    with open_func(filename, 'rt') as f:
        for line_num, line in enumerate(f, 1):
            if line_num % 100000 == 0:
                print(f"Processed {line_num:,} lines...", file=sys.stderr)
            
            parts = line.strip().split('|')
            if len(parts) < 7 or parts[0] != 'TABLE_DUMP2':
                continue
            
            # Extract AS path (field 6)
            as_path_str = parts[6]
            as_path = parse_as_path(as_path_str)
            
            if len(as_path) < 2:
                continue
            
            # For each ASN in the path, record its neighbors
            for i, asn in enumerate(as_path):
                # Left neighbors (upstream - earlier in path)
                if i > 0:
                    relationships[asn]['left'].add(as_path[i-1])
                
                # Right neighbors (downstream - later in path)
                if i < len(as_path) - 1:
                    relationships[asn]['right'].add(as_path[i+1])
    
    return relationships

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_bgp.py <bgpdump-output.txt>")
        sys.exit(1)
    
    filename = sys.argv[1]
    print(f"Processing {filename}...", file=sys.stderr)
    
    relationships = process_bgp_dump(filename)
    
    print(f"\nProcessed {len(relationships)} ASNs", file=sys.stderr)
    print("\nAS Relationship Summary:\n")
    print("ASN,Left_Count,Right_Count,Total_Neighbors")
    
    # Sort by total neighbor count
    sorted_asns = sorted(
        relationships.items(),
        key=lambda x: len(x[1]['left']) + len(x[1]['right']),
        reverse=True
    )
    
    for asn, neighbors in sorted_asns[:50]:  # Top 50
        left_count = len(neighbors['left'])
        right_count = len(neighbors['right'])
        total = left_count + right_count
        print(f"AS{asn},{left_count},{right_count},{total}")

if __name__ == '__main__':
    main()
```

## Alternative: Using BGPStream Python Library

```python
#!/usr/bin/env python3
"""Process BGP data using pybgpstream."""

import pybgpstream

# Initialize stream
stream = pybgpstream.BGPStream(
    from_time="2024-12-15 00:00:00",
    until_time="2024-12-15 00:05:00",
    collectors=["rrc00"],
    record_type="ribs"
)

relationships = {}

for rec in stream.records():
    for elem in rec:
        if elem.type != "R":  # RIB entry
            continue
        
        as_path = elem.fields.get("as-path", "").split()
        
        for i, asn in enumerate(as_path):
            if asn not in relationships:
                relationships[asn] = {'left': set(), 'right': set()}
            
            if i > 0:
                relationships[asn]['left'].add(as_path[i-1])
            if i < len(as_path) - 1:
                relationships[asn]['right'].add(as_path[i+1])

# Analyze Cogent (AS174)
cogent = relationships.get('174', {})
print(f"AS174 (Cogent) - Left: {len(cogent.get('left', []))}, "
      f"Right: {len(cogent.get('right', []))}")
```

## Option 2: Use CAIDS Relationship Inference

For a more sophisticated approach, use **CAIDA's AS Relationships** dataset which infers customer-provider, peer-to-peer, and sibling relationships:

```bash
# Download CAIDA AS relationships (updated monthly)
# Requires CAIDA account: https://www.caida.org/catalog/datasets/as-relationships/

wget https://publicdata.caida.org/datasets/as-relationships/serial-2/20241201.as-rel.txt.bz2
bunzip2 20241201.as-rel.txt.bz2

# Format: <provider-as>|<customer-as>|-1  (provider-to-customer)
#         <peer-as>|<peer-as>|0           (peer-to-peer)
```

**CAIDA's algorithm** analyzes the full BGP table and valley-free routing to infer:
- **-1**: Provider-to-Customer (upstream-downstream)
- **0**: Peer-to-Peer (settlement-free peering)
- **1**: Sibling-to-Sibling (same organization)

## Option 3: Load into Database for Analysis

### Using ClickHouse (Recommended for large-scale analysis)

```bash
# Install monocle and mrt-downloader
cargo install monocle
pip install mrt-downloader

# Download dumps
mrt-downloader ~/bgp-data 2024-12-15T00:00 2024-12-15T00:01 \
    --rib-only --project ris --collector rrc00

# Parse with monocle and import to ClickHouse
monocle parse ~/bgp-data/*.gz --output psv | \
    clickhouse-client --query "INSERT INTO bgp_rib FORMAT TSV"

# Query AS relationships
SELECT 
    arrayElement(splitByString(' ', as_path), 1) as asn,
    count() as prefix_count,
    uniqExact(arrayElement(splitByString(' ', as_path), 2)) as neighbor_count
FROM bgp_rib
GROUP BY asn
ORDER BY prefix_count DESC
LIMIT 50;
```

## Understanding the Data

### AS Path Example

```
Prefix: 1.1.1.0/24
AS Path: 34549 13335
         ↑     ↑
       Peer  Origin (Cloudflare)
```

**From AS34549's perspective:**
- **Right neighbor**: AS13335 (customer/downstream - receives route)

**From AS13335's perspective:**
- **Left neighbor**: AS34549 (provider/upstream - provides route)

### Why Cogent Shows Many "Left" Neighbors

1. **Peering disputes** force traffic through intermediaries
2. **Selective depeering** means they're not truly settlement-free with all Tier 1s
3. **Measurement artifacts** - some "left" relationships might be:
   - Paths through other networks due to lack of direct peering
   - Multi-hop paths that don't reflect direct business relationships

## Data Sources Comparison

| Source | Update Frequency | Size | Best For |
|--------|-----------------|------|----------|
| RIPE RIS dumps | Every 8 hours | ~300MB | Real-time analysis |
| RouteViews dumps | Every 2 hours | ~400MB | Alternative view |
| CAIDA AS-Relationships | Monthly | ~5MB | Business relationships |
| RIPE ASN-neighbours API | Real-time | N/A | Quick single-ASN lookup |

## Processing Performance

- **Single dump**: ~2-5 minutes to parse
- **Full table size**: ~1.2M prefixes, ~70k active ASNs
- **Memory requirements**: ~2-4 GB for Python dict approach
- **Disk space**: ~500 MB per dump (compressed)

## Next Steps

1. **Compare multiple collectors** (rrc00, rrc01, etc.) for better coverage
2. **Track changes over time** by processing daily dumps
3. **Cross-reference with CAIDA** for business relationship validation
4. **Analyze specific ASNs** to understand their connectivity patterns

## Resources

- **MRT Format Spec**: [RFC 6396](https://datatracker.ietf.org/doc/html/rfc6396)
- **RIPE RIS Docs**: https://ris.ripe.net/docs/
- **CAIDA Tools**: https://www.caida.org/catalog/software/
- **BGPStream**: https://bgpstream.caida.org/

