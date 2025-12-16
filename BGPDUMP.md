# BGPdump -m Format Reference

Complete field-by-field breakdown of the `bgpdump -m` output format for parsing BGP routing data.

## Format Overview

The `-m` flag outputs **one line per entry** with pipe-delimited fields and Unix timestamps. This is the most machine-parseable format.

```bash
bgpdump -m latest-bview.gz > bgp-table.txt
```

## RIB Entry Format (TABLE_DUMP_V2)

For routing table snapshots (RIB dumps), each line follows this format:

```
TABLE_DUMP2|unix_timestamp|B|peer_ip|peer_asn|prefix|as_path|origin|next_hop|local_pref|med|community|atomic_aggregate|aggregator
```

### Field-by-Field Breakdown

| Position | Field | Description | Example |
|----------|-------|-------------|---------|
| 0 | **Type** | Always `TABLE_DUMP2` for RIB entries | `TABLE_DUMP2` |
| 1 | **Timestamp** | Unix timestamp when dump was created | `1702742400` |
| 2 | **Subtype** | `B` for IPv4, `B6` for IPv6 | `B` |
| 3 | **Peer IP** | IP address of the BGP peer reporting this route | `80.77.16.114` |
| 4 | **Peer ASN** | AS number of the peer | `34549` |
| 5 | **Prefix** | IP prefix being announced | `1.0.0.0/24` |
| 6 | **AS Path** | Space-separated list of ASNs in the path | `34549 13335` |
| 7 | **Origin** | BGP origin type: `IGP`, `EGP`, or `INCOMPLETE` | `IGP` |
| 8 | **Next Hop** | Next hop IP address | `80.77.16.114` |
| 9 | **Local Pref** | Local preference value (optional, may be 0) | `100` |
| 10 | **MED** | Multi-Exit Discriminator (optional) | `0` |
| 11 | **Community** | BGP communities (space-separated) | `34549:1000 34549:2000` |
| 12 | **Atomic Aggregate** | `AG` if set, empty otherwise | `AG` or `` |
| 13 | **Aggregator** | Aggregator ASN and IP if present | `13335 1.1.1.1` |

### Real Example

```
TABLE_DUMP2|1702742400|B|80.77.16.114|34549|1.0.0.0/24|34549 13335|IGP|80.77.16.114|100|0|34549:1000|AG|
```

**Interpretation:**
- Prefix `1.0.0.0/24` 
- Learned from peer AS34549 at IP 80.77.16.114
- AS Path: `34549 → 13335` (originated by Cloudflare AS13335)
- Origin: IGP
- Has community tags and atomic aggregate flag

## BGP UPDATE Format

For BGP update messages (route changes), the format is:

```
BGP4MP|unix_timestamp|A|peer_ip|peer_asn|prefix|as_path|origin|next_hop|local_pref|med|community|atomic_aggregate|aggregator
```

Or for withdrawals:

```
BGP4MP|unix_timestamp|W|peer_ip|peer_asn|prefix
```

| First char after timestamp | Meaning |
|---------------------------|---------|
| `A` | Announcement (new route) |
| `W` | Withdrawal (route removed) |

### Real UPDATE Examples

**Announcement:**
```
BGP4MP|1702742405|A|192.0.2.1|174|8.8.8.0/24|174 15169|IGP|192.0.2.1|||174:1000||
```

**Withdrawal:**
```
BGP4MP|1702742410|W|192.0.2.1|174|8.8.8.0/24
```

## Special Cases & Edge Cases

### AS Path with AS Sets

AS sets appear in curly braces (multiple ASNs that could be the origin):

```
TABLE_DUMP2|1702742400|B|1.2.3.4|174|10.0.0.0/8|174 {701,702,703}|IGP|1.2.3.4||||
```

**Parsing tip:** When analyzing relationships, you may want to:
1. Skip AS sets entirely, or
2. Take the first ASN from the set

### AS Path Prepending

The same ASN may appear multiple times consecutively for traffic engineering:

```
TABLE_DUMP2|1702742400|B|1.2.3.4|174|192.0.2.0/24|174 64512 64512 64512 64512|IGP|1.2.3.4||||
```

**Parsing tip:** Remove consecutive duplicates before analyzing left/right relationships:
```python
def deduplicate_as_path(path):
    asns = path.split()
    deduped = []
    prev = None
    for asn in asns:
        if asn != prev:
            deduped.append(asn)
            prev = asn
    return deduped
```

### IPv6 Entries

IPv6 entries use subtype `B6`:

```
TABLE_DUMP2|1702742400|B6|2001:db8::1|13335|2606:4700::/32|13335|IGP|2001:db8::1||||
```

### Empty Fields

Fields may be empty (represented by nothing between pipes):

```
TABLE_DUMP2|1702742400|B|1.2.3.4|174|10.0.0.0/8|174|IGP|1.2.3.4|0|0|||
                                                                    ↑ ↑ ↑
                                                        no community or aggregator
```

## Python Parsing Example

```python
#!/usr/bin/env python3
"""Parse bgpdump -m output."""

import gzip
import sys

def parse_rib_entry(line):
    """Parse a TABLE_DUMP2 line into a dict."""
    fields = line.strip().split('|')
    
    if len(fields) < 8:
        return None
    
    entry_type = fields[0]
    if entry_type != 'TABLE_DUMP2':
        return None
    
    return {
        'type': fields[0],
        'timestamp': int(fields[1]),
        'subtype': fields[2],  # B or B6
        'peer_ip': fields[3],
        'peer_asn': int(fields[4]),
        'prefix': fields[5],
        'as_path': fields[6].split(),  # Split into list
        'origin': fields[7],
        'next_hop': fields[8] if len(fields) > 8 else '',
        'local_pref': int(fields[9]) if len(fields) > 9 and fields[9] else 0,
        'med': int(fields[10]) if len(fields) > 10 and fields[10] else 0,
        'community': fields[11].split() if len(fields) > 11 and fields[11] else [],
        'atomic_aggregate': fields[12] if len(fields) > 12 else '',
        'aggregator': fields[13] if len(fields) > 13 else ''
    }

def parse_update(line):
    """Parse a BGP4MP update line."""
    fields = line.strip().split('|')
    
    if len(fields) < 6:
        return None
    
    entry_type = fields[0]
    if entry_type != 'BGP4MP':
        return None
    
    action = fields[2]  # A = announcement, W = withdrawal
    
    result = {
        'type': fields[0],
        'timestamp': int(fields[1]),
        'action': action,
        'peer_ip': fields[3],
        'peer_asn': int(fields[4]),
        'prefix': fields[5]
    }
    
    if action == 'A' and len(fields) > 6:
        result['as_path'] = fields[6].split()
        result['origin'] = fields[7] if len(fields) > 7 else ''
    
    return result

# Example usage
with gzip.open('bgp-table.txt.gz', 'rt') as f:
    for line in f:
        entry = parse_rib_entry(line)
        if entry:
            print(f"Prefix: {entry['prefix']}, AS Path: {' -> '.join(entry['as_path'])}")
```

## Quick Extraction with Command Line

### Get all prefixes originated by an ASN

```bash
# Find all prefixes where AS13335 is the origin (rightmost in path)
bgpdump -m latest-bview.gz | grep -E '\|[0-9 ]*13335\|' | cut -d'|' -f6 | sort -u
```

### Count prefixes per ASN

```bash
bgpdump -m latest-bview.gz | awk -F'|' '{
    # Extract AS path (field 7) and get origin ASN (last in path)
    split($7, path, " ");
    origin = path[length(path)];
    count[origin]++;
}
END {
    for (asn in count) {
        print asn, count[asn];
    }
}' | sort -k2 -rn | head -20
```

### Extract AS relationships

```bash
bgpdump -m latest-bview.gz | awk -F'|' '{
    # Field 7 is AS path
    split($7, path, " ");
    for (i = 1; i < length(path); i++) {
        print path[i], path[i+1];
    }
}' | sort -u > as-relationships.txt
```

## Performance Tips

1. **Use awk/cut/grep** for quick filtering before loading into Python
2. **Process line-by-line** - don't load entire file into memory
3. **Filter early** - apply AS/prefix filters before parsing all fields
4. **Compressed I/O** - keep files gzipped and process with `zcat` or `gzip.open()`

## Common Pitfalls

❌ **Don't assume all lines have the same number of fields**
- Optional fields may be missing
- Always check `len(fields)` before accessing

❌ **Don't forget AS sets in paths**
- They appear as `{12345,67890}`
- May need special handling

❌ **Don't ignore IPv6 data**
- Check for subtype `B6`
- IPv6 AS paths are structured identically

❌ **Don't assume consecutive ASNs are different**
- AS path prepending creates duplicates
- Deduplicate before analyzing relationships

## Additional Resources

- **MRT Format Spec:** [RFC 6396](https://datatracker.ietf.org/doc/html/rfc6396)
- **BGPdump Source:** https://github.com/RIPE-NCC/bgpdump
- **RIPE RIS Data:** https://data.ris.ripe.ne

