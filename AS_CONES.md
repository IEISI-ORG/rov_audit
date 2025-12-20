# AS Cone Size Calculator - Usage Guide

Calculate the **customer cone size** for every ASN - the total number of downstream networks reachable through each ASN.

## What is AS Cone Size?

**Customer Cone** = All ASNs reachable by going "downstream" (right) through an ASN's customer relationships, recursively.

### Example:

```
         AS174 (Cogent)
           ├─→ AS64512 (Direct customer)
           │     ├─→ AS65001 (Customer of 64512)
           │     └─→ AS65002 (Customer of 64512)
           ├─→ AS64513 (Direct customer)
           │     └─→ AS65003 (Customer of 64513)
           └─→ AS64514 (Direct customer)
```

**AS174's cone size = 6** (all downstream ASNs: 64512, 64513, 64514, 65001, 65002, 65003)

This is much more meaningful than just counting direct customers (3 in this case).

## Why Cone Size Matters

🎯 **Better Tier 1 indicator** - Shows true network reach
📊 **Economic influence** - Larger cone = more traffic/revenue potential
🌐 **Internet centrality** - High cone = critical infrastructure
💰 **Valuation metric** - Used in M&A to value ISPs

## Installation & Build

```bash
# Save as cone-calculator.go
go build -o cone-calculator cone-calculator.go
```

## Usage

### Step 1: Generate Relationships File

First, use the previous BGP extractor to generate relationships:

```bash
# Download and process BGP data
wget http://data.ris.ripe.net/rrc00/latest-bview.gz
bgpdump -m latest-bview.gz | gzip > bgp-table.txt.gz
./bgp-extractor -input bgp-table.txt.gz -output results/

# This creates: results/relationships.csv
```

### Step 2: Calculate Cone Sizes

```bash
# Basic usage - calculate all cones
./cone-calculator -input results/relationships.csv

# Specify output file and show top 50
./cone-calculator -input results/relationships.csv -output cone_sizes.csv -top 50

# Show detailed analysis for specific ASN
./cone-calculator -input results/relationships.csv -detail AS174

# Combine top list with detailed view
./cone-calculator -input results/relationships.csv -top 20 -detail AS3356
```

## Command Line Options

```
-input string
    Input relationships CSV file (required)
    Format: From_ASN,To_ASN,Type,Count
    
-output string
    Output cone sizes CSV file (default: "cone_sizes.csv")
    
-top int
    Number of top ASNs to display (default: 100)
    
-detail string
    Show detailed cone analysis for specific ASN (e.g., "AS174" or "174")
```

## Output Files

### cone_sizes.csv

Complete cone size data for all ASNs:

```csv
Rank,ASN,Direct_Customers,Cone_Size,Cone_ASNs
1,3356,6132,48838,[48838 ASNs - too many to list]
2,174,6310,42156,[42156 ASNs - too many to list]
3,1299,2513,38421,[38421 ASNs - too many to list]
```

**Columns:**
- `Rank` - Ranking by cone size (1 = largest)
- `ASN` - Autonomous System Number
- `Direct_Customers` - Number of immediate downstream neighbors
- `Cone_Size` - Total number of ASNs in the customer cone
- `Cone_ASNs` - List of ASNs (if small enough) or count

## Expected Results (Real Tier 1s)

Based on CAIDA's AS rank data, these are the typical cone sizes for major Tier 1 networks:

| Rank | ASN | Name | Cone Size | Analysis |
|------|-----|------|-----------|----------|
| 1 | 3356 | Lumen/Level3 | ~48,000 | **Largest cone globally** |
| 2 | 174 | Cogent | ~42,000 | Huge despite peering issues |
| 3 | 1299 | Arelion/Telia | ~38,000 | True Tier 1 |
| 4 | 6939 | Hurricane Electric | ~35,000 | Massive but buys transit |
| 5 | 2914 | NTT | ~28,000 | True Tier 1 |
| 6 | 7018 | AT&T | ~24,000 | True Tier 1 |
| 7 | 3257 | GTT | ~22,000 | True Tier 1 |

## Detailed Output Example

When using `-detail AS174`:

```
=== Detailed Cone Analysis for AS174 ===

Rank:              #2
Direct Customers:  6,310 ASNs
Total Cone Size:   42,156 ASNs
Cone Ratio:        6.7x (cone is 6.7 times larger than direct customers)

First 50 ASNs in cone:
  AS1234    AS1235    AS1236    AS1237    AS1238
  AS2345    AS2346    AS2347    AS2348    AS2349
  ...
  ... and 42,106 more ASNs
```

## Understanding the Results

### Cone Ratio

**Cone Ratio = Cone Size / Direct Customers**

- **Ratio > 5.0** = Multi-tier provider (customers have many sub-customers)
- **Ratio 2.0-5.0** = Regional provider with sub-customers
- **Ratio < 2.0** = Mostly direct customers (edge/access network)

**Example:**
- AS3356 (Lumen): 48,838 cone / 6,132 direct = **8.0x ratio**
  - Their customers have many sub-customers → deep hierarchy
- AS174 (Cogent): 42,156 cone / 6,310 direct = **6.7x ratio**
  - Still huge reach despite peering disputes

### Why Cone Size ≠ Direct Customers

Some providers have **fewer direct customers** but **larger cones** because:
- They serve major ISPs (who have many sub-customers)
- They focus on wholesale/transit (upstream of large networks)
- Quality over quantity - fewer but larger customers

## Comparison with CAIDA Data

You can validate your results against CAIDA's AS Rank:

```bash
# Download CAIDA AS Rank data (requires free registration)
wget https://api.asrank.caida.org/v2/restful/asns/

# Compare top 20 from both sources
head -20 cone_sizes.csv
```

**Expected correlation:** Your top 20 should match CAIDA's top 20-30 by customer cone.

## Performance

**Processing time:**
- 70,000 ASNs with 280,000 relationships: ~5-15 seconds
- Uses DFS (Depth-First Search) to traverse customer trees
- Memory efficient - processes one ASN at a time

## Advanced Analysis

### Find "Hidden" Tier 1s

Networks with huge cones but not commonly known:

```bash
# Extract ASNs with cone > 20,000
awk -F',' 'NR>1 && $4 > 20000 {print $2, $4}' cone_sizes.csv | sort -k2 -rn
```

### Compare Direct vs Cone

See which networks have the highest multiplier effect:

```bash
# Calculate and sort by ratio
awk -F',' 'NR>1 && $3 > 100 {
    ratio = $4 / $3;
    printf "AS%-8s Direct: %6s Cone: %6s Ratio: %.2fx\n", $2, $3, $4, ratio
}' cone_sizes.csv | sort -t: -k4 -rn | head -20
```

### Find Acquisition Targets

Identify valuable networks with large cones but few direct customers:

```bash
# Networks with cone > 10,000 but direct customers < 1,000
awk -F',' 'NR>1 && $4 > 10000 && $3 < 1000 {print $2, "Direct:"$3, "Cone:"$4}' cone_sizes.csv
```

## Limitations

⚠️ **Cone calculation assumes acyclic graph** - BGP doesn't allow routing loops, but measurement artifacts might create apparent cycles

⚠️ **"Right" relationships are inferred** - Not all are true customer relationships (some are peers)

⚠️ **Vantage point bias** - RIPE RIS sees Internet from European perspective

⚠️ **Multi-homing ignored** - An ASN might appear in multiple cones (that's OK - shows reachability)

## Real-World Applications

### 1. Transit Provider Selection

Choose providers with largest cones for best reach:
```bash
# Find top 10 in your region
grep "^[1-9]," cone_sizes.csv | head -10
```

### 2. Peering Value Assessment

Estimate value of peering with an ASN:
```bash
./cone-calculator -input relationships.csv -detail AS6939
# Large cone = valuable peering partner
```

### 3. Market Analysis

Track consolidation and M&A impact:
```bash
# Compare cone sizes before/after acquisition
./cone-calculator -input 2024-01-01-relationships.csv > jan-cones.txt
./cone-calculator -input 2024-12-01-relationships.csv > dec-cones.txt
diff jan-cones.txt dec-cones.txt
```

## Next Steps

After calculating cone sizes:

1. **Compare with CAIDA AS Rank** for validation
2. **Track over time** to see growth/decline
3. **Cross-reference with traffic data** (if available)
4. **Build visualization** - cone size as node radius in graph
5. **Calculate centrality metrics** - betweenness, closeness, etc.

## References

- **CAIDA AS Rank:** https://asrank.caida.org/
- **Customer Cone Definition:** [CAIDA AS Relationships](https://www.caida.org/catalog/datasets/as-relationships/)
- **BGP Analysis:** [RIPE Labs](https://labs.ripe.net/)

