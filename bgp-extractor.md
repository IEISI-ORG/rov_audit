# Explaining the BGP Extractor: `bgp-extractor.go`

While the `cone-calculator.go` builds the **theoretical** map of who *should* talk to whom, `bgp-extractor.go` is the **observation engine**. It processes real-world BGP data to see what is *actually* happening on the internet.

---

## 1. The Purpose: Converting Binary to Insight
BGP data is shared between researchers and operators using the **MRT (Multi-threaded Routing Toolkit)** format. This is a compact binary format that is unreadable by standard text processors.

`bgp-extractor.go` serves three primary functions:
1.  **Parsing:** It decodes binary MRT files (typically from collectors like RouteViews or RIPE RIS).
2.  **Extraction:** It pulls out the specific attributes needed for an audit: the **IP Prefix** and the **AS-PATH**.
3.  **Normalization:** It cleans up the path data so it can be compared against the Customer Cones.

---

## 2. Key Technical Workflow

### Step A: Handling MRT Records
The script uses the GoBGP library (or similar MRT parsers) to iterate through the dump. It specifically looks for:
*   **TABLE_DUMP_V2:** A snapshot of the entire routing table (RIB).
*   **UPDATE_MESSAGE:** Real-time changes to the routing table.

### Step B: AS-PATH Processing
This is the most critical part of the script. The AS-PATH tells us the route a packet takes. The script looks at the sequence of ASNs:
`[AS-701, AS-1239, AS-15169]`

*   **Origin AS:** The last AS in the list (`AS-15169`). This is the network claiming to "own" the IP space.
*   **Transit ASes:** The ASNs in the middle. These are the networks providing "Transit."

### Step C: Cleaning "Path Prepending"
Operators often use "Path Prepending" (repeating their own ASN multiple times, e.g., `AS-100, AS-100, AS-100`) to make a route look less attractive.
The extractor simplifies this:
*   **Raw Path:** `701, 1239, 1239, 1239, 15169`
*   **Normalized Path:** `701, 1239, 15169`
This normalization is essential because the "Valley-Free" audit only cares about the **unique adjacencies** between networks.

---

## 3. Connecting to the Audit Logic

In the context of the `rov_audit` suite, the extractor provides the "Evidence" for the trial.

| Component | Role | Logic |
| :--- | :--- | :--- |
| **Extractor** | The Witness | "I saw AS-200 announcing a route for AS-500 via AS-100." |
| **Cone Calculator** | The Law | "AS-500 is not in the Customer Cone of AS-100." |
| **The Audit Result** | The Verdict | **Route Leak Detected.** |

---

## 4. Why Use Go for This?
In your talk, it’s worth mentioning why this is written in Go:
1.  **Concurrency:** BGP RIB dumps can contain millions of routes. Go's `goroutines` allow the script to parse these records in parallel.
2.  **Binary Handling:** Go provides excellent low-level control for reading binary streams (like MRT) while maintaining high-level memory safety.
3.  **Speed:** To audit the entire internet in a reasonable timeframe, you need a language that compiles to machine code.

---

## 5. Summary for the Talk

1.  **Observation vs. Theory:** This script captures "Ground Truth" from the global routing table.
2.  **Data Reduction:** It turns a multi-gigabyte binary MRT file into a structured list of Prefix -> AS-Path mappings.
3.  **The "Origin" Focus:** By identifying the last AS in the path, it helps verify if the network originating the prefix is actually the one authorized to do so via ROA (Route Origin Authorization).
4.  **Adjacency Mapping:** The extractor identifies every pair of ASNs that are currently talking to each other, which is the input data used to verify if those relationships follow the "Valley-Free" rules.

---

### Visualizing the Pipeline:
`[MRT Binary File]` —> `[bgp-extractor.go]` —> `[CSV/JSON: Prefix, Path, Origin]` —> `[Audit Engine]`
