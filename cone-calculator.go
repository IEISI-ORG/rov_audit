package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config
const (
	// How much bigger must a provider be to be considered a provider?
	// 4.0 means Provider must have 4x more neighbors than Customer.
	// If ratio is < 4.0, we assume they are Peers (no cone).
	PROVIDER_RATIO = 4.0
)

type ASNInfo struct {
	ASN       string
	Degree    int            // Total unique neighbors
	Customers map[string]bool // Only confirmed downstream customers
	Cone      int            // Final calculated cone size
}

func main() {
	inputFile := flag.String("input", "", "Input relationships.csv from bgp-extractor")
	outputFile := flag.String("output", "as_rank_caida.csv", "Output file")
	topN := flag.Int("top", 50, "Number of top ASNs to display")
	flag.Parse()

	if *inputFile == "" {
		log.Fatal("Usage: cone-calculator-v2 -input relationships.csv")
	}

	start := time.Now()

	// 1. LOAD & CALCULATE DEGREE
	// We need to know everyone's size before we can determine relationships
	fmt.Println("[1/3] Loading Data & Calculating Node Degrees...")
	adjacency, degrees := loadAdjacency(*inputFile)
	fmt.Printf("      Loaded %d unique ASNs.\n", len(degrees))

	// 2. INFER RELATIONSHIPS (The CAIDA Logic)
	// We only keep links where Provider is significantly larger than Customer
	fmt.Println("[2/3] Inferring Provider-Customer Relationships (Valley-Free)...")
	nodes := buildHierarchy(adjacency, degrees)
	
	// 3. CALCULATE CONES (Recursive)
	fmt.Println("[3/3] Calculating Customer Cones...")
	calculateCones(nodes)

	// 4. OUTPUT
	writeOutput(*outputFile, nodes, *topN)
	
	fmt.Printf("\nDone in %v. Results saved to %s\n", time.Since(start), *outputFile)
}

func loadAdjacency(filename string) (map[string][]string, map[string]int) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Skip header if present
	row1, _ := reader.Read()
	if !strings.HasPrefix(row1[0], "AS") && !isNumeric(row1[0]) {
		// It's a header, continue
	} else {
		// It's data, seek back (simplified: just re-open or handle logic)
		// For this snippet, assuming standard header present or we skip first row
	}

	rows, err := reader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	adj := make(map[string][]string)
	degreeSet := make(map[string]map[string]bool) // Use set to count unique neighbors

	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		as1, as2 := row[0], row[1]

		// Init sets
		if degreeSet[as1] == nil { degreeSet[as1] = make(map[string]bool) }
		if degreeSet[as2] == nil { degreeSet[as2] = make(map[string]bool) }

		// Record Adjacency (Undirected at this stage)
		degreeSet[as1][as2] = true
		degreeSet[as2][as1] = true
		
		// Store raw link for later processing
		adj[as1] = append(adj[as1], as2)
	}

	// Finalize Degrees
	degrees := make(map[string]int)
	for asn, neighbors := range degreeSet {
		degrees[asn] = len(neighbors)
	}

	return adj, degrees
}

func buildHierarchy(adj map[string][]string, degrees map[string]int) map[string]*ASNInfo {
	nodes := make(map[string]*ASNInfo)
	
	// Init Nodes
	for asn, deg := range degrees {
		nodes[asn] = &ASNInfo{
			ASN:       asn,
			Degree:    deg,
			Customers: make(map[string]bool),
		}
	}

	// Apply Logic
	peersCount := 0
	custCount := 0

	// We iterate the adjacency map. 
	// adj contains raw observed links. We need to decide who is the parent.
	seen := make(map[string]bool) // Dedupe links

	for as1, neighbors := range adj {
		for _, as2 := range neighbors {
			linkKey := as1 + "-" + as2
			if as1 > as2 { linkKey = as2 + "-" + as1 }
			if seen[linkKey] { continue }
			seen[linkKey] = true

			d1 := degrees[as1]
			d2 := degrees[as2]

			// === THE FILTER LOGIC ===
			
			// Case 1: AS1 is much bigger -> AS1 is Provider
			if float64(d1) > float64(d2)*PROVIDER_RATIO {
				nodes[as1].Customers[as2] = true
				custCount++
			
			// Case 2: AS2 is much bigger -> AS2 is Provider
			} else if float64(d2) > float64(d1)*PROVIDER_RATIO {
				nodes[as2].Customers[as1] = true
				custCount++
			
			// Case 3: Similar sizes -> Peering (Ignore for Cone)
			} else {
				peersCount++
			}
		}
	}

	fmt.Printf("      Inferred %d Customer Links and %d Peering Links.\n", custCount, peersCount)
	return nodes
}

func calculateCones(nodes map[string]*ASNInfo) {
	// Memoization cache for cone sizes
	// But actually, we need the SET of ASNs to handle overlap correctly
	// Optimization: Since we just want the COUNT, but A->B and A->C->B shouldn't double count B.
	// For massive graphs, we usually implement a "Cone Set" cache.
	
	coneCache := make(map[string]map[string]bool)

	var getCone func(string) map[string]bool
	getCone = func(asn string) map[string]bool {
		if cache, ok := coneCache[asn]; ok {
			return cache
		}

		node := nodes[asn]
		myCone := make(map[string]bool)
		
		// Add direct customers
		for custASN := range node.Customers {
			myCone[custASN] = true
			
			// recurse
			subCone := getCone(custASN)
			for sub := range subCone {
				myCone[sub] = true
			}
		}

		coneCache[asn] = myCone
		return myCone
	}

	// Calculate for all
	// We sort processing by Degree (Ascending) to populate leaf caches first? 
	// No, calculating root requires children. DFS handles this naturally.
	
	// Just iterate everyone to ensure stats are populated
	// Doing this in parallel would be faster for massive sets, but serial is safe.
	count := 0
	total := len(nodes)
	
	// To speed up, we only really care about calculating the big ones, 
	// but to get the big ones right we need the small ones.
	
	for asn := range nodes {
		c := getCone(asn)
		nodes[asn].Cone = len(c)
		
		count++
		if count%5000 == 0 {
			fmt.Printf("\r      Calculated %d/%d...", count, total)
		}
	}
	fmt.Println()
}

func writeOutput(filename string, nodes map[string]*ASNInfo, topN int) {
	// Convert map to slice for sorting
	var list []*ASNInfo
	for _, n := range nodes {
		list = append(list, n)
	}

	// Sort by Cone Size
	sort.Slice(list, func(i, j int) bool {
		return list[i].Cone > list[j].Cone
	})

	// Print Top N
	fmt.Printf("\n=== TOP %d ASNs BY CONE SIZE ===\n", topN)
	fmt.Printf("%-6s %-10s %-12s %-12s %-10s\n", "Rank", "ASN", "Cone", "Degree", "Ratio")
	fmt.Println("-------------------------------------------------------")

	for i := 0; i < topN && i < len(list); i++ {
		n := list[i]
		ratio := 0.0
		if len(n.Customers) > 0 {
			ratio = float64(n.Cone) / float64(len(n.Customers))
		}
		fmt.Printf("%-6d AS%-9s %-12d %-12d %.1fx\n", 
			i+1, n.ASN, n.Cone, n.Degree, ratio)
	}

	// Write CSV
	file, err := os.Create(filename)
	if err != nil { log.Fatal(err) }
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write([]string{"Rank", "ASN", "Cone_Size", "Node_Degree", "Direct_Customers"})

	for i, n := range list {
		writer.Write([]string{
			strconv.Itoa(i + 1),
			n.ASN,
			strconv.Itoa(n.Cone),
			strconv.Itoa(n.Degree),
			strconv.Itoa(len(n.Customers)),
		})
	}
	writer.Flush()
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}