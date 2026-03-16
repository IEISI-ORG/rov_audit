# Explaining the Valley-Free Algorithm in `cone-calculator.go`

This document explains the "Valley-Free" principle and how the `cone-calculator.go` script implements it to derive AS (Autonomous System) Customer Cones for BGP auditing.

---

## 1. The "Valley-Free" Principle (Gao-Rexford Model)
In BGP routing, the "Valley-Free" rule is based on the commercial relationships between ISPs. It assumes that no AS will provide transit for traffic that doesn't provide them with revenue.

### The Rules of the Path:
A valid BGP path must follow this specific sequence:
1. **The Uphill:** Zero or more Customer-to-Provider links.
2. **The Top:** (Optional) One Peer-to-Peer link.
3. **The Downhill:** Zero or more Provider-to-Customer links.

**The Golden Rule:** Once a path starts going "Downhill" (Provider to Customer), it can **never** go back "Uphill" (Customer to Provider). 

### What is a "Valley"?
A **Valley** occurs when an AS receives a route from one Provider and announces it to another Provider. 
* **Path:** `Provider A -> AS X -> Provider B`
* **Why it's forbidden:** AS X would be paying both Provider A and Provider B to carry traffic for which it receives no revenue. This is a "Route Leak."

---

## 2. How `cone-calculator.go` Implements the Logic
The script calculates the **Customer Cone** of an AS. A Customer Cone is the set of all ASes reachable from a starting AS by only following "Downhill" links.

### Step A: Filtering Relationships
The code parses CAIDA relationship data. It specifically looks for `relationship == -1`, which represents a **Provider-to-Customer** link.

```go
// Logical representation of the link filtering
if relationship == -1 {
    // We only care about the Downhill direction
    customerMap[providerAS] = append(customerMap[providerAS], customerAS)
}
```

### Step B: Recursive Expansion (Transitive Closure)
To find the full cone, the algorithm doesn't just look at direct customers. It finds the customers of customers, recursively.

1. **Input:** A specific `AS_X`.
2. **Action:** Find all ASes in `customerMap[AS_X]`.
3. **Iteration:** For every new AS found, look up their customers in the map.
4. **Termination:** Stop when no new ASes can be added to the set.

This set of ASes represents the **downward-only** reachability of the starting AS, which is the definition of a Customer Cone in a valley-free environment.

---

## 3. Why this matters for the `rov_audit`
The `rov_audit` tool uses these cones to detect BGP anomalies.

| Scenario | Logic | Result |
| :--- | :--- | :--- |
| **Normal Path** | AS A is in the Customer Cone of AS B. | **Valid** |
| **Route Leak** | AS B announces a route for AS A, but AS A is **not** in AS B's Customer Cone. | **Valley Violation** (Potential Leak) |

By calculating the cone, the script defines the "Commercial Boundary" of an AS. If an AS tries to act as a transit provider for an AS that isn't in its cone, it is likely creating a "Valley" and violating the Gao-Rexford model.

---

## 4. Summary for the Talk
When presenting this code, you can summarize the algorithm in three points:

1. **Directionality:** The script ignores Peer-to-Peer and Customer-to-Provider links because the "Cone" is strictly about who is "below" you in the hierarchy.
2. **Transitivity:** The script performs a graph traversal to ensure that "The customer of my customer is also in my cone."
3. **Policy Enforcement:** The resulting "Cone" data serves as a baseline. In the context of Route Origin Validation (ROV) and Auditing, any route seen on the internet that contradicts this cone is a red flag for a configuration error or a hijack.

---

### Visual Aid for your Presentation:
```text
      [ Tier 1 Provider ]
         /           \
    (Downhill)     (Downhill)
       /               \
 [ Regional ISP ]    [ Regional ISP ]
      /        \          \
  (Downhill) (Downhill)  (Downhill)
    /            \          \
[ Enterprise ] [ Mini-ISP ] [ Customer ]
```
*The `cone-calculator.go` starts at any node and identifies every node reachable below it.*
