import json
with open('data/downstream_graph.json') as f:
    graph = json.load(f)

asns = [64073, 55850]
results = {asn: [] for asn in asns}
for p, customers in graph.items():
    for asn in asns:
        if asn in customers:
            results[asn].append(p)

for asn, providers in results.items():
    print(f"Providers of {asn}: {providers}")
