import json
with open('data/downstream_graph.json') as f:
    graph = json.load(f)

is_customer = 9500 in graph.get('64073', [])
print(f"Is 9500 a customer of 64073? {is_customer}")
