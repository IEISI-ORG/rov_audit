import rov_utils
rov_set, cf_set, apnic_map = rov_utils.load_security_status()
target_asns = [6461, 4637, 1299, 174, 55850, 64073]
for asn in target_asns:
    in_rov = asn in rov_set
    in_cf = asn in cf_set
    score = apnic_map.get(asn, -1)
    print(f"AS{asn}: ROV_TAG={in_rov}, CF_SAFE={in_cf}, APNIC_SCORE={score}")
