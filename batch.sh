
python3 rov_global_audit_v12.py

python3 build_topology_v2.py

python3 analyze_cone_quality.py

###grep 'Unknown,XX' cone_quality_report.csv | csvcut -c 1 | xargs -n1 python3 scrape_single_asn_v2.py

python3 update_apnic_data.py rov_audit_v12.csv

python3 find_missing_data.py --save

###while read asn; do python3 scrape_single_asn_v2.py $asn; done < missing_targets.txt

