import json
import sys

if len(sys.argv) < 2:
    print('usage: %s filen_name' % sys.argv[0])
    sys.exit()

with open(sys.argv[1], 'r') as json_file:
    j = json.load(json_file)

rep = j['vulgateAuditReport']
print('Vulnerables CPEs:')
vuls = rep['vulnerableCpes']
for vul in vuls:
    if 'cves' not in vul:
        continue
    cves = vul['cves']
    for cve in cves:
        cve_id = cve['cveId']
        print(cve_id)

