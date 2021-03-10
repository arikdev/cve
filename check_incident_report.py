import json
import sys

if len(sys.argv) < 3:
    print('usage: %s incident_report vulgate_report' % sys.argv[0])
    sys.exit()

vulgate = {}
vulgate['reported'] = []
vulgate['ignored'] = []
vulgate['falsePositive'] = {}

with open(sys.argv[2], 'r') as vulgate_file:
    j = json.load(vulgate_file)

rep = j['vulgateAuditReport']
vuls = rep['vulnerableCpes']
for vul in vuls:
    if 'cves' not in vul:
        continue
    if 'kernel' not in vul['upstream']:
        continue
    cves = vul['cves']
    for cve in cves:
        cve_id = cve['cveId']
        vulgate['reported'].append(cve_id)
    for i in vul['userIgnoredCves']:
        cve_id = i['cveId']
        vulgate['ignored'].append(cve_id)
    for i in vul['autodetectedFalsePositiveCves']:
        cves = vul['cves']
        cve_id = i['cveId']
        vulgate['falsePositive'][cve_id] =  i['justificationForFalsePositive']

ok = 0
ignore = 0
falsePositive = 0
falseNegative = 0
missing = 0


my_cves = []

with open(sys.argv[1], 'r') as incidents_file:
    first = True
    for line in incidents_file:
        if first:
            first = False
            continue
        tokens = line.split(',')
        cve = tokens[1]
        my_cves.append(cve)
        if cve in vulgate['reported']:
            print(cve + ' OK')
            ok += 1
            continue
        if cve in vulgate['ignored']:
            print(cve + ' IGNORE')
            ignore = 1
            continue
        if cve in vulgate['falsePositive']:
            print(cve + ' FLASE POSITIVE ' +  vulgate['falsePositive'][cve]  )
            falsePositive += 1
            continue

print('----------------------------------------------')
for vul in vulgate['reported']:
    if vul not in my_cves:
        print(vul + ' Not reported')
        falseNegative += 1

print('====================  SUMMARY ============================================================')
print('OK: ' + str(ok) + ' FALSENEGATIVE: ' + str(falseNegative) + ' FALSEPOSITIVE: ' + str(falsePositive))
