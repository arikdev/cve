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

cyb_cves = []

falsePositive = 0
userIgnored = 0
falseNegative = 0
ok = 0
with open(sys.argv[1], 'r') as cyb_file:
    first = True
    for line in cyb_file:
        if first:
            first = False
            #continue
        line = line[:-1]
        tokens = line.split(',')
        cve = tokens[1]
        cyb_cves.append(cve)
        if cve in vulgate['reported']:
            print(cve + ' OK')
            ok += 1
            continue
        if cve in vulgate['ignored']:
            print(cve + ' IGNORE by user')
            userIgnored += 1
            continue
        if cve in vulgate['falsePositive']:
            print(cve + ' FALSE POSITIVE ' +  vulgate['falsePositive'][cve]  )
            falsePositive += 1
            continue

print('\nNot reported :')
print('----------------------------------------------')
for vul in vulgate['reported']:
    if vul not in cyb_cves:
        print(vul + ' Not reported')
        falseNegative += 1

print('\n====================  SUMMARY ============================================================')
print('OK: ' + str(ok) + ' FALSENEGATIVE: ' + str(falseNegative) + ' FALSEPOSITIVE: ' + str(falsePositive) + ' USER IGNORED: ' + str(userIgnored))
