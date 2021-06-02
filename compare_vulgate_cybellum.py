import json
import sys
import pandas as pd

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

df = pd.read_excel(sys.argv[1])
cves_df = df.loc[(df['Status'] == 'new') & (df['Package'] == 'linux_kernel')]['Name']
cyb_cves = cves_df.tolist()

falsePositive = 0
userIgnored = 0
falseNegative = 0
ok = 0

cves_not_in_vulgate = []

FP_NC_list = []
FP_list = []
I_list = []
OK_list = []

for cve in cyb_cves:
    if cve in vulgate['reported']:
        OK_list.append(cve)
        ok += 1
        continue
    if cve in vulgate['ignored']:
        I_list.append(cve)
        userIgnored += 1
        continue
    if cve in vulgate['falsePositive']:
        falsePositive += 1
        if 'not compiled' in vulgate['falsePositive'][cve]:
            FP_NC_list.append(cve + ' FALSE POSITIVE ' +  vulgate['falsePositive'][cve])
        else:
            FP_list.append(cve + ' FALSE POSITIVE ' +  vulgate['falsePositive'][cve])
        continue
    cves_not_in_vulgate.append(cve)

print("Cybellum Vulgate report")
print("-----------------------------------------------")

print('Cybellun file:' + sys.argv[1] + '\nVulgate file:' + sys.argv[2])

print('\nCVEs OK(' + str(len(OK_list)) + '):')
print('---------------------------')
for i in OK_list:
    print(i)

print('\nFalse positive NOT compiled(' + str(len(FP_NC_list)) + '):')
print('---------------------------')
for i in FP_NC_list:
    print(i)

print('\nFalse positive compiled(' + str(len(FP_list)) + '):')
print('---------------------------')
for i in FP_list:
    print(i)

print('\nUser Ignored(' + str(len(I_list)) + '):')
print('---------------------------')
for i in I_list:
    print(i)

print('\nCVES reported and not found in Vulgate:')
print('----------------------------------------------')
for cve in cves_not_in_vulgate:
    print(cve)

print('\nNot reported by Cybelum :')
print('----------------------------------------------')
for vul in vulgate['reported']:
    if vul not in cyb_cves:
        print(vul + ' Not reported')
        falseNegative += 1

print('\n====================  SUMMARY ============================================================')
print('OK: ' + str(ok) + ' FALSENEGATIVE: ' + str(falseNegative) + ' FALSEPOSITIVE: ' + str(falsePositive) + ' USER IGNORED: ' + str(userIgnored))
