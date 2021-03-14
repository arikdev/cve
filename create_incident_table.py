import requests
import json
import sys
from datetime import datetime
from time import sleep
import csv_tools as csv
from general_tools import timer
import concurrent.futures
from time import time

CSV_HOME = '/home/manage/splunk/etc/apps/lookup_editor/lookups/'
CPE_TABLE = 'vul_cpe.csv'
PRODUCT_TABLE = 'vul_product_table.csv'
PRODUCT_CPE_TABLE = 'vul_product_cpe.csv'
CVE_IGNORE = 'vul_cve_ignore.csv'
INCIDENT_TABLE = 'vul_incidents.csv'
CPE_COMPILED_FILES_TABLE = 'vul_cpe_compiled_files.csv'
CVE_COMMITS_FILE = 'vul_cve_commits.txt'

debug = False
get_time = False

def version_cmp(ver1, ver2):
    parts1 = [int(x) for x in ver1.split('.')]
    parts2 = [int(x) for x in ver2.split('.')]

    len_diff = len(parts1) - len(parts2)
    if len_diff > 0:
        for i in range(len_diff):
            parts2.append(0)
    if len_diff < 0:
        for i in range(-len_diff):
            parts1.append(0)

    for i in range(len(parts1)):
        if parts1[i] > parts2[i]:
            return 1
        if parts2[i] > parts1[i]:
            return -1

    return 0

def get_cvss(cve_item):
    try:
        return  cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
    except KeyError:
        pass
    try:
        return  cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
    except KeyError:
        pass

    return '0'

def handle_cve(cve_item, part, vendor, product, version, cves):
    cve_id = cve_item['cve']['CVE_data_meta']['ID']
    conf = cve_item['configurations']
    nodes = conf['nodes']
    cvss = str(get_cvss(cve_item))
    found = False
    for node in nodes:
        if found:
            break;
        if 'cpe_match' not in node:
            continue
        matches = node['cpe_match']
        for match in matches:
            if found:
                break;
            cpe = match['cpe23Uri']
            tokens = cpe.split(':')
            cur_part = tokens[2]
            cur_vendor = tokens[3]
            cur_product = tokens[4]
            if cur_part != part or cur_vendor != vendor or cur_product != product:
                continue
            cur_version = tokens[5]
            if cur_version.find(version) != -1:
                cves.append({'cve_id': cve_id, 'cvss': cvss})
                found = True
                break
            if cur_version == '-':
                print('----------------------------- cve:' + cve_id)
            if cur_version == '*':
                startIncluding = None
                endIncluding = None
                try:
                    startIncluding = match.get('versionStartIncluding')
                    if startIncluding is not None and version_cmp(version, startIncluding) == -1:
                        continue;
                    endIncluding = match.get('versionEndIncluding')
                    if endIncluding is not None and version_cmp(version, endIncluding) == 1:
                        continue;
                    startExcluding = match.get('versionStartExcluding')
                    if startExcluding is not None and version_cmp(version, startExcluding) != 1:
                        continue;
                    endExcluding = match.get('versionEndExcluding')
                    if endExcluding is not None and version_cmp(version, endExcluding) != -1:
                        continue;
                except ValueError:
                    print('ERROR in versionStartIncluding')
                cves.append({'cve_id': cve_id, 'cvss': cvss})
                found = True
                break

    return cves

# Get CVES that match CPEs
def get_cves(cves, part, vendor, product, version):
    for l in cves_db:
        handle_cve(cve_item=l, part=part, vendor=vendor, product=product, version=version, cves=cves)

# Each product should contain the following:
# List of dictionaries that contains:
#   CPE ID 
#   list of all relevant CVEs
# build the product DB

class Product_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global product_db
        product_db[tokens[0]] = {'cpes':{}, 'customer':tokens[2]}

class Product_cpe_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global product_db
        product_id = tokens[0]
        cpe_id = tokens[1]
        version = tokens[2]
        hw = tokens[3]
        if product_id not in product_db:
           print('ERROR: product :' + product_id)
           return
        product_db[product_id]['cpes'][cpe_id] = {'version':version, 'cves':[]}

class Cpe_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global cpe_db
        cpe_id = tokens[0]
        cpe_db.setdefault(cpe_id, []).append({'part': tokens[1], 'vendor': tokens[2], 'product': tokens[3]})

class Cpe_compiled_files(csv.CSV_FILE):
    def implementation(self, tokens):
        global cpe_compiled_files_db
        cpe_id = tokens[0]
        product_id = tokens[1]
        source_file = tokens[2]
        cpe_compiled_files_db.setdefault(cpe_id, [])
        for cpe_entry in cpe_compiled_files_db[cpe_id]:
            if 'product_id' in cpe_entry and cpe_entry['product_id'] == product_id: 
                break
        else:
            cpe_entry = {'files':set(), 'product_id':product_id}
            cpe_compiled_files_db[cpe_id].append(cpe_entry)

        cpe_entry['files'].add(source_file)

class Cve_ignore_file(csv.CSV_FILE):
    def implementation(self, tokens):
        ignore_list.append(tokens[0])


class Incident_seq_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global incident_seq
        if int(tokens[0]) > incident_seq:
            incident_seq = int(tokens[0])

def load_cves():
    global cves_db

    with open('cves.json', 'r') as json_file:
        for line in json_file:
            j = json.loads(line)
            cves_db.append(j)

def load_ref():
    global ref_db

    with open('cves_refs.json', 'r') as json_file:
        for line in json_file:
            j = json.loads(line)
            files = ref_db.setdefault(j['cve_id'], {'files':set(),'commits':set()})['files']
            commits = ref_db.setdefault(j['cve_id'], {'files':set(),'commits':set()})['commits']
            for ref_file in j['files']:
                files.add(ref_file)
            for ref_commit in j['commits']:
                commits.add(ref_commit)


def load_commits():
    with open(CSV_HOME + CVE_COMMITS_FILE, 'r') as fp:
        while True:
            try:
                commit_id = fp.readline()[:-1]
                if not commit_id:
                    break
                commits_db[commit_id] = True
            except UnicodeDecodeError as e:
                print('---- UnicodeDecodeError')
                continue


def init_db():
    product_file = Product_file(CSV_HOME + PRODUCT_TABLE)
    product_file.process()

    product_cpe_file = Product_cpe_file(CSV_HOME + PRODUCT_CPE_TABLE)
    product_cpe_file.process()

    cpe_file = Cpe_file(CSV_HOME + CPE_TABLE)
    cpe_file.process()

    incident_seq_file = Incident_seq_file(CSV_HOME + INCIDENT_TABLE)
    incident_seq_file.process()

    cpe_compiled_files = Cpe_compiled_files(CSV_HOME + CPE_COMPILED_FILES_TABLE)
    cpe_compiled_files.process()

    cve_ignore_file = Cve_ignore_file(CSV_HOME + CVE_IGNORE)
    cve_ignore_file.process()

    load_cves()

    load_ref()

    load_commits()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        exec_results = executor.map(handle_product_init_db, product_db.items())


def dump_db():
    print(product_db)
    print(cpe_db)
    for product_id,product_info in product_db.items():
        print('-----------------------')
        print('product id:' + product_id)
        for cpe_id, cpe_info in product_info['cpes'].items():
            print(cpe_id)
            version = cpe_info['version']
            for variant in cpe_db.setdefault(cpe_id, None):
                print('++++')
                print(variant['part'])
                print(variant['vendor'])
                print(variant['product'])
                print(version)
                for cve in cpe_info['cves']:
                    print(cve['cve_id'])

if get_time:
    @timer
    def handle_product_init_db(product_entry):
        return __handle_product_init_db(product_entry)
else:
    def handle_product_init_db(product_entry):
        return __handle_product_init_db(product_entry)

def __handle_product_init_db(product_entry):
    product_id = product_entry[0]
    product_info = product_entry[1]
    print('Handleing product init DB ..... product:' + product_id)
    for cpe_id, cpe_info in product_info['cpes'].items():
        version = cpe_info['version']
        cves = cpe_info['cves']
        for variant in cpe_db.setdefault(cpe_id, None):
            get_cves(cves, variant['part'], variant['vendor'], variant['product'], version)

    return ""


if get_time:
    @timer
    def handle_product(product_entry):
        return __handle_product(product_entry)
else:
    def handle_product(product_entry):
        return __handle_product(product_entry)

def __handle_product(product_entry):
    product_id = product_entry[0]
    product_info = product_entry[1]
    print('>>>>Handling product: ' + product_id)
    customer_id = product_info['customer']
    for cpe, cpe_info in product_info['cpes'].items():
        if 'version' not in cpe_info:
            print('ERROR: no version in cpe: ' + cpe)
            continue
        if 'cves' not in cpe_info:
            #nothing to do for this cpe.
            continue
        version = cpe_info['version']
        if debug:
            print('>>>>> Processing ' + str(product_id) + ' ' + str(cpe) + ' ' + str(version))
        for cve in cpe_info['cves']:
            cve_id = cve['cve_id']
            if cve_id in ignore_list:
                continue
            # No reference for the CVE - nothing to do
            if is_reference_relevant(cve_id, cpe, version, product_id) == False:
                continue
            if debug:
                print('key: ' + product_id + ',' +  cve_id + ',' + cpe + ',' + version)
                print(reference)
            res = get_incident(incidents, product_id, cve_id, cpe, version)
            if res is not None:
                continue
            insert_incident(incident_file, incidents, product_id, customer_id, cve_id, cpe, version, cve['cvss'])

    return ""


def get_incident(incidents_db, product_id, cve, cpe, version):
    for incident in incidents_db:
        try:
            if cve == incident['CVE'] and cpe == incident['CPE'] and version == incident['Version'] and product_id == incident['Product_id']:
                return incident
        except KeyError:
            pass

    return None

def insert_incident(incidents_file, incidents, product_id, customer_id, cve, cpe, version, cvss):
    global incident_seq
    incident_values = []
    incident_seq += 1
    incident_values.append(str(incident_seq))
    incident_values.append(cve)
    incident_values.append(cpe)
    incident_values.append(version)
    incident_values.append(product_id)
    incident_values.append(customer_id)
    incident_values.append('Open')
    incident_values.append('nvd')
    now = datetime.now()
    incident_values.append(now.strftime("%d/%m/%Y %H:%M:%S"))
    incident_values.append(now.strftime("%d/%m/%Y %H:%M:%S"))
    incident_values.append('Jira ticket')
    incident_values.append('0')
    incident_values.append(cvss)

    incidents_file.insert_dic_line(incidents, incident_values)


def is_reference_relevant(cve_id, cpe, version, product_id):
    global cpe_compiled_files_db
    global ref_db

    if cve_id not in ref_db:
        return True

    for file in ref_db[cve_id]['files']:
        if '.c' in file:
            break
    else:
        return True

    if cpe not in cpe_compiled_files_db:
        return False
    for cpe_entry in cpe_compiled_files_db[cpe]:
        if cpe_entry.get('product_id') == product_id: 
            break
    else:
        return False

    for c in ref_db[cve_id]['commits']:
        if c in commits_db:
            return False

    for pfile in cpe_entry['files']:
        for rfile in ref_db[cve_id]['files']:
            if pfile in rfile:
                return True

    return False

#############################################################################
# DB model: product db
# {'product_id' : 'customer_id' : '..'
#                 'cpes': { 'cpe1name' :{ 'version': '...'
#                                         'cves'    : ['CVE-2020-28282', ...]
#                                       }
#                           'cpe2name' :{ 'version': '...'
#                                         'cves'    : ['CVE-2020-28282', ...]
#                                       }
#                         }
#  }

incident_file = csv.CSV_FILE(CSV_HOME + INCIDENT_TABLE)
incident_seq = 0
product_db = {}
cpe_db = {}
ref_db = {}
cves_db = []
ignore_list = []
cpe_compiled_files_db = {}
commits_db = {}

init_db()

if debug:
    dump_db()

#Load the content of incident table to a dictionary
#The matchin fileds in the incident table is product_id,cve,cpe,version
incidents = incident_file.to_dic();

if debug:
    print(incidents)

with concurrent.futures.ThreadPoolExecutor() as executor:
    exec_results = executor.map(handle_product, product_db.items())

if debug:
    print('=========================== incidents after !!!: ===================================================================')
    print(incidents)

incident_file.from_dic(incidents)
