from time import sleep
import requests
import json
import sys
import re

counter = 0
res = {}
files_found = 0

def handle_files(cve_id, files):
    global f
    global files_found
    for file in files:
        if cve_id not in res:
            info = {}
            info['files'] = []
            info['commits'] = []
            res[cve_id] = info
        if file not in res[cve_id]['files']:
            f.write('>>>>>FILE ' + cve_id + ' ' + file + '\n')
            res[cve_id]['files'].append(file)
            files_found += 1

def handle_commit(cve_id, url):
    if 'commit' not in url:
        return
    tokens = url.split('/')
    commit_id = tokens[-1]
    tokens = commit_id.split('=')
    commit_id = tokens[-1]
    if cve_id not in res:
       info = {}
       info['files'] = []
       info['commits'] = []
       res[cve_id] = info
    if commit_id not in res[cve_id]['commits']:
        res[cve_id]['commits'].append(commit_id)
        f.write('>>>>>COMMIT ' + commit_id + ' from url: ' + url + '\n')


def handle_patch(cve_id, url, str_patch):
    global files_found
    if url is not None:
        handle_commit(cve_id, url)
        files = re.findall(r'(\/[\/\w]*?\.[ch]+\b)', str_patch)
        handle_files(cve_id, files)

def handle_ref(cve_id, r):
    global counter
    if 'tags' not in r:
        return
    tags = r['tags']
    if 'Patch' not in tags:
       return
    if 'url' not in r:
       return
    url = r['url']
    if 'git' not in url and 'lkml.org' not in url:
        return
    counter = counter + 1
    try:
      response = requests.get(url)
    except:
      f.write('Eeception URL:' + url + '\n')
      return
    handle_patch(cve_id, url, str(response.content, 'utf-8'))

def handle_description(cve_id, cve):
    if 'description' not in cve:
        return
    desc = cve['description']
    if 'description_data' not in desc:
        return;
    desc_data = desc['description_data']
    for i in desc_data:
        if 'value' not in i:
            continue
        handle_patch(cve_id, None, i['value'])


def handle_cve(item):
    cve = item['cve']
    cve_meta_data = cve['CVE_data_meta']
    print('----- Handle cve:' +  cve_meta_data['ID'])
    #handle_description(cve_meta_data['ID'], cve)
    if 'references' not in cve:
        return
    references = cve['references']
    if 'reference_data' not in references:
        return
    ref_data = references['reference_data']
    for r in ref_data:
      handle_ref(cve_meta_data['ID'], r)

f = open("cve_reference_log.txt", "w")
fcves_refs = open("cves_refs.json", "w")
cves = []
with open('cves.json', 'r') as json_file:
    for line in json_file:
        data = json.loads(line)
        handle_cve(data)

for cve_id, cve_info in res.items():
    cve_ref = {}
    cve_ref['cve_id'] = cve_id
    cve_ref['files'] = cve_info['files']
    if 'commits' in cve_info:
        cve_ref['commits'] = cve_info['commits']
    fcves_refs.write(json.dumps(cve_ref) + '\n')

fcves_refs.close()

f.write('FINISH!!!!\n')
f.close()
