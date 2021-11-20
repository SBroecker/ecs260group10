import requests
import json
import csv
import os
import random

s = requests.Session()

# the URL that we pull data for npm packages from
REGISTRY_URL = "https://registry.npmjs.org"
DOWNLOADS_URL = "https://api.npms.io/v2/package"
url = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"

with open("db/all.json", "r") as f:
	data = json.load(f)

package_names = data["packageNames"]

index_list = random.sample(range(0, len(package_names)), len(package_names))

sample = []
no_vuln = []
ct = 0
while len(sample) < 1000:
	versions, downloads, vulnerability = 0, 0, False
	pkg = package_names[index_list[ct]]
	req = s.get(os.path.join(REGISTRY_URL, pkg))
	if req.status_code == 200 and "versions" in req.json():
		version_list = list(req.json()["versions"].keys())
		versions = len(version_list)
		d_req = s.get(os.path.join(DOWNLOADS_URL, pkg))
		if d_req.status_code == 200:
			downloads = d_req.json()["evaluation"]["popularity"]["downloadsCount"]
			body = {
				pkg: version_list
			}
			resp = s.post(url, json=body)
			if resp.status_code == 200:
				if resp.json() != {}:
					vulnerability = True
	d = [pkg, versions, downloads, vulnerability]
	if (versions > 5) & (downloads > 5) & vulnerability:
		sample.append(d)
		print("success")
	else:
		no_vuln.append(d)
		print("{}, versions: {}, downloads: {}, vulnerability: {}".format(pkg, versions, downloads, vulnerability))
	ct += 1
