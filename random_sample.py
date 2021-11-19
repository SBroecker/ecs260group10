import requests
import json
import csv
import os
import random

s = requests.Session()

# the URL that we pull data for npm packages from
REGISTRY_URL = "https://registry.npmjs.org"
DOWNLOADS_URL = "https://api.npms.io/v2/package"

with open("db/all.json", "r") as f:
	data = json.load(f)

package_names = data["packageNames"]

index_list = random.sample(range(0, len(package_names)), len(package_names))

sample = []
ct = 0
while len(sample) < 1000:
	versions, downloads = 0, 0
	pkg = package_names[index_list[ct]]
	req = s.get(os.path.join(REGISTRY_URL, pkg))
	if req.status_code == 200 and "versions" in req.json():
		versions = len(req.json()["versions"])
		d_req = s.get(os.path.join(DOWNLOADS_URL, pkg))
		if d_req.status_code == 200:
			downloads = d_req.json()["evaluation"]["popularity"]["downloadsCount"]
	if (versions > 5) & (downloads > 5):
		sample.append(pkg)
	# else:
	# 	print("{}, versions: {}, downloads: {}".format(pkg, versions, downloads))
	ct += 1
