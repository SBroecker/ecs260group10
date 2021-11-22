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
meta_file = "db/metadata_expanded.csv"
num_random_packages = 2000
num_vulnerable_packages = 2000

with open("db/all.json", "r") as f:
	data = json.load(f)

package_names = data["packageNames"]

index_list = random.sample(range(0, len(package_names)), len(package_names))

print("gathering random packages")
ct = 0
i = 0
with open(meta_file, 'a') as fm:
	# create csv reader and writer objects
	csv_writer = csv.writer(fm)
	while ct < num_random_packages:
		versions, downloads = 0, 0
		version_list = {}
		keywords = []
		vh = {}
		pkg = package_names[index_list[i]]
		req = s.get(os.path.join(REGISTRY_URL, pkg))
		if req.status_code == 200 and "versions" in req.json():
			metadata = req.json()
			version_list = metadata["versions"]
			versions = len(version_list)
			if "keywords" in metadata:
				keywords = metadata["keywords"]
			vh = metadata["time"]
			d_req = s.get(os.path.join(DOWNLOADS_URL, pkg))
			if d_req.status_code == 200:
				downloads = d_req.json()["evaluation"]["popularity"]["downloadsCount"]
		if (versions > 5) | (downloads > 100):
			ct += 1
			for key, value in version_list.items():
				# write a row to the metadata table with: package name, version, date, vulnerabilities, and dependencies
				csv_writer.writerow([pkg, key, vh.get(key), keywords, json.dumps(value.get("dependencies"))])
		i += 1
print(i)
with open("db/vulns.csv") as f:
	raw_vulns = f.read()

vulns = raw_vulns.split(",")
vulns = list(set(vulns))

v_index_list = random.sample(range(0, len(vulns)), num_vulnerable_packages)

print("gathering vulnerable packages")
with open(meta_file, 'a') as fm:
	# create csv reader and writer objects
	csv_writer = csv.writer(fm)
	# for each package in the list of packages
	for v in v_index_list:
		# get the name of the package
		package = vulns[v]
		# call the npm registry with the package name to get the package metadata
		try:
			req = s.get(os.path.join(REGISTRY_URL, package))
			metadata = req.json()
			# get the versions section from the metadata
			versions = metadata["versions"]
			# get the times for each version
			vh = metadata["time"]
		except Exception as e:
			continue
		# get keywords of the data
		keywords = []
		if "keywords" in metadata:
			keywords = metadata["keywords"]
		# for each version in the npm registry
		for key, value in versions.items():
			# write a row to the metadata table with: package name, version, date, vulnerabilities, and dependencies
			csv_writer.writerow([package, key, vh.get(key), keywords, json.dumps(value.get("dependencies"))])



