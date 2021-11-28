import requests
import json
import csv
import os
import subprocess

# the URL that we pull data for npm packages from
REGISTRY_URL = 'https://registry.npmjs.org'

# a path to save the npm data to
DATA_PATH = "db"

# get a list of all npm packages
def fetch_package_list(dest):
	# send a GET request to npm requesting all package names
	req = requests.get("https://replicate.npmjs.com/_all_docs")
	# if the call was successful
	if req.status_code == 200:
		# create a file as the designated destination
		with open(dest, 'w') as f:
			# create a csv writer object so we can write to the file
			writer = csv.writer(f)
			# parse the response from npm and get the "rows" object
			d = req.json()["rows"]
			# write every package name to our file
			for row in d:
				writer.writerow([row["key"]])

# a method to query the npm registry for a certain package
def get_package(package):
	# send a GET request to the registry
	req = requests.get(os.path.join(REGISTRY_URL, package))
	if req.status_code == 200:
		# parse the response as a json object and return it
		return req.json()
	else:
		raise ValueError('unable to fetch metadata for {} (status code: {})'.format(package, req.status_code))

# a method to collect and parse the data returned by npm
def get_package_metadata(packages, meta_file):
	# open the file containing the list of packages
	with open(packages) as f:
		# open a file to write metadata to
		with open(meta_file, 'a') as fm:
			# create csv reader and writer objects
			csv_reader = csv.reader(f)
			csv_writer = csv.writer(fm)
			# for each package in the list of packages
			for row in csv_reader:
				# get the name of the package
				package = row[0]
				# call the npm registry with the package name to get the package metadata
				try:
					metadata = get_package(package)
				except Exception as e:
					logger.exception('Error while getting metadata for {}'.format(package))
					return
				# get the versions section from the metadata
				versions = metadata["versions"]
				# get keywords of the data
				keywords = []
				if "keywords" in metadata:
					keywords = metadata["keywords"]
				# get the times for each version
				vh = metadata["time"]
				# for each version in the npm registry
				for key, value in versions.items():
					# write a row to the metadata table with: package name, version, date, vulnerabilities, and dependencies
					csv_writer.writerow([package, key, vh.get(key), keywords, json.dumps(value.get("dependencies"))])

if __name__ == '__main__':

	# write list of all packages to a file
	packages_filename = "{}/packages.csv".format(DATA_PATH)
	# fetch_package_list(packages_filename)

	# write dependency info to metadata file
	metadata_filename = "{}/metadata_top1k.csv".format(DATA_PATH)
	# https://gist.github.com/anvaka/8e8fa57c7ee1350e3491
	get_package_metadata("top_packages.csv", metadata_filename)
