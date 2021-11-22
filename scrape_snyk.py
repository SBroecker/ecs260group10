from bs4 import BeautifulSoup
import requests
import re
import csv

empty = False
pkgs = []
pg = 1

while not empty:
	url = "https://security.snyk.io/page/{}?type=npm".format(pg)
	page = requests.get(url).text
	soup = BeautifulSoup(page)
	if len(soup.find_all("h2", {"class": "vue--empty-state__heading"})) != 0:
		empty = True
	rows = soup.find_all("tr", {"class": "vue--table__row"})
	for row in rows:
		if row.find_all("a"):
			anchor = row.find_all("a", {"class": "vue--anchor", "data-snyk-test": "vuln package"})[0]
			version = row.find_all("span", {"class": "vulns-table__semver"})[0]
			pkg = re.split('\s+', anchor.text.strip())[0]
			vsn = version.text.strip()
			pkgs.append([pkg, vsn])
	pg += 1

with open("db/vulns.csv", "w") as f:
	write = csv.writer(f)
	write.writerows(pkgs)