import pandas as pd
import requests
import csv
s = requests.Session()

# the file created with the npm_packages.py file
metadata_file = "db/metadata_expanded.csv"
pickle_file_name = "db/graphs_snyk.pkl"

# create a pandas dataframe from the metadata file
df = pd.read_csv(metadata_file, names=["package", "version", "release_date", "keywords", "dependencies"])
# add an empty column that will eventually store vulnerability info
df["vulnerability"] = ""

# convert the release_date column into a datetime object
df["release_date"] = df["release_date"].astype('datetime64[ns]')

# get the previous release date for each package version
df["last_release_date"] = df.sort_values("release_date").groupby("package")["release_date"].shift(1)
# get the most recent release date for each package
df["max_release_date"] = df.sort_values("release_date").groupby("package")["release_date"].transform(max)
# find the difference between the current version and the most recent version
df["max_release_staleness"] = (df["max_release_date"] - df["release_date"]).dt.days
# find how long it has been since the previous version
df["time_since_prev"] = (df["release_date"] - df["last_release_date"]).dt.days

# rank each version of a package
df["release_rank"] = df.sort_values("release_date").groupby("package")["release_date"].rank()
# find the rank of the latest version of the package
df["max_release_rank"] = df.sort_values("release_date").groupby("package")["release_rank"].transform(max)
# get the difference between the current version and the most recent version
df["version_sequence_staleness"] = (df["max_release_rank"] - df["release_rank"])

# sort the dataframe by release date
df =  df.sort_values("release_date")

# aggregate all of the versions for each package
package_versions = df.groupby("package").agg(versions=("version", "unique"))

# a list to store npm audit information
vulnerabilities = []
url = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"

print("checking packages for known vulnerabilities")
# for each package, send a request to npm to get all of the known vulnerabilities
for index, row in package_versions.iterrows():
    body = {
        index: row[0].tolist()
    }
    resp = s.post(url, json=body).json()
    # add the vulnerabilities of the package to our list
    vulnerabilities.append([index, resp])

# filter out packages that didn't have known vulnerabilities
actual_vulnerabilities = [x for x in vulnerabilities if x[1] != {}]

# get list of packages in df
vuln_lookup = df["package"].unique().tolist()

# get known vulnerabilities from synk
vulns = []
# open the file
with open("db/vulns.csv") as f:
    # create a csv object
    csv_reader = csv.reader(f)
    # write a row for each package that matches the expected format
    for row in csv_reader:
        # if the package is in our current df, add it to the vulnerability list
        if row[0] in vuln_lookup:
            d = [row[0], {row[0]: [{"severity": "synk", "vulnerable_versions": row[1]}]}]
            vulns.append(d)

# combine vulnerability lists from synk and npm
actual_vulnerabilities = actual_vulnerabilities + vulns

print("adding vulnerabilities to dataframe")
# loop through the vulnerabilities
for v in actual_vulnerabilities:
    # get the package name
    pkg = v[0]
    # get the list of vulnerabilities for the package
    jsn_lst = v[1][pkg]
    # loop through each one
    for item in jsn_lst:
        # the severity of the vulnerability
        severity = item["severity"]
        # the package versions that are affected by the vulnerability
        # can have a range: >=5.5.0 <5.7.4
        # or be a single number: <0.4.11
        versions = item["vulnerable_versions"]
        # flags to keep track of the signs in the vulnerable versions
        greater = False
        less = False
        less_equals = False
        equals = False
        star = False
        # placeholder variables used to filter later
        first = ""
        second = ""
        # check each version (if a range is given)
        for version in versions.split(" "):
            # set flags depending on what's contained in the version number
            if ">=" in version:
                greater = True
                first = version.replace(">=", "")
            elif "<=" in version:
                less_equals = True
                second = version.replace("<=", "")
            elif "<" in version:
                less = True
                second = version.replace("<", "")
            elif "=" in version:
                equals = True
                first = version.replace("=", "")
            elif "*" in version:
                star = True
        # based on the flags set above, update the original dataframe with severity information
        if equals:
            df.loc[(df["package"] == pkg) & (df["version"] == first), "vulnerability"] += severity + " "
        elif greater and less:
            df.loc[(df["package"] == pkg) & (df["version"] >= first) & (df["version"] < second), "vulnerability"] += severity + " "
        elif greater and less_equals:
            df.loc[(df["package"] == pkg) & (df["version"] >= first) & (df["version"] <= second), "vulnerability"] += severity + " "
        elif less:
            df.loc[(df["package"] == pkg) & (df["version"] < second), "vulnerability"] += severity + " "
        elif less_equals:
            df.loc[(df["package"] == pkg) & (df["version"] <= second), "vulnerability"] += severity + " "
        elif star:
            df.loc[(df["package"] == pkg), "vulnerability"] += severity + " "

# convert the strings into a list
df["vulnerability"] = df["vulnerability"].str.split(" ").str[:-1]

df2 = df.drop_duplicates(subset=["package", "version", "release_date"]).set_index(["package", "version"]).sort_index()


# CREATE DEPENDENCY GRAPHS
import json

# method to find the date for each package version
# input is a list of packages and their versions
def parse_packages(deps):
    # list to keep track of all outputs
    all_deps = []
    # iterate through each dependency
    for d in deps:
        key = d[0]
        value = d[1]
        # query the metadata for a package of a particular version
        try:
            f = df2.loc[(key, value)]
            # if the package version was found
            # add it to the list packages with the release date
            all_deps.append([key, value, f.release_date, f.keywords, f.vulnerability, f.max_release_staleness, f.time_since_prev, f.version_sequence_staleness])
        except:
            # if it wasn't found, check if the package exists in our df at all
            try:
                new_f = df2.loc[key]
                # if it does, get the most recent version
                idx = new_f.release_date.idxmax()
                new_f = new_f.loc[idx]
                all_deps.append([key, idx, new_f.release_date, new_f.keywords, new_f.vulnerability, new_f.max_release_staleness, new_f.time_since_prev, new_f.version_sequence_staleness])
            except:
                # if it doesn't, return None for the release date
                all_deps.append([key, value, None, None, None, None, None, None])
    return all_deps

print("building dependency graphs")
# for tracking how long it takes to build the dependency graphs
from time import process_time
import pickle
start_time = process_time()

"""
~version “Approximately equivalent to version”, will update you to all future patch versions, without incrementing the minor version. ~1.2.3 will use releases from 1.2.3 to <1.3.0.
^version “Compatible with version”, will update you to all future minor/patch versions, without incrementing the major version. ^2.3.4 will use releases from 2.3.4 to <3.0.0.
"""
firstten = []
nodes = 0
# open a file to keep track of incremental graphs
with open(pickle_file_name, "wb") as pickle_file:
    # go through every row in the metadata df
    for index, row in df2.iterrows():
        # get the dependencies for the current row
        d = row["dependencies"]
        package = index[0]
        version = index[1]
        # a list to track the dependency graph
        graph = []
        # a list to track dependency names
        names = []
        # a list to keep track of packages that still need to be parsed
        q = []
        # if the current package has dependencies
        if not pd.isnull(d):
            # parse the json and add them to q
            for key, value in json.loads(d).items():
                # don't reprocess a dependency that's already in the graph
                if key not in names:
                    q.append([key, value])
                    names.append(key)
            # add the current package to the dependency graph
            graph.append([package, version])
            names.append(package)
        else:
            # if the package does not have dependencies, add it to the dependency graph
            graph.append([package, version])
            names.append(package)
        # if there are any packages that need to be parsed in q
        while len(q) > 0:
            # get the first item in q and remove it from the list
            node = q.pop(0)
            key = node[0]
            value = node[1]
            # prefilter for the package
            try:
                f = df2.loc[key]
            except:
                graph.append([key, value])
                names.append(key)
                continue
            # if >= is in the version number
            if ">=" in value:
                # remove the >=
                min_value = value.replace(">=", "").strip()
                # query the dataframe for packages that are above the version
                f = f[f.index >= min_value]
                # if any are found
                if not f.empty:
                    # find the most recent package that was returned
                    idx = f.release_date.idxmax()
                    f = f.loc[idx]
                    # add it to the dependency graph
                    graph.append([key, idx])
                    names.append(key)
                    # check if that dependency has dependencies
                    curr_d = f["dependencies"]
                    # if it does, add those to q
                    if not pd.isnull(curr_d):
                        for new_key, new_value in json.loads(curr_d).items():
                            if new_key not in names:
                                q.append([new_key, new_value])
                                names.append(new_key)
                # if the package is not found, add the current version to the dependency graph
                else:
                    graph.append([key, min_value])
                    names.append(key)
            # if ~ is in the version number
            elif "~" in value:
                # remove ~ from the string
                app_value = value.replace("~", "").strip()
                # get the first two parts of the version (eg get 1.2 from 1.2.3)
                version_prefix = ".".join(app_value.split(".")[:-1])
                # look for packages that start with that version number
                reg = "^" + version_prefix
                f = f.filter(regex=reg, axis=0)
                # if any are found
                if not f.empty:
                    # get the most recent one
                    idx = f.release_date.idxmax()
                    f = f.loc[idx]
                    # add it to the dependency graph
                    graph.append([key, idx])
                    names.append(key)
                    # check if the package has any dependencies
                    curr_d = f["dependencies"]
                    # if it does, add those to q
                    if not pd.isnull(curr_d):
                        for new_key, new_value in json.loads(curr_d).items():
                            if new_key not in names:
                                q.append([new_key, new_value])
                                names.append(new_key)
                else:
                    # if the package is not found, add the current version to the dependency graph
                    graph.append([key, app_value])
                    names.append(key)
            # if ^ is in the version number
            elif "^" in value:
                # remove ^ from the version
                comp_value = value.replace("^", "").strip()
                # get only the major version numner (the first number)
                version_prefix = comp_value.split(".")[0]
                if version_prefix != "*":
                    # look for packages with that major version number
                    reg = "^" + version_prefix
                    f = f.filter(regex=reg, axis=0)
                # if any are found
                if not f.empty:
                    # get the most recent one
                    idx = f.release_date.idxmax()
                    f = f.loc[idx]
                    # add it to the dependency graph
                    graph.append([key, idx])
                    names.append(key)
                    # check if the package has any dependencies
                    curr_d = f["dependencies"]
                    # if it does, add them to q
                    if not pd.isnull(curr_d):
                        for new_key, new_value in json.loads(curr_d).items():
                            if new_key not in names:
                                q.append([new_key, new_value])
                                names.append(new_key)
                else:
                    # if the package is not found, add the current version to the dependency graph
                    graph.append([key, comp_value])
                    names.append(key)
            # an exact version is given
            else:
                # check the database for that version
                try:
                    f = df2.loc[(key, value)]
                    # add it to the dependency graph
                    graph.append([key, value])
                    names.append(key)
                    # check for dependencies
                    curr_d = f["dependencies"].item()
                    # if any are found, add them to q
                    if not pd.isnull(curr_d):
                        for new_key, new_value in json.loads(curr_d).items():
                            if new_key not in names:
                                q.append([new_key, new_value])
                                names.append(new_key)
                except:
                    # if it's found
                    graph.append([key, value])
                    names.append(key)
            # go back to beginning of while loop if any more elements are in q
        # call parse packages to get release dates for each package in the dependency graph
        deps = parse_packages(graph)
        # add this dependency graph to the list of all graphs
        if deps is not None:
            firstten.append(deps)
        # filter to cut this process off at a certain point
        if len(firstten) % 2000 == 0:
            pickle.dump(firstten, pickle_file, protocol=pickle.HIGHEST_PROTOCOL)
            nodes += len(firstten)
            firstten = []
            print(nodes)
    pickle.dump(firstten, pickle_file, protocol=pickle.HIGHEST_PROTOCOL)
# END CREATE DEPENDENCY GRAPHS

# calculate how long it took to get all graphs
end_time = process_time() 
print("Elapsed time during the whole program in seconds:", end_time-start_time)



