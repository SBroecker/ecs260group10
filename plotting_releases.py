import matplotlib.pyplot as plt
import matplotlib.dates as dt
import numpy as np
import pandas as pd

# the file created with the npm_packages.py file
metadata_file = "db/metadata.csv"

# create a pandas dataframe from the metadata file
df = pd.read_csv(metadata_file, names=["package", "version", "release_date", "dependencies"])

# convert the release_date column into a datetime object
df["release_date"] = df["release_date"].astype('datetime64[ns]')
# add a column for today
df["today"] = pd.to_datetime("today")

# sort the dataframe by release date
df =  df.sort_values("release_date")

# create a duplicate dataframe with new indexes. Allows for quicker lookups
df2 = df.set_index(["package", "version"])


# VISUALIZE RELEASES OVER TIME
# an iterator so that each package will get its own row in the chart
counter = 0
# initialize the chart
fig, ax = plt.subplots()
# make the x-axis a date axis
ax.xaxis_date()
# go through each package in the data
for name, group in df.groupby("package", sort=False):
    # find the first and last release date for the package
    # group.amin = group["release_date"].iloc[0]
    # group.amax = group["release_date"].iloc[-1]
    # draw a line between those two dates
    # ax.hlines(counter, dt.date2num(group.amin), dt.date2num(group.amax))

    # create a new list that has as many elements as the package has releases
    lst = [counter] * len(group["release_date"])
    # create a point for each release
    ax.scatter(x=group["release_date"], y=lst, marker=".")
    # iterate the counter for the next package
    counter += 1

# show the plot
plt.show()
# END VISUALIZING RELEASES OVER TIME

# LINE CHART WHERE EACH RELEASE GOES UP ON THE Y-AXIS BY 1
# initialize the chart
fig, ax = plt.subplots()
# make the x-axis a date axis
ax.xaxis_date()
# go through each package in the data
for name, group in df.groupby("package", sort=False):
    # make a list that counts from 1 to the number of releases for the package
    group["counter"] = range(len(group))
    # plot the releases over time, going up by 1 for each release
    ax.plot(group["release_date"], group["counter"], marker=".")

# show the plot
plt.show()
# END LINE CHART WHERE EACH RELEASE GOES UP ON THE Y-AXIS BY 1

# HISTOGRAM OF THE TIME BETWEEN RELEASES
# list to keep track of times
deltas = []
# go through each package in the data
for name, group in df.groupby("package", sort=False):
    # for each release, subtract the time from the previous release to get the time difference between the two
    group["delta"] = group["release_date"]-group["release_date"].shift()
    # add those time differences to the deltas list
    deltas.append(group["delta"].tolist())

# combine all of the arrays into a single array
arr = np.hstack(deltas)
# convert that into a dataframe
delta_df = pd.DataFrame(arr, columns=["delta"])
# remove any nulls (this happens for the first release because there's nothing before it to compare it to)
delta_df = delta_df[delta_df.delta.notnull()]
# round each time difference to the nearest day
delta_df.delta = delta_df.delta.dt.days

# create a histogram with 100 buckets
hist = delta_df.hist(column="delta", bins=100)
# show the histogram
plt.show()
# END HISTOGRAM OF THE TIME BETWEEN RELEASES

# COMPARE THE MOST RECENT RELEASE TO THE OVERAL AVERAGE
# get mean and standard deviation for all releases
desc = delta_df.describe()
sd = desc.loc["std"][0]
mean = desc.loc["mean"][0]

# for each package, find the latest release data
current_staleness = df.groupby("package", as_index=False).agg(
    recent_release=pd.NamedAgg(column="release_date", aggfunc="max"),
    today=pd.NamedAgg(column="today", aggfunc="max"),)

# find the difference between the most recent release and today 
current_staleness["staleness"] = current_staleness["today"] - current_staleness["recent_release"]
# round that difference to the nearest day
current_staleness.staleness = current_staleness.staleness.dt.days

# find the number of standard deviations between the delta for the most recent release and the average
current_staleness["distance"] = (current_staleness["staleness"] - mean)/sd
# make a histogram with 100 bins
hist = current_staleness.hist(column="distance", bins=100)
# show the plot
plt.show()
# END COMPARE THE MOST RECENT RELEASE TO THE OVERAL AVERAGE

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
            all_deps.append([key, value, f.release_date])
        except:
            # if it wasn't found, check if the package exists in our df at all
            try:
                new_f = df2.loc[key]
                # if it does, get the most recent version
                idx = new_f.release_date.idxmax()
                new_f = new_f.loc[idx]
                all_deps.append([key, idx, new_f.release_date])
            except:
                # if it doesn't, return None for the release date
                all_deps.append([key, value, None])
    return all_deps

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
with open("db/graphs.pkl", "wb") as pickle_file:
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

# unpack the incremental files
chunks = []
with open("db/graphs.pkl", "rb") as f:
    try:
        while True:
            chunk = pickle.load(f)
            chunks.append(chunk)
    except (EOFError):
        pass

# flatten the incremental lists into a single list of graphs
flat_list = [item for sublist in chunks for item in sublist]


# PROCESS DEPENDENCY GRAPHS
import datetime
# a list to keep track of staleness values
stalenesses = []
# iterate through each dependency graph
for graph in flat_list:
    # list to keep track of times
    times = []
    # go through each node in the graph
    for node in graph:
        # get the time, if it exists
        if node[2] is not None:
            times.append(node[2])
    # find the difference between now and the release date for each release date in the graph
    diffs = [(pd.Timestamp.now() - i).days for i in times]
    # add the average time difference to the list of staleness values
    stalenesses.append(sum(diffs)/len(diffs))

# calculate average graph staleness
sum(stalenesses)/len(stalenesses)

# find the size of each dependency graph
lengths = [len(i) for i in flat_list]
# calculate the average size
avg_size = float(sum(lengths)) / len(lengths)

# END PROCESS DEPENDENCY GRAPHS


