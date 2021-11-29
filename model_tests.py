import pickle
import pandas as pd
import numpy as np

"""
FILES
metadata_snyk.csv -> graphs_snyk.pkl
metadata_top1k.csv + metadata_snyk.csv -> graphs_snyk_top1k.pkl
"""

# START DATA LOADING
# unpack the incremental files
chunks = []
with open("db/graphs_snyk.pkl", "rb") as f:
    try:
        while True:
            chunk = pickle.load(f)
            chunks.append(chunk)
    except (EOFError):
        pass


# flatten the incremental lists into a single list of graphs
flat_list = [item for sublist in chunks for item in sublist]

# function to format each row
def unpack(x):
    p = x.pop(0)
    return (p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], x)

# apply the formatting function to the list of lists
formatted = list(map(unpack, flat_list))

# turn into pandas df
df = pd.DataFrame(formatted, columns=["package", "version", "release_date", "keywords", "vulnerabilities", "max_release_staleness", "time_since_prev", "version_sequence_staleness", "dependencies"])

# END DATA LOADING

# START FORMATTING AND CALCULATING FEAURES
# function to get average staleness of each package's dependencies
def calc_staleness(graph):
    # list to keep track of times
    times = []
    # go through each node in the graph
    for node in graph:
        # get the time, if it exists
        if node[2] is not None:
            times.append(node[2])
    # find the difference between now and the release date for each release date in the graph
    diffs = [(pd.Timestamp.now() - i).days for i in times]
    if times == []:
        return 0.0
    # add the average time difference to the list of staleness values
    return sum(diffs)/len(diffs)

# function to calculate the average max release staleness of the dependency graph
def max_release_staleness(graph):
    # list to keep track of times
    times = []
    # go through each node in the graph
    for node in graph:
        # get the time, if it exists
        if node[5] is not None:
            times.append(node[5])
    # check that any values exist
    if times == []:
        return 0.0
    # find the average
    return sum(times)/len(times)

# function to calculate the average time since the previous version of the dependency graph
def time_since_prev(graph):
    # list to keep track of times
    times = []
    # go through each node in the graph
    for node in graph:
        # get the time, if it exists
        if node[6] is not None:
            times.append(node[6])
    # check that any values exist
    if times == []:
        return 0.0
    # find the average
    return sum(times)/len(times)

# function to calculate the average version sequence staleness of the dependency graph
def version_sequence_staleness(graph):
    # list to keep track of times
    times = []
    # go through each node in the graph
    for node in graph:
        # get the time, if it exists
        if node[7] is not None:
            times.append(node[7])
    # check that any values exist
    if times == []:
        return 0.0
    # find the average
    return sum(times)/len(times)

# function to calculate how many nodes in a dependency graph we have information for
def known_nodes(graph):
    # counter for the number of nodes
    nodes = 0
    # go through each node in the graph
    for node in graph:
        # iterate if a time exists
        if node[2] is not None:
            nodes += 1
    # return the value
    return nodes

# function to identify if dependency graph contains vulnerabilities
def dep_has_vuln(graph):
    if graph != []:
        for x in graph:
            if (x[4] is not None) & (x[4] != []):
                if (len(x[4]) != 0):
                    return 1
            else:
                return 0
    else:
        return 0

# calculate features
df["dep_staleness"] = df["dependencies"].apply(calc_staleness)
df["pkg_staleness"] = (pd.Timestamp.now() - df["release_date"]).dt.days
df["dep_max_release_staleness"] = df["dependencies"].apply(max_release_staleness)
df["dep_time_since_prev"] = df["dependencies"].apply(time_since_prev)
df["dep_version_sequence_staleness"] = df["dependencies"].apply(version_sequence_staleness)
df["dep_count"] = df["dependencies"].apply(len)
df["dep_has_vuln"] = df["dependencies"].apply(dep_has_vuln)
df["dep_known_nodes"] = df["dependencies"].apply(known_nodes)

# calculate a basic binary label
df["has_vuln"] = np.where((df["vulnerabilities"].str.len() != 0) | (df["dep_has_vuln"] == 1), 1, 0)

# get latest (max)/oldest (min) release of each package
idx_min = df.groupby(['package'])['release_date'].transform(min) == df['release_date']
idx_max = df.groupby(['package'])['release_date'].transform(max) == df['release_date']
df_min = df[idx_min]
df_max = df[idx_max]

df = df_min

# check correlation between features
import matplotlib.pyplot as plt
import seaborn as sns

# show a heatmeat for the correlations between features
hm = sns.heatmap(df.corr(), annot=True)
plt.tight_layout()
plt.show()

# END FORMATTING AND CALCULATING FEAURES

# START SOME MODELING TESTS
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.feature_selection import RFECV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV

# prepare features and labels
X_new = df[["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "time_since_prev", "version_sequence_staleness", "dep_time_since_prev", "dep_version_sequence_staleness", "dep_count"]].fillna(0)
Y_new = df["has_vuln"]

# split data for training and testing with a 50/50 split
X_tftrain, X_tftest, y_tftrain, y_tftest = train_test_split(X_new, Y_new, test_size=0.30, random_state=10)

# create a scaler transformer to transform raw numeric columns into Z scores
scaler = StandardScaler()

# make a transformer that applies the scaler transformer to the numeric columns and the vectorizer transformer on the keywords
feature_columns = ["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "time_since_prev", "version_sequence_staleness", "dep_time_since_prev", "dep_version_sequence_staleness", "dep_count"]
preprocessor = ColumnTransformer([
    ("stalenesses", scaler, feature_columns)
])

# provide parameter options for logistic regression
param_grid = {
    'C': [0.001,0.01,0.1,1,10,100,1000]
}

# a random forest classifier object
log = LogisticRegression()
# pass the forest object to the grid search object with the optional params
grid = GridSearchCV(log, param_grid, verbose=1, cv=3)
# pass the forest object to the RFE object
selector = RFECV(log, verbose=1)

# create a pipeline that applies the transformers and then feeds them into a model (or grid search, or RFE)
pipe = Pipeline([
    ("preprocessor", preprocessor),
    ("model", selector)
])

# fit the transformer to the training data
pipe.fit(X_tftrain, y_tftrain)

