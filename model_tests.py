import pickle
import pandas as pd
import numpy as np

# START DATA LOADING
# unpack the incremental files
chunks = []
with open("db/graphs_wv.pkl", "rb") as f:
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

# calculate features
df["dep_staleness"] = df["dependencies"].apply(calc_staleness)
df["pkg_staleness"] = (pd.Timestamp.now() - df["release_date"]).dt.days
df["dep_max_release_staleness"] = df["dependencies"].apply(max_release_staleness)
df["dep_time_since_prev"] = df["dependencies"].apply(time_since_prev)
df["dep_version_sequence_staleness"] = df["dependencies"].apply(version_sequence_staleness)

# calculate a basic binary label
df["has_vuln"] = np.where(df["vulnerabilities"].str.len() != 0, 1, 0)

# END FORMATTING AND CALCULATING FEAURES

# START SOME MODELING TESTS
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

from sklearn.ensemble import RandomForestClassifier

# get latest release of each package
idx = df.groupby(['package'])['release_date'].transform(max) == df['release_date']
test2 = df[idx]

# prepare features and labels
X = df[["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "dep_time_since_prev", "dep_version_sequence_staleness"]].fillna(0)
Y = df["has_vuln"]

X_new = test2[["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "dep_time_since_prev", "dep_version_sequence_staleness"]].fillna(0)
Y_new = test2["has_vuln"]

# split data for training and testing with a 50/50 split
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.50)

# run a logistic regression
reg = LogisticRegression().fit(X_train, y_train)

# check how well we did by getting an R^2 value
r2 = reg.score(X_test, y_test)

# create a new input dataframe that includes keywords
X_new = test2[["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "time_since_prev", "version_sequence_staleness", "dep_time_since_prev", "dep_version_sequence_staleness", "keywords"]].fillna(0)
X_tftrain, X_tftest, y_tftrain, y_tftest = train_test_split(X_new, Y_new, test_size=0.50)

X_tftrain = X2[:60000]
X_tftest = X2[60000:]
y_tftrain = Y[:60000]
y_tftest = Y[60000:]

# create a scaler transformer to transform raw numeric columns into Z scores
scaler = StandardScaler()
# screate a vectorizer to transform keywords with TF-IDF
tfidf_model = CountVectorizer()

# make a transformer that applies the scaler transformer to the numeric columns and the vectorizer transformer on the keywords
preprocessor = ColumnTransformer([
    ("stalenesses", scaler, ["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "time_since_prev", "version_sequence_staleness", "dep_time_since_prev", "dep_version_sequence_staleness"]),
    ("tfidf", tfidf_model, "keywords")
])

# create a pipeline that applies the transformers and then feeds them into a model
pipe = Pipeline([
    ("preprocessor", preprocessor),
    ("model", LogisticRegression())
])

# fit the transformer to the training data
pipe.fit(X_tftrain, y_tftrain)

# check how well we did by getting an R^2 value
tf_r2 = pipe.score(X_tftest, y_tftest)

y_pred = pipe.predict(X_tftest)
conf = confusion_matrix(y_tftest, y_pred)

disp = ConfusionMatrixDisplay(conf)
disp.plot()
plt.show()

# END MODELING TESTS

