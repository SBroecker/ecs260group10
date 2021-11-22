import pickle
import pandas as pd
import numpy as np

# START DATA LOADING
# unpack the incremental files
chunks = []
with open("db/graphs_expanded.pkl", "rb") as f:
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

# function to identify if dependency graph contains vulnerabilities
def dep_has_vuln(graph):
    if len(graph) != 0:
        return 1
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


# calculate a basic binary label
df["has_vuln"] = np.where((df["vulnerabilities"].str.len() != 0) | (df["dep_has_vuln"] == 1), 1, 0)

# get latest (max)/oldest (min) release of each package
idx = df.groupby(['package'])['release_date'].transform(min) == df['release_date']
df = df[idx]

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
X_new = df[["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "time_since_prev", "version_sequence_staleness", "dep_time_since_prev", "dep_version_sequence_staleness", "dep_count", "keywords"]].fillna(0)
Y_new = df["has_vuln"]

# split data for training and testing with a 50/50 split
X_tftrain, X_tftest, y_tftrain, y_tftest = train_test_split(X_new, Y_new, test_size=0.50)

# create a scaler transformer to transform raw numeric columns into Z scores
scaler = StandardScaler()
# screate a vectorizer to transform keywords with TF-IDF
tfidf_model = CountVectorizer()

# make a transformer that applies the scaler transformer to the numeric columns and the vectorizer transformer on the keywords
preprocessor = ColumnTransformer([
    ("stalenesses", scaler, ["pkg_staleness", "dep_staleness", "dep_max_release_staleness", "time_since_prev", "version_sequence_staleness", "dep_time_since_prev", "dep_version_sequence_staleness", "dep_count"])
    # ,("tfidf", tfidf_model, "keywords")
])

# provide parameter options for random forest
param_grid = {
    'max_depth': [80, 90, 100, 110],
    'max_features': ["auto", 2, 3],
    'n_estimators': [100, 200, 300, 1000]
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

# check how well we did by getting an R^2 value
tf_r2 = pipe.score(X_tftest, y_tftest)

# get predictions for each test case
y_pred = pipe.predict(X_tftest)

# get % predictions for each test case
y_pred_prob = pipe.predict_proba(X_tftest)

# isolate the prediction for class 1 (vulnerable)
y_pred_prob_1 = [x[1] for x in y_pred_prob]

# generate and plot the confusion matrix
conf = confusion_matrix(y_tftest, y_pred)
disp = ConfusionMatrixDisplay(conf)
disp.plot()
plt.show()

# check how predictions change over x values for a feature
plt.scatter(X_tftest["dep_count"], y_pred_prob_1)
plt.xlim([0, 10])
plt.show()

# check how prediction residuals change over x values for a feature
plt.scatter(X_tftest["dep_count"], y_tftest - y_pred_prob_1)
plt.xlim([0, 50])
plt.show()

# END MODELING TESTS


# plot number of features VS. cross-validation scores
plt.figure()
plt.xlabel("Number of features selected")
plt.ylabel("Cross validation score (accuracy)")
plt.plot(
    range(1, len(selector.grid_scores_) + 1),
    selector.grid_scores_,
)
plt.legend()
plt.show()

# generate model metrics
from sklearn import metrics
print("Accuracy:",metrics.accuracy_score(y_tftest, y_pred))
print("Precision:",metrics.precision_score(y_tftest, y_pred))
print("Recall:",metrics.recall_score(y_tftest, y_pred))
print("F1 Score:", metrics.f1_score(y_tftest, y_pred))

# some more metrics
import scipy
a= np.var(y_tftest)
b= np.var(y_pred)
print(a,b)
fstat_var = np.var(y_tftest,ddof=1/np.var(y_pred,ddof=1))
dof_num = y_tftest.size - 1
dof_den = y_pred.size - 1
fstat_critical = scipy.stats.f.ppf(0.05,dof_num,dof_den)
p = 1-scipy.stats.f.cdf(fstat_var, dof_num, dof_den)
print("f critical: ",fstat_critical )
print("f stat: ", fstat_var)
print("p value: ", p)

# calculate auc score
auc = metrics.roc_auc_score(y_tftest, y_pred)
print("auc score: ", auc)

# get the number of features after RFE and the ranking of the features (to figure out what order they were eliminated)
selector.n_features_
selector.ranking_
