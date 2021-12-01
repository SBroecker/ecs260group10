"""
ASSUMES YOU'VE ALREADY BUILT A MODEL IN MODEL_TESTS.PY
"""

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
n_feats = selector.n_features_
feat_ranking = selector.ranking_

# find the indexes of the top features
top_n_idx = np.argsort(feat_ranking, kind="stable")[:n_feats]

# get the corresponding feature names
top_features = [feature_columns[i] for i in top_n_idx]

# add the prediction and the true label to the training data
X_tftest["y_tftest"] = y_tftest
X_tftest["y_pred"] = y_pred

# break up the data into dataframes based on predictions and labels
true_pos = X_tftest.loc[(X_tftest["y_tftest"] == 1) & (X_tftest["y_pred"] == 1)]
true_neg = X_tftest.loc[(X_tftest["y_tftest"] == 0) & (X_tftest["y_pred"] == 0)]
false_pos = X_tftest.loc[(X_tftest["y_tftest"] == 0) & (X_tftest["y_pred"] == 1)]
false_neg = X_tftest.loc[(X_tftest["y_tftest"] == 1) & (X_tftest["y_pred"] == 0)]

# get descriptive stats for each
true_pos[top_features+["y_tftest", "y_pred"]].describe()
true_neg[top_features+["y_tftest", "y_pred"]].describe()
false_pos[top_features+["y_tftest", "y_pred"]].describe()
false_neg[top_features+["y_tftest", "y_pred"]].describe()

# plot a distribution of the values of each feature, labeled by predicted value
from scipy import stats
for feat in top_features:
    plt.figure()
    plt.hist(true_pos[(np.abs(stats.zscore(true_pos[feat])) < 2)][feat], label="True Positives", bins=50, alpha=0.5)
    plt.hist(true_neg[(np.abs(stats.zscore(true_neg[feat])) < 2)][feat], label="True Negatives", bins=50, alpha=0.5)
    plt.hist(false_pos[(np.abs(stats.zscore(false_pos[feat])) < 2)][feat], label="False Positives", bins=50, alpha=0.5)
    plt.hist(false_neg[(np.abs(stats.zscore(false_neg[feat])) < 2)][feat], label="False Negatives", bins=50, alpha=0.5)
    plt.legend(loc="upper right")
    plt.title(feat)

plt.show()


# check how predictions change over x values for a feature
for feat in top_features:
    plt.figure()
    plt.scatter(X_tftest[feat], y_pred_prob_1)
    plt.title(feat)

plt.show()

# check how prediction residuals change over x values for a feature
for feat in top_features:
    plt.figure()
    plt.scatter(X_tftest[feat], (y_pred_prob_1 - y_tftest))
    plt.title(feat)

plt.show()

# get the prediction coefficients
coefs = selector.estimator_.coef_.tolist()[0]

# a basic bar chart to show the weights for each feature
plt.bar(top_features, coefs)
plt.axhline(y=0, color="r")
plt.xticks(rotation = 45)
plt.title("Feature Importance")
plt.tight_layout()
plt.show()


# https://stackoverflow.com/questions/25122999/scikit-learn-how-to-check-coefficients-significance
from scipy.stats import norm
# calculate p values for each feature
def logit_pvalue(model, x):
    """ Calculate z-scores for scikit-learn LogisticRegression.
    parameters:
        model: fitted sklearn.linear_model.LogisticRegression with intercept and large C
        x:     matrix on which the model was fit
    This function uses asymtptics for maximum likelihood estimates.
    """
    p = model.predict_proba(x)
    n = len(p)
    m = len(model.coef_[0]) + 1
    coefs = np.concatenate([model.intercept_, model.coef_[0]])
    x_full = np.matrix(np.insert(np.array(x), 0, 1, axis = 1))
    ans = np.zeros((m, m))
    for i in range(n):
        ans = ans + np.dot(np.transpose(x_full[i, :]), x_full[i, :]) * p[i,1] * p[i, 0]
    vcov = np.linalg.inv(np.matrix(ans))
    se = np.sqrt(np.diag(vcov))
    t =  coefs/se  
    p = (1 - norm.cdf(abs(t))) * 2
    return p

p_values = logit_pvalue(selector.estimator_, X_tftrain[top_features])
