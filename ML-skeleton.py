import pandas as pd
import numpy as np
import csv
import sys
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree

numPackets = sys.argv[1]
fileName = numPackets + 'pktData.csv'

df = pd.read_csv(fileName, header=None)
# You might not need this next line if you do not care about losing information about flow_id etc. All you actually need to
# feed your machine learning model are features and output label.
columns_list = ['IP src', 'IP dest', 'src port', 'dest port', 'proto', 'packet len', 'label', 'flow id']
df.columns = columns_list
features = ['proto', 'packet len', 'flow id']

X = df[features]
y = df['label']

acc_scores = 0
totalResult = 0
testSetRange = 100
for i in range(0, testSetRange):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = .25)

    #Decision Trees
    clf = tree.DecisionTreeClassifier()
    clf.fit(X_train, y_train)

    # Neural network (MultiPerceptron Classifier)
    #clf = MLPClassifier()
    #clf.fit(X_train, y_train)

    #SVM's
    #clf = SVC(gamma='auto')     #SVC USE THIS
    #clf = LinearSVC()  #Linear SVC
    #clf.fit(X_train, y_train)


    #here you are supposed to calculate the evaluation measures indicated in the project proposal (accuracy, F-score etc)
    result = clf.score(X_test, y_test)  #accuracy score
    totalResult += result

avgResult = totalResult / testSetRange
print(avgResult)
