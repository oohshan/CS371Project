import pandas as pd
import numpy as np
import csv
import sys
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree
#take in command line argument to clarify which csv file to analyze
numPackets = sys.argv[1]
fileName = numPackets + 'pktData.csv'

df = pd.read_csv(fileName, header=None)
#columns listed in the order they are listed in the csv file
columns_list = ['IP src', 'IP dest', 'src port', 'dest port', 'proto', 'packet len', 'ttl', 'chksum', 'label', 'flow id']
df.columns = columns_list
features = ['proto', 'packet len', 'ttl', 'chksum', 'flow id']

X = df[features]
y = df['label']

acc_scores = 0
totalResult = 0
testSetRange = 30

totalAccuracy = 0
totalPrecision = 0
totalRecall = 0
totalf1 = 0

for i in range(0, testSetRange):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = .25)

	#Decision Trees
	clf = tree.DecisionTreeClassifier()
	clf.fit(X_train, y_train)

        prediction = clf.predict(X_test)

	# Neural network (MultiPerceptron Classifier)
	#clf = MLPClassifier()
	#clf.fit(X_train, y_train)

	#SVM's
	#clf = SVC(gamma='auto')	 #SVC USE THIS
	#clf = LinearSVC()  #Linear SVC
	#clf.fit(X_train, y_train)

	#here you are supposed to calculate the evaluation measures indicated in the project proposal (accuracy, F-score etc)
	accuracy = clf.score(X_test, y_test)  #accuracy score
	
	yTest = np.array(y_test)
	yTrain= np.array(y_train)

	precision = precision_score(yTest, prediction, average = 'weighted')
	recall = recall_score(yTest, prediction, average = 'weighted')
	f1 = f1_score(yTest, prediction, average = 'weighted')
	
        print('precision: ' + str(precision))

	totalAccuracy += accuracy
	totalPrecision += precision
	totalRecall += recall
	totalf1 += f1
	
avgAccuracy = totalAccuracy / testSetRange
avgPrecision = totalPrecision / testSetRange
avgRecall = totalRecall / testSetRange
avgf1 = totalf1/testSetRange

#Print average of all metrics
print('Average Accuracy: ' + str(avgAccuracy))
print('Average Precision: ' + str(avgPrecision))
print('Average Recall: ' + str(avgRecall))
print('Average F1: ' + str(avgf1))
