import pandas as pd
import numpy as np
import csv
import sys
import matplotlib.pyplot as plt
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
testSetRange = 10

'''totalAccuracy = 0
totalPrecision = 0
totalRecall = 0
totalf1 = 0 '''

accuracyList = []
precisionList = []
recallList = []
f1List = []

for i in range(0, testSetRange):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = .25)

	#Decision Trees
	clf = tree.DecisionTreeClassifier()
	clf.fit(X_train, y_train)

	# Neural network (MultiPerceptron Classifier)
	#clf = MLPClassifier()
	#clf.fit(X_train, y_train)

	#SVM's
	#clf = SVC(gamma='auto')	 #SVC USE THIS
	#clf = LinearSVC()  #Linear SVC
	#clf.fit(X_train, y_train)
	
	prediction = clf.predict(X_test)

	#here you are supposed to calculate the evaluation measures indicated in the project proposal (accuracy, F-score etc)
	accuracy = clf.score(X_test, y_test)  #accuracy score
	
	yTest = np.array(y_test)
	yTrain= np.array(y_train)

	#calculate precision, recall, and f1 scores
	precision = precision_score(yTest, prediction, average = 'weighted')
	recall = recall_score(yTest, prediction, average = 'weighted')
	f1 = f1_score(yTest, prediction, average = 'weighted')
	
	#add accuracy, precision, recall, and f1 scores to lists
	accuracyList.append(accuracy)
	precisionList.append(precision)
	recallList.append(recall)
	f1List.append(f1)
	
	#calculate average value of each metric
	avgAccuracy = sum(accuracyList)/len(accuracyList)
	avgPrecision = sum(precisionList)/len(precisionList)
	avgRecall = sum(recallList)/len(recallList)
	avgf1 = sum(f1List)/len(f1List)

N = 4
ind = np.arange(N)
width = .35

plot_accuracy = plt.bar(ind,avgAccuracy, width)
plot_precision = plt.bar(ind,avgPrecision, width)
plot_recall = plt.bar(ind,avgRecall, width)
plot_f1 = plt.bar(ind,avgf1, width)

plt.title('Decision Tree Metrics')
# Be sure to choose the right title based on the Machine Learning Type

# plt.title('Neural Network Metrics')
# plt.title('SVM Metrics')

plt.ylabel('Score')
plt.xticks(ind, ('Accuracy', 'Precision', 'Recall', 'F1 Score'))
plt.yticks(np.arange(0,1.0,.05))
plt.show()
