import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
import joblib

data = pd.read_csv('../datasets/Vulnerabilities.csv')  
X = data['URL']
y = data['Vulnerability Type']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer()), 
    ('classifier', RandomForestClassifier())
])

pipeline.fit(X, y)

joblib.dump(pipeline, 'url_vulnerability_model.joblib')

accuracy = pipeline.score(X_test, y_test)
print(f"Model Accuracy: {accuracy * 100:.2f}%")
