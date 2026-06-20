import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

df = pd.read_csv('dataset_phishing.csv')

# Use ONLY features extractable from URL structure
# No HTML, no WHOIS, no web traffic — just the URL itself
url_features = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
    'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
    'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
    'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
    'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
    'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
    'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
    'nb_subdomains', 'prefix_suffix', 'random_domain',
    'shortening_service', 'path_extension', 'nb_redirection',
    'nb_external_redirection', 'length_words_raw', 'char_repeat',
    'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
    'longest_words_raw', 'longest_word_host', 'longest_word_path',
    'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints',
    'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
    'suspecious_tld', 'statistical_report'
]

X = df[url_features]
y = df['status']

print("Features shape:", X.shape)
print("Label counts:")
print(y.value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

print("\nTraining Decision Tree...")
dt_model = DecisionTreeClassifier(max_depth=10, random_state=42)
dt_model.fit(X_train, y_train)
dt_accuracy = accuracy_score(y_test, dt_model.predict(X_test))
print(f"Decision Tree Accuracy: {dt_accuracy * 100:.2f}%")

print("\nTraining Random Forest...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
rf_accuracy = accuracy_score(y_test, rf_model.predict(X_test))
print(f"Random Forest Accuracy: {rf_accuracy * 100:.2f}%")

print("\n--- Model Comparison ---")
print(f"Decision Tree: {dt_accuracy * 100:.2f}%")
print(f"Random Forest: {rf_accuracy * 100:.2f}%")

pickle.dump(dt_model, open('DecisionTree.pkl', 'wb'))
pickle.dump(rf_model, open('RandomForest.pkl', 'wb'))
pickle.dump(url_features, open('feature_columns.pkl', 'wb'))
print("\nModels saved!")