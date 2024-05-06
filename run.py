import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib  
from colorama import Fore, Style  
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
]
data = pd.read_csv("kddcup.data_10_percent_corrected", header=None, names=column_names)

categorical_columns = ['protocol_type', 'service', 'flag']
label_encoder = LabelEncoder()
for col in categorical_columns:
    data[col] = label_encoder.fit_transform(data[col])
features = data.drop('label', axis=1)  
labels = data['label']
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
model = IsolationForest(contamination=0.1, random_state=42) 
joblib.dump(model, 'isolation_forest_model_kdd.pkl')
loaded_model = joblib.load('isolation_forest_model_kdd.pkl')
attack_data = X_test.sample(n=30, random_state=42).copy()  
for col in categorical_columns:
    label_encoder.fit(data[col])
attack_data['dst_bytes'] = np.random.randint(1000, 10000, size=30)  
attack_data['src_bytes'] = np.random.randint(1000, 10000, size=30) 
attack_data['protocol_type'] = 0 


attack_predictions = loaded_model.predict(attack_data)

attack_predictions[attack_predictions == 1] = 0  
attack_predictions[attack_predictions == -1] = 1  

print("Attack Predictions:")
for i, prediction in enumerate(attack_predictions):
    if prediction == 1:  
        print(f"{Style.BRIGHT}{Fore.RED}[ANOMALY]{Style.RESET_ALL} Instance {i+1}: {attack_data.iloc[i].to_dict()}")
    else:  
        print(f"{Style.BRIGHT}{Fore.GREEN}[NORMAL]{Style.RESET_ALL} Instance {i+1}: {attack_data.iloc[i].to_dict()}")
