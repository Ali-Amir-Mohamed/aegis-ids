import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import joblib, os, warnings, time
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve, auc

print("=" * 65)
print("   AEGIS — AI INTRUSION DETECTION SYSTEM")
print("   Full Training: All 7 Days — 2,313,810 rows")
print("=" * 65)

print("\n[1/7] Loading all dataset files...")
files = [
    'data/Benign-Monday-no-metadata.parquet',
    'data/Botnet-Friday-no-metadata.parquet',
    'data/Bruteforce-Tuesday-no-metadata.parquet',
    'data/DDoS-Friday-no-metadata.parquet',
    'data/DoS-Wednesday-no-metadata.parquet',
    'data/Infiltration-Thursday-no-metadata.parquet',
    'data/Portscan-Friday-no-metadata.parquet',
    'data/WebAttacks-Thursday-no-metadata.parquet',
]
dfs = []
for f in files:
    tmp = pd.read_parquet(f)
    name = f.split('/')[-1].replace('-no-metadata.parquet','')
    print(f"   {name:<35} {len(tmp):>8,} rows")
    dfs.append(tmp)
df = pd.concat(dfs, ignore_index=True)
print(f"\n   TOTAL ROWS LOADED: {len(df):,}")

print("\n[2/7] Cleaning data...")
df.columns = df.columns.str.strip()
df.replace([float('inf'), float('-inf')], float('nan'), inplace=True)
before = len(df)
df.dropna(inplace=True)
print(f"   Rows before : {before:,}")
print(f"   Rows after  : {len(df):,}")

print("\n[3/7] Preparing labels...")
for label, count in df['Label'].value_counts().items():
    print(f"   {label:<30} {count:>8,}  ({count/len(df)*100:.1f}%)")
df['binary_label'] = df['Label'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
safe = (df['binary_label']==0).sum()
attack = (df['binary_label']==1).sum()
print(f"\n   BENIGN (0) : {safe:,}")
print(f"   ATTACK (1) : {attack:,}")

print("\n[4/7] Selecting features...")
remove_cols = ['Label','binary_label','Flow ID','Source IP','Destination IP','Timestamp']
remove_cols = [c for c in remove_cols if c in df.columns]
X = df.drop(columns=remove_cols)
y = df['binary_label']
print(f"   Features : {X.shape[1]}")
print(f"   Samples  : {X.shape[0]:,}")

print("\n[5/7] Splitting and normalizing...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)
print(f"   Training : {len(X_train):,}")
print(f"   Testing  : {len(X_test):,}")
print("   Z-score normalization done")

print("\n[6/7] Training Random Forest...")
print("   Please wait 5-15 minutes...")
start = time.time()
model = RandomForestClassifier(n_estimators=100, max_depth=20, class_weight='balanced', random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
t = time.time() - start
print(f"   Done in {t:.1f} seconds!")

print("\n[7/7] Evaluating...")
y_pred  = model.predict(X_test)
acc     = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, model.predict_proba(X_test)[:,1])
cm      = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print("\n" + "="*65)
print("   RESULTS")
print("="*65)
print(f"   Accuracy         : {acc*100:.2f}%")
print(f"   ROC-AUC          : {roc_auc:.4f}")
print(f"   Training time    : {t:.1f} seconds")
print(f"   True Negatives   : {tn:,}")
print(f"   True Positives   : {tp:,}")
print(f"   False Positives  : {fp:,}")
print(f"   False Negatives  : {fn:,}")
print(f"   False Alarm Rate : {fp/(fp+tn)*100:.4f}%")
print(f"   Miss Rate        : {fn/(fn+tp)*100:.4f}%")
print("\n   Detailed Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN','ATTACK']))

os.makedirs('outputs', exist_ok=True)

plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Predicted BENIGN','Predicted ATTACK'],
            yticklabels=['Actual BENIGN','Actual ATTACK'])
plt.title('Confusion Matrix — CIC-IDS2017')
plt.tight_layout()
plt.savefig('outputs/confusion_matrix.png', dpi=150)
plt.close()

fpr, tpr, _ = roc_curve(y_test, model.predict_proba(X_test)[:,1])
plt.figure(figsize=(8,6))
plt.plot(fpr, tpr, color='#00d4ff', lw=2, label=f'AUC = {auc(fpr,tpr):.4f}')
plt.plot([0,1],[0,1],'--',color='gray')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve — CIC-IDS2017')
plt.legend()
plt.tight_layout()
plt.savefig('outputs/roc_curve.png', dpi=150)
plt.close()

feature_names = df.drop(columns=remove_cols).columns
importances   = model.feature_importances_
indices       = np.argsort(importances)[::-1][:15]
plt.figure(figsize=(10,7))
plt.barh(range(15), importances[indices][::-1], color='steelblue')
plt.yticks(range(15), [feature_names[i] for i in indices][::-1], fontsize=9)
plt.xlabel('Importance Score')
plt.title('Top 15 Most Important Features')
plt.tight_layout()
plt.savefig('outputs/feature_importance.png', dpi=150)
plt.close()

pd.DataFrame({'Feature': feature_names, 'Importance': importances}).sort_values('Importance', ascending=False).to_csv('outputs/feature_importance.csv', index=False)

os.makedirs('models', exist_ok=True)
joblib.dump(model,  'models/ids_model.pkl')
joblib.dump(scaler, 'models/ids_scaler.pkl')

print("   Saved: outputs/confusion_matrix.png")
print("   Saved: outputs/roc_curve.png")
print("   Saved: outputs/feature_importance.png")
print("   Saved: models/ids_model.pkl")
print("   Saved: models/ids_scaler.pkl")
print("\n" + "="*65)
print("   TRAINING COMPLETE")
print("="*65)
