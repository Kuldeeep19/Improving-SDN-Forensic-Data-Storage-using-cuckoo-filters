import pandas as pd

# Load just the Monday file (normal traffic - good starting point)
df = pd.read_csv('MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv')
df.columns = df.columns.str.strip()

# See how many rows and columns
print("Shape:", df.shape)

# See column names
print("\nColumns:")
for col in df.columns:
    print(" -", col)

# Show first 3 rows to see actual data
print("\nFirst 3 rows:")
print(df.head(3))

# Show what labels exist
print("\nUnique Labels:")
print(df['Label'].unique())


# Load Tuesday file - has attacks
df2 = pd.read_csv('MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv')
df2.columns = df2.columns.str.strip()
print("\nTuesday Labels:")
print(df2['Label'].value_counts())
