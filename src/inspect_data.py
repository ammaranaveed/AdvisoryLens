import os
import pandas as pd
import json

def inspect_project_data():
    print("==================================================")
    print("🔍 ADVISORYLENS DATA & QUALITY INSPECTION 🔍")
    print("==================================================")
    
    raw_path = "data/raw/raw_advisories.json"
    processed_path = "data/processed/processed_advisories.csv"
    
    # 1. Check Raw Data count
    if os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        print(f"Total Raw Records Extracted: {len(raw_data)}")
    else:
        print("Raw JSON file not found!")
        
    # 2. Check Processed CSV data
    if os.path.exists(processed_path):
        df = pd.read_csv(processed_path)
        print(f"Total Processed Records in CSV: {len(df)}")
        print("\n--- Available Columns ---")
        print(df.columns.tolist())
        
        print("\n--- Data Types & Non-Null Counts ---")
        print(df.info())
        
        print("\n--- Missing Values Count per Column ---")
        print(df.isnull().sum())
        
        print("\n--- Severity Value Counts ---")
        if "severity" in df.columns:
            print(df["severity"].value_counts())
    else:
        print("Processed CSV file not found!")

if __name__ == "__main__":
    inspect_project_data()