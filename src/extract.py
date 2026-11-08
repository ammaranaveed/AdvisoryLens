import requests
import json
import os

def fetch_github_advisories(per_page=100, max_records=1500):
    print("==================================================")
    print("FETCHING LATEST GITHUB SECURITY ADVISORIES")
    print("==================================================")
    
    url = "https://api.github.com/advisories"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    all_records = []
    params = {"per_page": per_page, "sort": "published", "direction": "desc"}
    
    while url and len(all_records) < max_records:
        print(f"Fetching from URL: {url} ...")
        try:
            response = requests.get(url, headers=headers, params=params if "?" not in url else None, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if not data or not isinstance(data, list):
                    print("No more records found.")
                    break
                all_records.extend(data)
                print(f"Fetched {len(data)} records. Total unique so far: {len(all_records)}")
                
                # Check GitHub Link header for official 'next' page pagination
                link_header = response.headers.get("Link", "")
                url = None
                params = None  # Reset params because next link already contains cursors in URL query string
                if link_header:
                    links = link_header.split(",")
                    for link in links:
                        if 'rel="next"' in link:
                            url = link.split(";")[0].strip().strip("<>")
                            break
            else:
                print(f"Failed to fetch. Status code: {response.status_code}")
                break
        except Exception as e:
            print(f"Error occurred: {e}")
            break
            
    # Trim to max_records if we fetched slightly more
    all_records = all_records[:max_records]
    print(f"\nTotal Unique Raw Records Fetched: {len(all_records)}")
    return all_records

def save_raw_json(raw_data, filepath="data/raw/raw_advisories.json"):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(raw_data, f, ensure_ascii=False, indent=4)
    print(f"✅ Raw JSON data successfully saved to {filepath} with {len(raw_data)} records.")
    return filepath

if __name__ == "__main__":
    records = fetch_github_advisories()
    save_raw_json(records)