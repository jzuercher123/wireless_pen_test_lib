import subprocess
import json
import os


def searchsploit_to_json(query: str) -> list:
    try:
        # Run Searchsploit with --json flag
        result = subprocess.run(
            ["searchsploit", query, "--json"],
            capture_output=True,
            text=True,
            check=True
        )

        # Load the JSON output
        exploits = json.loads(result.stdout)
        return exploits.get("RESULTS_EXPLOIT", [])
    except subprocess.CalledProcessError as e:
        print(f"Error running searchsploit: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON output: {e}")
        return []


def convert_to_vulnerabilities_format(exploit_list: list) -> list:
    vulnerabilities = []

    for exploit in exploit_list:
        vulnerability = {
            "id": exploit.get("ID", ""),
            "name": exploit.get("Title", ""),
            "description": exploit.get("Description", "No description available."),
            "severity": "unknown",  # You may need to assign severity based on description
            "recommendation": "Refer to ExploitDB and apply appropriate patches.",
            "affected_protocols": [exploit.get("Platform", "unknown").lower()],
            "references": [
                f"https://www.exploit-db.com/exploits/{exploit.get('EDB-ID')}"
            ]
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities


# Specify the vulnerability query
query = "apache"

# Run Searchsploit to get results
exploits = searchsploit_to_json(query)

# Convert to desired vulnerabilities.json format
vulnerabilities = convert_to_vulnerabilities_format(exploits)

# Save to vulnerabilities.json file
vulnerabilities_path = "vulnerabilities.json"
with open(vulnerabilities_path, 'w') as f:
    json.dump({"vulnerabilities": vulnerabilities}, f, indent=4)

print(f"Saved {len(vulnerabilities)} vulnerabilities to {vulnerabilities_path}")
