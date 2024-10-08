import json

def generate_report(results):
    with open('report.json', 'w') as report_file:
        json.dump(results, report_file, indent=4)
    print("Report generated: report.json")
