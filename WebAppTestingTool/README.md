You're welcome! Here's a sample `README.md` file for your **Web Application Security Testing Tool**. You can modify it based on the exact details of your project.

### `README.md`

```markdown
# Web Application Security Testing Tool

This tool is designed to test web applications for common vulnerabilities like **SQL Injection**, **Cross-Site Scripting (XSS)**, **brute force attacks**, and **directory traversal**, as well as check for the presence of important **HTTP security headers**. It can be used by security professionals and developers to identify security issues in their web applications.

## Features

- **SQL Injection Detection**: Tests if a web application is vulnerable to SQL injection attacks by using common payloads.
- **Cross-Site Scripting (XSS) Detection**: Detects XSS vulnerabilities by injecting malicious JavaScript into form fields and URLs.
- **Brute Force Attack Simulation**: Attempts to break into web applications by brute-forcing login forms with a list of username-password combinations.
- **Directory Traversal Vulnerability Testing**: Checks for directory traversal issues by trying to access sensitive files on the server.
- **HTTP Header Security Check**: Ensures that important security headers like `Content-Security-Policy` and `X-Frame-Options` are implemented.

## Installation

To get started, clone the repository and install the required dependencies:

```bash
git clone https://github.com/your-username/web-app-security-tool.git
cd web-app-security-tool
pip install -r requirements.txt
```

Make sure to have Python 3 installed on your system. This tool has been tested on Python 3.8+.

## Usage

You can run the tool by specifying the target URL for testing. Below are examples of how to run individual tests:

### SQL Injection Test

```bash
python3 src/sql_injection.py --url "http://example.com/?id="
```

### Cross-Site Scripting (XSS) Test

```bash
python3 src/xss_detection.py --url "http://example.com/search" --params '{"input": "query"}'
```

### Brute Force Attack Test

```bash
python3 src/brute_force.py --url "http://example.com/login" --usernames "usernames.txt" --passwords "passwords.txt"
```

### Directory Traversal Test

```bash
python3 src/directory_traversal.py --url "http://example.com/download?file="
```

### HTTP Header Check

```bash
python3 src/header_check.py --url "http://example.com"
```

### Run All Tests and Generate Report

You can run all tests at once and generate a report in JSON format:

```bash
python3 src/main.py --url "http://example.com"
```

The results will be saved in a file called `report.json` in the `reports/` directory.

## Sample Report

Here’s a [sample report](./reports/sample_report.json) that shows what the final output looks like. The tool will generate a report summarizing all detected vulnerabilities.

## Requirements

- Python 3.8+
- Python Libraries:
  - `requests`
  - `beautifulsoup4`
  - `json`
  - `argparse`
  - `subprocess`

You can install all necessary libraries using:

```bash
pip install -r requirements.txt
```

## Disclaimer

**Use this tool responsibly.** This tool is meant for educational purposes and testing on web applications where you have explicit permission. Unauthorized testing on web applications could be illegal and violate the terms of service.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more details.

## Contributing

If you'd like to contribute to this project, feel free to open a pull request or submit an issue. Contributions are always welcome!

---

### Author

- **Earl Wang**

