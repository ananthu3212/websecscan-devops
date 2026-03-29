### Nikto scanning

Install Nikto (`brew install nikto` | `apt install nikto`) and start the app:

```bash
export NIKTO_PATH="$(which nikto)"
python -m Backend.app
   

Scan only systems you’re authorized to test.

Start backend: python -m Backend.app

Call: POST /api/scan with { "target": "<URL>" }

Nikto findings are returned in nikto_data.report_json (plus raw report_txt if needed).