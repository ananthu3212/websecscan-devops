auto install dependencies:
    cd backend
    source venv/bin/activate (on linux)
    .\venv\Scripts\activate (on windows)
    pip install -r requirements.txt
    python3 app.py


mannual installation:
you need pyton, check if you have it or not 
    py --version
then create the virtual enviroment 
    py -m venv venv
    for linux: python3 -venv venv
activate the source enviroment 
    .\venv\Scripts\activate
    for linux: source venv/bin/activate
then install flask
    pip install Flask
Set Flask Environment Variables:
    $env:FLASK_APP="app.py"
Set Flask to development mode:
    $env:FLASK_ENV="development"
ensure certain libraries are installed:
    pip install Flask-Cors
    pip install python-nmap
    pip install psycopg2-binary
    pip install python-dotenv
to run flask:
    flask run
## 🧠 HTTPS Development Setup

To run Flask locally with HTTPS, create self-signed certificates once:

```bash
mkdir certs
cd certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
Then start Flask:
python app.py



