from flask import Flask, render_template, request, redirect, url_for, session, flash
import joblib
import numpy as np
from urllib.parse import urlparse
import re
from difflib import SequenceMatcher

app = Flask(__name__)
app.secret_key = "secret_key_for_demo" 


model = joblib.load('phishing_dt_pruned.pkl')

users_db = {}

def extract_url_features(url):
    # Basic Parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path
    query = parsed.query
    full_url = parsed.geturl()

    features = []
    
    
    
    features.append(full_url.count('.'))             # NumDots
    subdomains = len(hostname.split('.')) - 1
    features.append(subdomains)                      # SubdomainLevel
    features.append(len([p for p in path.split('/') if p])) # PathLevel
    features.append(len(full_url))                   # UrlLength
    features.append(full_url.count('-'))             # NumDash
    features.append(hostname.count('-'))             # NumDashInHostname
    features.append(1 if '@' in full_url else 0)     # AtSymbol
    features.append(1 if '~' in full_url else 0)     # TildeSymbol
    features.append(full_url.count('_'))             # NumUnderscore
    features.append(full_url.count('%'))             # NumPercent
    features.append(len(query.split('&')) if query else 0) # NumQueryComponents
    features.append(full_url.count('&'))             # NumAmpersand
    features.append(full_url.count('#'))             # NumHash
    features.append(len(re.findall(r'\d', full_url)))# NumNumericChars
    features.append(1 if not url.startswith('https') else 0) # NoHttps
    features.append(1 if re.search(r'[a-zA-Z0-9]{10,}', path) else 0) # RandomString
    features.append(1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0) # IpAddress
    features.append(1 if hostname.count('.') > 2 else 0) # DomainInSubdomains
    features.append(1 if 'http' in path else 0)      # DomainInPaths
    features.append(1 if 'https' in hostname else 0) # HttpsInHostname
    features.append(len(hostname))                   # HostnameLength
    features.append(len(path))                       # PathLength
    features.append(len(query))                      # QueryLength
    features.append(1 if '//' in path else 0)        # DoubleSlashInPath
    
    
   
    sensitive_words = ['login', 'bank', 'verify', 'secure', 'update', 'account', 'security','metamask', 'office365', 'webscr', 'signin', 'http']
    count = sum(1 for word in sensitive_words if word in full_url.lower())
    features.append(count*2) 
    
    brands = ['paypal', 'amazon', 'apple', 'metamask', 'wallets']
    features.append(1 if any(brand in hostname for brand in brands) else 0)
    
    
    features.append(1 if subdomains <= 2 else -1)    
    features.append(1 if len(full_url) < 54 else (0 if len(full_url) < 75 else -1))

    return features



def get_similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def heuristic_check(url):
    url = url.lower().strip()
    
   
    if url.startswith("http://"):
        return True 

    brands = ['microsoft', 'google', 'facebook', 'paypal', 'amazon', 'netflix', 'metamask', 'binance']
    legit_domains = ['microsoft.com', 'google.com', 'facebook.com', 'paypal.com', 'amazon.com', 'netflix.com']
    suspicious_tlds = ['.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']

    
    if any(url.endswith(tld) or (tld + "/") in url for tld in suspicious_tlds):
        return True

   
    for brand in brands:
        if brand in url:
            if not any(legit in url for legit in legit_domains):
                return True
        
        
        parts = re.split(r'\W+', url)
        for part in parts:
            if 0.8 <= get_similarity(part, brand) < 1.0:
                return True 

    return False

@app.route('/')
def index():
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if email in users_db:
        return "User already exists! <a href='/'>Go back</a>"
    
   
    users_db[email] = {'username': username, 'password': password}
    print(f"New User Registered: {users_db}") 
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

   
    if email in users_db and users_db[email]['password'] == password:
        session['user'] = users_db[email]['username']
        return redirect(url_for('home'))
    else:
        return "Invalid Credentials! <a href='/'>Try again</a>"

@app.route('/home')
def home():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('home.html', user=session['user'])

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return redirect(url_for('index'))

    url = request.form.get('url')
    if not url: 
        return redirect(url_for('home'))

    # Hybrid detection logic
    is_suspicious = heuristic_check(url)
    features = extract_url_features(url)
    input_data = np.array(features).reshape(1, -1)
    
    try:
        prob = model.predict_proba(input_data)[0][1] * 100 
    except:
        prob = 90.0 if model.predict(input_data)[0] == 1 else 10.0
        
    prediction = model.predict(input_data)[0]

    if is_suspicious or prediction == 1:
        final_result = "Phishing"
        risk_score = max(prob, 85.0) if is_suspicious else prob
    else:
        final_result = "Safe"
        risk_score = prob

    return render_template('home.html', 
                           prediction=final_result, 
                           prob=round(risk_score, 2),
                           analyzed_url=url, 
                           user=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None) 
    flash("You have been logged out safely.", "info")
    return redirect(url_for('index')) 

if __name__ == '__main__':
    app.run(debug=True)