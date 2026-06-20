from flask import Flask, render_template, request
import pickle
import pandas as pd
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)

# Load models and feature columns
dt_model = pickle.load(open('DecisionTree.pkl', 'rb'))
rf_model = pickle.load(open('RandomForest.pkl', 'rb'))
feature_columns = pickle.load(open('feature_columns.pkl', 'rb'))

def extract_features(url):
    features = {}
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        query = parsed.query
    except:
        hostname = ''
        path = ''
        query = ''

    # --- URL based features ---
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    features['ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = url.lower().count('www')
    features['nb_com'] = url.lower().count('.com')
    features['nb_dslash'] = url.count('//')
    features['http_in_path'] = 1 if 'http' in path.lower() else 0
    features['https_token'] = 1 if 'https' in hostname.lower() else 0

    # Digit ratios
    digits_url = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = round(digits_url / len(url), 4) if len(url) > 0 else 0
    digits_host = sum(c.isdigit() for c in hostname)
    features['ratio_digits_host'] = round(digits_host / len(hostname), 4) if len(hostname) > 0 else 0

    features['punycode'] = 1 if 'xn--' in url.lower() else 0

    try:
        port = parsed.port
        features['port'] = 1 if port else 0
    except:
        features['port'] = 0

    tlds = ['.com', '.org', '.net', '.gov', '.edu', '.io']
    features['tld_in_path'] = 1 if any(t in path.lower() for t in tlds) else 0
    features['tld_in_subdomain'] = 1 if any(t in hostname.lower() for t in tlds) else 0
    features['abnormal_subdomain'] = 1 if re.search(r'(http[s]?://)(w[w]?[0-9]?\.)', url) else 0

    # Number of subdomains
    host_parts = hostname.replace('www.', '').split('.')
    features['nb_subdomains'] = len(host_parts) - 1

    features['prefix_suffix'] = 1 if '-' in hostname else 0

    # Random domain detection
    letters = [c for c in hostname if c.isalpha()]
    consonants = [c for c in letters if c.lower() not in 'aeiou']
    features['random_domain'] = 1 if (len(consonants) / len(letters) > 0.6 if letters else 0) else 0

    # Shortening service
    shortening = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|tr\.im|is\.gd|cli\.gs"
    features['shortening_service'] = 1 if re.search(shortening, url) else 0

    # Path extension
    sus_ext = ['.exe', '.zip', '.rar', '.php', '.js']
    features['path_extension'] = 1 if any(e in path.lower() for e in sus_ext) else 0

    features['nb_redirection'] = url.count('//')
    features['nb_external_redirection'] = 0

    # Word based features
    words_raw = re.split(r'\W+', url)
    words_raw = [w for w in words_raw if w]
    host_words = [w for w in re.split(r'\W+', hostname) if w]
    path_words = [w for w in re.split(r'\W+', path) if w]

    features['length_words_raw'] = len(words_raw)
    features['char_repeat'] = max([url.count(c) for c in set(url)]) if url else 0
    features['shortest_words_raw'] = min([len(w) for w in words_raw]) if words_raw else 0
    features['shortest_word_host'] = min([len(w) for w in host_words]) if host_words else 0
    features['shortest_word_path'] = min([len(w) for w in path_words]) if path_words else 0
    features['longest_words_raw'] = max([len(w) for w in words_raw]) if words_raw else 0
    features['longest_word_host'] = max([len(w) for w in host_words]) if host_words else 0
    features['longest_word_path'] = max([len(w) for w in path_words]) if path_words else 0
    features['avg_words_raw'] = round(sum([len(w) for w in words_raw]) / len(words_raw), 4) if words_raw else 0
    features['avg_word_host'] = round(sum([len(w) for w in host_words]) / len(host_words), 4) if host_words else 0
    features['avg_word_path'] = round(sum([len(w) for w in path_words]) / len(path_words), 4) if path_words else 0

    # Phishing hints
    phish_words = ['secure', 'account', 'update', 'login', 
                   'signin', 'banking', 'confirm', 'verify', 'paypal']
    features['phish_hints'] = sum(1 for w in phish_words if w in url.lower())

    # Brand features
    brands = ['google', 'facebook', 'apple', 'amazon', 
              'paypal', 'microsoft', 'netflix', 'instagram']
    features['domain_in_brand'] = 1 if any(b in hostname.lower() for b in brands) else 0
    features['brand_in_subdomain'] = 1 if any(b in hostname.lower() for b in brands) else 0
    features['brand_in_path'] = 1 if any(b in path.lower() for b in brands) else 0

    # Suspicious TLD
    sus_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    features['suspecious_tld'] = 1 if any(t in url.lower() for t in sus_tlds) else 0
    features['statistical_report'] = 0

    # --- HTML based features ---
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        all_links = soup.find_all('a', href=True)
        nb_hyperlinks = len(all_links)
        features['nb_hyperlinks'] = nb_hyperlinks

        int_links = [l for l in all_links if hostname in l.get('href', '')]
        ext_links = [l for l in all_links if hostname not in l.get('href', '') 
                     and l.get('href', '').startswith('http')]
        null_links = [l for l in all_links if l.get('href', '') in ['#', '', 'javascript:void(0)']]

        features['ratio_intHyperlinks'] = round(len(int_links) / nb_hyperlinks, 4) if nb_hyperlinks > 0 else 0
        features['ratio_extHyperlinks'] = round(len(ext_links) / nb_hyperlinks, 4) if nb_hyperlinks > 0 else 0
        features['ratio_nullHyperlinks'] = round(len(null_links) / nb_hyperlinks, 4) if nb_hyperlinks > 0 else 0

        css = soup.find_all('link', rel='stylesheet')
        ext_css = [c for c in css if c.get('href', '').startswith('http') 
                   and hostname not in c.get('href', '')]
        features['nb_extCSS'] = len(ext_css)

        features['ratio_intRedirection'] = 0
        features['ratio_extRedirection'] = round(len(response.history) / 10, 4)
        features['ratio_intErrors'] = 0
        features['ratio_extErrors'] = 0

        forms = soup.find_all('form')
        features['login_form'] = 1 if any('login' in str(f).lower() 
                                          or 'password' in str(f).lower() 
                                          for f in forms) else 0

        favicon = soup.find('link', rel=lambda x: x and 'icon' in x)
        features['external_favicon'] = 1 if favicon and favicon.get('href', '').startswith('http') \
                                        and hostname not in favicon.get('href', '') else 0

        features['links_in_tags'] = len(soup.find_all(['script', 'img', 'link']))
        features['submit_email'] = 1 if 'mailto:' in response.text else 0

        imgs = soup.find_all('img', src=True)
        int_media = [i for i in imgs if hostname in i.get('src', '')]
        ext_media = [i for i in imgs if hostname not in i.get('src', '') 
                     and i.get('src', '').startswith('http')]
        features['ratio_intMedia'] = round(len(int_media) / len(imgs), 4) if imgs else 0
        features['ratio_extMedia'] = round(len(ext_media) / len(imgs), 4) if imgs else 0
        features['sfh'] = 0
        features['iframe'] = 1 if soup.find('iframe') else 0
        features['popup_window'] = 1 if 'window.open' in response.text else 0
        features['safe_anchor'] = round(len([l for l in all_links 
                                             if l.get('href', '').startswith('#')]) 
                                        / nb_hyperlinks, 4) if nb_hyperlinks > 0 else 0
        features['onmouseover'] = 1 if 'onmouseover' in response.text.lower() else 0
        features['right_clic'] = 1 if 'event.button==2' in response.text else 0

        title = soup.find('title')
        features['empty_title'] = 1 if not title or not title.text.strip() else 0
        features['domain_in_title'] = 1 if title and hostname.split('.')[0] in title.text.lower() else 0
        features['domain_with_copyright'] = 1 if hostname.split('.')[0] in response.text.lower() \
                                            and '©' in response.text else 0

    except:
        # If page can't be fetched, use neutral defaults
        features['nb_hyperlinks'] = 0
        features['ratio_intHyperlinks'] = 0
        features['ratio_extHyperlinks'] = 0
        features['ratio_nullHyperlinks'] = 0
        features['nb_extCSS'] = 0
        features['ratio_intRedirection'] = 0
        features['ratio_extRedirection'] = 0
        features['ratio_intErrors'] = 0
        features['ratio_extErrors'] = 0
        features['login_form'] = 0
        features['external_favicon'] = 0
        features['links_in_tags'] = 0
        features['submit_email'] = 0
        features['ratio_intMedia'] = 0
        features['ratio_extMedia'] = 0
        features['sfh'] = 0
        features['iframe'] = 0
        features['popup_window'] = 0
        features['safe_anchor'] = 0
        features['onmouseover'] = 0
        features['right_clic'] = 0
        features['empty_title'] = 1
        features['domain_in_title'] = 0
        features['domain_with_copyright'] = 0

    return features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':

        url = request.form['url']
        model_choice = int(request.form['model'])

        # Extract features
        features = extract_features(url)

        # Create dataframe with correct column order
        features_df = pd.DataFrame([features])[feature_columns]

        # Predict
        if model_choice == 1:
            prediction = dt_model.predict(features_df)[0]
            model_name = "Decision Tree (90.59%)"
        else:
            prediction = rf_model.predict(features_df)[0]
            model_name = "Random Forest (93.92%)"

        return render_template('result.html',
                             prediction=prediction,
                             url=url,
                             model_name=model_name)

if __name__ == '__main__':
    app.run(debug=True)

