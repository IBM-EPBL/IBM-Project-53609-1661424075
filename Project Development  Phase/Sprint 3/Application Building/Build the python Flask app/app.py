from flask import Flask, request, render_template
import numpy as np
import rfc
import pandas as pd 
from sklearn import metrics 
import requests
import json
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

API_KEY = "ITkxxANDG6N3roYajqDgCD4qZOdsELITcTYseAecmJKu"
token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey":
 API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
mltoken = token_response.json()["access_token"]

header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}



file = open("pickle/model.pkl","rb")
rfc = pickle.load(file)
file.close()


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =rfc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = rfc.predict_proba(x)[0,0]
        y_pro_non_phishing = rfc.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return render_template('index.html',xx =round(y_pro_non_phishing,2),url=url )
    return render_template("index.html", xx =-1)
payload_scoring = {"input_data": [{"field": ["PrefixSuffix-",
                                "SubDomains",
                                "HTTPS",
                                "AnchorURL",
                                "WebsiteTraffic"], "values": [1, -1]}]}
response_scoring = requests.post('https://us-south.ml.cloud.ibm.com/ml/v4/deployments/f44a67e9-ebef-4ab8-abf0-91b5e1307e64/predictions?version=2022-11-13', json=payload_scoring,
 headers={'Authorization': 'Bearer ' + mltoken})
print("Scoring response")
print(response_scoring.json())


if __name__ == "__main__":
    app.run(debug=True)