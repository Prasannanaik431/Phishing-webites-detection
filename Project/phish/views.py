from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from SplitData import createmodel
from urllib.parse import urlparse
from django.contrib.auth.models import User
import numpy as np
from test import featureExtraction
import pandas as pd
from joblib import load
model = load('./model.joblib')
import re
# Create your views here.
def isValidURL(str):
    # Regex to check valid URL
    regex = ("((http|https)://)(www.)?" +
             "[a-zA-Z0-9@:%._\\+~#?&//=]" +
             "{2,256}\\.[a-z]" +
             "{2,6}\\b([-a-zA-Z0-9@:%" +
             "._\\+~#?&//=]*)")

    # Compile the ReGex
    p = re.compile(regex)

    # If the string is empty
    # return false
    if (str == None):
        return False

    # Return if the string
    # matched the ReGex
    if (re.search(p, str)):
        return True
    else:
        return False


# Driver code


#features extraction

def predict(request):
    if request.method=="POST":
        input_url=request.POST['url1']
        print(input_url);

        features=[]
        features.append(featureExtraction(input_url))
        df = pd.DataFrame(features,columns=['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards'])
        detect_url=model.predictURL(df)
        predictions = np.array([model._most_common_label(pred) for pred in detect_url])
        if predictions==0:
            predictions = f'Legitimate URL'
        else:
            predictions = f'Phishing URL'
        accuracy=model.accuracyURL(detect_url)
        return render(request,'index.html',{'output1':predictions,'accuracy':accuracy})
    return render(request, 'index.html')

#login view
def login_view(request1):
    if request1.method=="POST":
        username = request1.POST['username']
        password = request1.POST['password']
        errormsg="Invalid username or password"
        user = User.objects.filter(username=username).first()
        if user is not None and user.check_password(password):
            print('User exists and password is correct')
            return render(request1, 'adminpanel.html')
        else:
            print('Invalid username or password') 
            return render(request1, 'admin.html',{'errmsg':errormsg})

    return render(request1, 'admin.html')



def adminpanel(request):
    if request.method=="POST":
        n_trees=int(request.POST['n_trees'])
        n_feat=int(request.POST['n_feat'])
        max_depth=int(request.POST['max_depth'])
        model="Model Created sucessfully"
        createmodel(n_trees,n_feat,2,max_depth)
        return render(request,'adminpanel.html',{'out':model})
    
def extractfeat(request):
    if request.method=="POST":
        input_url=request.POST['url1']
        input_url1=urlparse(input_url).netloc
        features=[]
        features.append(featureExtraction(input_url))
        
        return render(request,'adminpanel.html',{'features':features,'url':input_url1})
    return render(request, 'adminpanel.html')


#prediction of the url
def predictURL(request):
    if request.method=="POST":
        input_url=request.POST['url1']
        print(input_url)
        features=[]
        features.append(featureExtraction(input_url))
        df = pd.DataFrame(features,columns=['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards'])
        detect_url=model.predictURL(df)
        predictions = np.array([model._most_common_label(pred) for pred in detect_url])

        #print("entered here")

        if predictions==0:
            predictions = f'Legitimate URL'
        else:
            predictions = f'Phishing URL'

        if isValidURL(input_url) == False:
            predictions = f'Invalid URL'

        return render(request,'adminpanel.html',{'output1':predictions})
    return render(request, 'adminpanel.html')