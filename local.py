'''
Script : local_dl_waf.py (Python 3.6)
Name   : Deep Learning Driven Web Application Firewall
Author : Samiux (https://www.infosec-ninjas.com, https://samiux.blogspot.com)
Date   : MAR 04, 2019
Version: 0.10.5
'''

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.neural_network import MLPClassifier
from mitmproxy.script import concurrent
from mitmproxy import http, ctx
import urllib.parse, os, pickle, time, re, string

script_ver = "0.10.5"
ml_path = "/home/samiux/longjing/"
loaded = 0

# start() is run it once only
def start():
    global etc, X, vectorizer

    # display program information
    print ("\nDeep Learning Driven Web Application Firewall (mitmproxy) v" + script_ver + " - Samiux\n")
    print ("Loading sample data from disk ....")

    # read trained data
    print ("Loading training data from disk ....")

    if os.path.exists(ml_path + "waf_dl.pickle")==True:
        pickle_in = open(ml_path + "waf_dl.pickle", "rb")
        etc = pickle.load(pickle_in)
    else:
        print ("Modeling data file not exists!")
        exit(1)

    if os.path.exists(ml_path + "X.pickle")==True:
        pickle_in = open(ml_path + "X.pickle", "rb")
        X = pickle.load(pickle_in)
    else:
        print ("X data file not exists!")
        exit(1)

    if os.path.exists(ml_path + "vectorizer.pickle")==True:
        pickle_in = open(ml_path + "vectorizer.pickle", "rb")
        vectorizer = pickle.load(pickle_in)
    else:
        print ("Vectorizer data file not exists!")
        exit(1)

    print ("Loading data completed!")
    return

@concurrent
def request(flow):
    temp_list = []
    temp_content = ""
    # flow.request.path
    # flow.request.headers
    # flow.request.content
    # flow.request.multipart_form
    # flow.request.urlencode_form

    # vectorized the feeding test data
    print ("Vectorizing prediction data ....")

    # handling flow.request.path
    request_path = flow.request.path
    # to clean the root url false positive of detection
    if request_path == "/":
        request_path = ""
    request_path = request_path.split()

    # handling flow.request.headers
    request_headers = flow.request.headers
    for x in flow.request.headers:
        temp_headers = (str(x) + ": " + str(flow.request.headers[x]))
        # do not include Cookie as it will caused a lot of false positive (commented out)
        #if x.lower() != "cookie":
        #    temp_list.append(temp_headers)
        if x.lower() != "content-length":  # for ajax request
            temp_list.append(temp_headers)

    request_headers = temp_list

    # handling flow.request.content
    request_content = flow.request.content
    if request_content == b'':  # blank
        request_content = []
    else:
        for y in flow.request.content:
            # video is in integer
            if isinstance(y, int):
                request_content = []
            else:
                temp_content = (str(y) + " " + str(flow.request.content[y]))
                for i in range(len(flow.request.content)):
                    temp_content += ("" + " " + str(flow.request.content[i]))
                    temp_list.append(temp_content)
                request_content = temp_list

    # handling flow.request.multipart_form
    temp_list = []
    string_list = (
#                   "<h1>", "<h2>", "<h3>", "</h1>", "</h2>", "</h3>", "<b>",
                  )
    request_multipart_form = flow.request.multipart_form
    for z in flow.request.multipart_form:
        temp_form = (str(z, encoding="utf-8") + ": " + str(flow.request.multipart_form[z], encoding="utf-8"))
        if not (temp_form == " " or temp_form == ""):
            # filter out html code
            if any(s in temp_form for s in string_list):
                for s in string_list:
                    temp_form = temp_form.replace(s, "")

            # filter out chinese characters
            filtrate = re.compile(u'[^\u4E00-\u9FFF]')
            filtered_str = filtrate.sub(r'', temp_form)
            if (filtered_str == ""):
                temp_list.append(temp_form)

    request_multipart_form = temp_list


    # handling flow.request.urlencoded_form
    temp_list = []
    string_list = (
#                   "<h1>", "<h2>", "<h3>", "</h1>", "</h2>", "</h3>", "<b>",
                  )
    request_urlencoded_form = flow.request.urlencoded_form
    for k in flow.request.urlencoded_form:
        temp_form = (k + ": " + str(flow.request.urlencoded_form[k]))
        if not (temp_form == " " or temp_form == ""):
            # filter out html code and special character
            if any(s in temp_form for s in string_list):
                for s in string_list:
                    temp_form = temp_form.replace(s, "")

            # filter out chinese characters
            filtrate = re.compile(u'[^\u4E00-\u9FFF]')
            filtered_str = filtrate.sub(r'', temp_form)
            if (filtered_str == ""):
                temp_list.append(temp_form)

    request_urlencoded_form = temp_list

    final_request = request_path + request_headers + request_content + request_multipart_form + request_urlencoded_form

    K_test = vectorizer.transform(final_request)

    ##############
    # Prediction #
    ##############

    print ("Prediction is in progress ....")
    predicted = etc.predict(K_test)
    predicted = list(predicted)

    # print the result
    print ("\n")
    for i in range(len(predicted)):
        if predicted[i] == 0:
            result = "Clean    "
        else:
            # redirect to blank host and it will cause 502 Bad Gateway Error
            flow.request.path = "/index.html"
            flow.request.method = "GET"
            result = "Malicious"

        print (result + " - " + final_request[i].replace("\n", ""))

    print ("\n")

# run this function first
if loaded == 0:
    start()
    loaded = 1
