import sys
import requests
import json
import os
import datetime
import argparse
import yaml
import ast
#import base64

#$from sentiment_analysis import PackageSentiment 
from .sentiment_analysis import PackageSentiment as sentiment

#GRAPH_DB_URL = "http://{host}:{port}".format\
#            (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),\
#             port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182")) #"http://bayesian-gremlin-http-sentiment-score.dev.rdu2c.fabric8.io/"

# secret file location /src/key.json

class SentimentDetails():

    @classmethod
    def get_graph_url(self):
        url = "http://{host}:{port}".format\
            (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),\
             port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))
        #url = "http://bayesian-gremlin-http-sentiment-score.dev.rdu2c.fabric8.io/"
        print("Graph_URL_is", url)
        return url

    def __init__(self):
        pass


    @classmethod
    def execute_query(self, query):
        payload = {'gremlin': query}
        url = self.get_graph_url()
        response = requests.post(url, data=json.dumps(payload))
        if response.status_code != 200:
            print ("ERROR %d: %s") % (response.status_code, response.reason)
        resp_json = response.json()
        return resp_json

#    @classmethod
#    def get_k_file(self):
#        key_j = os.environ.get("KEY", "")
#        key_s = base64.b64decode(key_j)
#        k_file = ast.literal_eval(key_s)
#        print k_file
#        with open('src/key1.json', 'w') as f:
#            json.dump(k_file, f)
#        return
    
    @classmethod
    def get_pkg_sentiment(self, google_key, input_data):
        sentiment_details = {}
        pkg_name = input_data['package_name']
        query = "g.V().has('pname','" + pkg_name + "').toList()"
#        self.get_k_file()

        pkg_data = self.execute_query(query)
        if pkg_data:
            raw_pkgdata = pkg_data.get('result').get('data',[])
            if raw_pkgdata:
                sentiment_details = self.find_sentiment_details(raw_pkgdata)
                if sentiment_details['last_updated_sentiment_score'] is None:
                    sentiment_file = sentiment.runsentiment_process(google_key, pkg_name)
                    sentiment_details = self.create_sentiment_details(sentiment_file, pkg_name)
                else:
                    last_sentiment_update_time = sentiment_details['last_updated_sentiment_score'].split()[0]
                    current_time = str(datetime.datetime.now()).split()[0]
                    last_sentiment_update_time1 = datetime.datetime.strptime(last_sentiment_update_time, '%Y-%m-%d')
                    current_time1 = datetime.datetime.strptime(current_time, '%Y-%m-%d')
                    time_diff = current_time1 - last_sentiment_update_time1
                    if time_diff.days > int(os.environ.get('SENTIMENT_TIME_DELTA', '7')):
                        old_sentiment_details = sentiment_details
                        sentiment_file = sentiment.runsentiment_process(google_key, pkg_name)
                        sentiment_details = self.update_sentiment_details(sentiment_file, pkg_name)
            else:
                print ("No such node exist in graph")
        return sentiment_details


    @classmethod
    def find_sentiment_details(self, raw_pkgdata):
        sentiment_details = {}
        raw_pkgdata_sentiment_details = raw_pkgdata[0].get('properties',[])
        if raw_pkgdata_sentiment_details:
            sentiment_details['overall_sentiment_score'] = raw_pkgdata_sentiment_details.get('overall_sentiment_score')[0].\
                                                                                         get('value',0) if 'overall_sentiment_score' in raw_pkgdata_sentiment_details else None
            sentiment_details['overall_magnitude_score'] = raw_pkgdata_sentiment_details.get('overall_magnitude_score')[0].\
                                                                                         get('value',0) if 'overall_magnitude_score' in raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment'] = raw_pkgdata_sentiment_details.get('latest_comment')[0].\
                                                                                get('value',0) if 'latest_comment' in raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment_sentiment_score'] = raw_pkgdata_sentiment_details.get('latest_comment_sentiment_score')[0].\
                                                                                                get('value',0) if 'latest_comment_sentiment_score' in raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment_magnitude_score'] = raw_pkgdata_sentiment_details.get('latest_comment_magnitude_score')[0].\
                                                                                                get('value',0) if 'latest_comment_magnitude_score' in raw_pkgdata_sentiment_details else None
            sentiment_details['last_updated_sentiment_score'] = raw_pkgdata_sentiment_details.get('last_updated_sentiment_score')[0].\
                                                                                              get('value',0) if 'last_updated_sentiment_score' in raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment_time'] = raw_pkgdata_sentiment_details.get('latest_comment_time')[0].\
                                                                                     get('value',0) if 'latest_comment_time' in raw_pkgdata_sentiment_details else None
            
        return sentiment_details


    @classmethod
    def read_from_bigsqldata(self,sentiment_file):
        sentiment_details = {}
        pkg_sentiment_data  = yaml.load(sentiment_file)
        sentiment_details['overall_sentiment_score'] = pkg_sentiment_data.get('sentiment_score_details').get('overall_sentiment_score')
        sentiment_details['overall_magnitude_score'] = pkg_sentiment_data.get('sentiment_score_details').get('overall_magnitude_score')
        sentiment_details['latest_comment'] = pkg_sentiment_data.get('sentiment_score_details').get('latest_comment_details').get('comment')
        sentiment_details['latest_comment_sentiment_score'] = pkg_sentiment_data.get('sentiment_score_details').get('latest_comment_details').get('sentiment_score')
        sentiment_details['latest_comment_magnitude_score'] = pkg_sentiment_data.get('sentiment_score_details').get('latest_comment_details').get('magnitude_score')
        sentiment_details['latest_comment_time'] = pkg_sentiment_data.get('sentiment_score_details').get('latest_comment_details').get('comment_time')
        sentiment_details['last_updated_sentiment_score'] = datetime.datetime.now()
        return sentiment_details

    @classmethod
    def create_sentiment_details(self, sentiment_file, pkg_name):
        sentiment_details = self.read_from_bigsqldata(sentiment_file)
        query = "g.V().has('pname','" + pkg_name + "').property('overall_sentiment_score','"+ str(sentiment_details['overall_sentiment_score']) +"').\
                                                      property('overall_magnitude_score','"+ str(sentiment_details['overall_magnitude_score']) +"').\
                                                      property('latest_comment_sentiment_score','"+ str(sentiment_details['latest_comment_sentiment_score']) +"').\
                                                      property('latest_comment_magnitude_score','"+ str(sentiment_details['latest_comment_magnitude_score']) +"').\
                                                      property('latest_comment_time','"+ str(sentiment_details['latest_comment_time']) +"').\
                                                      property('latest_comment','" + str(sentiment_details['latest_comment']) +"').\
                                                      property('last_updated_sentiment_score','"+ str(sentiment_details['last_updated_sentiment_score']) +"').\
                                                      toList()"
        resp = self.execute_query(query)
        return sentiment_details


    @classmethod
    def update_sentiment_details(self, sentiment_file, pkg_name):
        sentiment_details = self.create_sentiment_details(sentiment_file, pkg_name)
        return sentiment_details

