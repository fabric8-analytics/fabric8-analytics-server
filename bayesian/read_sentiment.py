import sys
import requests
import json
import os
import datetime
import argparse
import yaml
#import ast
from flask import current_app
from .sentiment_analysis import PackageSentiment


class SentimentDetails():
    """
    Class read, write and update sentiment details for a package into graph data-base
    """

    def get_graph_url(self):
        """
        provides the graph database url
        :return: graph-url
        """
        url = "http://{host}:{port}".format\
            (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),\
             port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))
        current_app.logger.warning("Graph url is: {}".format(url))
        return url

    def __init__(self):
        pass

    def execute_query(self, query):
        """
        :param query:
        :return: query response
        """
        payload = {'gremlin': query}
        url = self.get_graph_url()
        response = requests.post(url, data=json.dumps(payload))
        if response.status_code != 200:
            print ("ERROR %d: %s") % (response.status_code, response.reason)
        resp_json = response.json()
        return resp_json

    def get_pkg_sentiment(self, google_key, pkg_name):
        """
        :param google_key: Credential file to use Google Cloud Natural Language API's
        :param pkg_name: for which sentiment deatils is required
        :return: Sentiment details for a package
        """
        sentiment_details = {}
        query = "g.V().has('pname','" + pkg_name + "').toList()"
        pkg_data = self.execute_query(query)
        sentiment = PackageSentiment()
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
                current_app.logger.warning("The is no data for package {} in graph".format(pkg_name))
        return sentiment_details

    def find_sentiment_details(self, raw_pkgdata):
        """
        Wrap up raw sentiment details data fetched from Graph into one file as per end-point format
        :param raw_pkgdata:
        :return: Sentiment Details
        """
        sentiment_details = {}
        raw_pkgdata_sentiment_details = raw_pkgdata[0].get('properties',[])
        if raw_pkgdata_sentiment_details:
            sentiment_details['overall_sentiment_score'] = raw_pkgdata_sentiment_details.\
                get('overall_sentiment_score')[0].get('value',0) if 'overall_sentiment_score' in\
                                                                    raw_pkgdata_sentiment_details else None
            sentiment_details['overall_magnitude_score'] = raw_pkgdata_sentiment_details.\
                get('overall_magnitude_score')[0].get('value', 0) if 'overall_magnitude_score' in\
                                                                raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment'] = raw_pkgdata_sentiment_details.\
                get('latest_comment')[0].get('value',0) if 'latest_comment' in\
                                                           raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment_sentiment_score'] = raw_pkgdata_sentiment_details.\
                get('latest_comment_sentiment_score')[0].get('value',0) if 'latest_comment_sentiment_score' in\
                                                                           raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment_magnitude_score'] = raw_pkgdata_sentiment_details.\
                get('latest_comment_magnitude_score')[0].get('value',0) if 'latest_comment_magnitude_score' in\
                                                                           raw_pkgdata_sentiment_details else None
            sentiment_details['last_updated_sentiment_score'] = raw_pkgdata_sentiment_details.\
                get('last_updated_sentiment_score')[0].get('value',0) if 'last_updated_sentiment_score' in\
                                                                         raw_pkgdata_sentiment_details else None
            sentiment_details['latest_comment_time'] = raw_pkgdata_sentiment_details.\
                get('latest_comment_time')[0].get('value',0) if 'latest_comment_time' in\
                                                                raw_pkgdata_sentiment_details else None
        return sentiment_details

    def read_from_bigsqldata(self,sentiment_file):
        """
        :param sentiment_file: Sentiment details as computed by google cloud natural language API's
        :return: sentiment_details: Sentiment details as per graph ingestion requirement
        """
        sentiment_details = {}
        pkg_sentiment_data  = yaml.load(sentiment_file)
        sentiment_details['overall_sentiment_score'] = pkg_sentiment_data.\
            get('sentiment_score_details').get('overall_sentiment_score')
        sentiment_details['overall_magnitude_score'] = pkg_sentiment_data.\
            get('sentiment_score_details').get('overall_magnitude_score')
        sentiment_details['latest_comment'] = pkg_sentiment_data.\
            get('sentiment_score_details').get('latest_comment_details').get('comment')
        sentiment_details['latest_comment_sentiment_score'] = pkg_sentiment_data.\
            get('sentiment_score_details').get('latest_comment_details').get('sentiment_score')
        sentiment_details['latest_comment_magnitude_score'] = pkg_sentiment_data.\
            get('sentiment_score_details').get('latest_comment_details').get('magnitude_score')
        sentiment_details['latest_comment_time'] = pkg_sentiment_data.\
            get('sentiment_score_details').get('latest_comment_details').get('comment_time')
        sentiment_details['last_updated_sentiment_score'] = datetime.datetime.now()
        return sentiment_details

    def create_sentiment_details(self, sentiment_file, pkg_name):
        """
        Create or overwrite package node properties into graph in term of sentiment details
        :param sentiment_file: Sentiment details as per graph ingestion requirement
        :param pkg_name: package name
        :return:
        """
        sentiment_details = self.read_from_bigsqldata(sentiment_file)
        query = "g.V().has('pname','" + pkg_name + "').\
        property('overall_sentiment_score','" + str(sentiment_details['overall_sentiment_score']) + "').\
        property('overall_magnitude_score','" + str(sentiment_details['overall_magnitude_score']) + "').\
        property('latest_comment_sentiment_score','" + str(sentiment_details['latest_comment_sentiment_score']) + "').\
        property('latest_comment_magnitude_score','" + str(sentiment_details['latest_comment_magnitude_score']) + "').\
        property('latest_comment_time','" + str(sentiment_details['latest_comment_time']) + "').\
        property('latest_comment','" + str(sentiment_details['latest_comment']) + "').\
        property('last_updated_sentiment_score','" + str(sentiment_details['last_updated_sentiment_score']) + "').\
        toList()"
        self.execute_query(query)
        return sentiment_details

    def update_sentiment_details(self, sentiment_file, pkg_name):
        """
        Update the sentiment details into Graph
        :param sentiment_file: Sentiment details as per graph ingestion requirement
        :param pkg_name: Name of the package
        :return: Sentiment details as per end-point format
        """
        sentiment_details = self.create_sentiment_details(sentiment_file, pkg_name)
        return sentiment_details
