import argparse
import csv
import os
import json
import string
from google.cloud import bigquery
from google.cloud import language
import datetime
from google.cloud.bigquery import SchemaField
import re

class PackageSentiment():
    def __init__(self):
        pass


    @classmethod
    def get_latest_comment_query(cls, pkg_name):
        latest_comment_query = "SELECT  text, creation_date FROM `bigquery-public-data.stackoverflow.comments` where text like '%" + pkg_name + "%' ORDER BY creation_date desc LIMIT 1"
        return latest_comment_query


    @classmethod
    def get_comment_query(cls, pkg_name):
        comment_query = "SELECT text FROM `bigquery-public-data.stackoverflow.comments` where text like '%" + pkg_name + "%'"
        return comment_query


    @classmethod
    def get_question_query(cls, pkg_name):
        question_query = "SELECT body FROM `bigquery-public-data.stackoverflow.posts_questions` where body like '%" + pkg_name + "%'"
        return question_query


    @classmethod
    def get_answer_query(cls, pkg_name):
        answer_query = "SELECT body FROM `bigquery-public-data.stackoverflow.posts_answers` where body like '%" + pkg_name + "%'"
        return answer_query


    @classmethod
    def get_stackoverflow_query(cls, pkg_name):
        stackoverflow_query = "SELECT body FROM `bigquery-public-data.stackoverflow.stackoverflow_posts` where body like '%" + pkg_name + "%'"
        return stackoverflow_query


    @classmethod    
    def query_big_query(cls, key_file, bigquerysql):
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
        bigquery_service = bigquery.Client()
        query = bigquery_service.run_sync_query(bigquerysql)
        query.timeout_ms = 60000
        query.use_legacy_sql = False
        query.use_query_cache = True
        query.run()
        return  query


    @classmethod
    def get_sentiment_score(cls, all_text):
        yes_sentiment_score = False 
        language_service = language.Client()
        score = 0.0
        magnitude = 0.0
        allcomment = ''
        commentdatetime = ''

        try:
             document = language_service.document_from_text(all_text)
             annotations = document.annotate_text(include_sentiment=True, include_syntax=False, include_entities=False)
             score, magnitude = cls.get_scores(annotations)

        except Exception as e:
            print(e)

        return score, magnitude, all_text


    @classmethod
    def get_scores(cls, annotations):
        score = annotations.sentiment.score
        magnitude = annotations.sentiment.magnitude
        return score, magnitude


    @classmethod
    def get_aggregated_string(self, query_data):
        aggregated_text = ''
        for row in query_data.rows:
            aggregated_text = aggregated_text + row[0] + ' '

        return  aggregated_text


    @classmethod
    def get_latest_comment_time(cls, query_data):
        latest_comment_time = ''
        for row in query_data.rows:
            latest_comment_time = row[1]
        return latest_comment_time

    @classmethod
    def runsentiment_process(cls, key_file, pkg_name1):
        first_colon_index =  pkg_name1.find(":")
        pkg_name = pkg_name1[first_colon_index + 1 :]
        all_text = ''
        all_comment_text = ''
        sum_score = 0.0
        magnitude_score = 0.0
        comment = ''
        overall_score = 0.0
        overall_magnitude = 0.0
        all4comment = ''

        comment_query = cls.get_comment_query(pkg_name = pkg_name)
        query_data = cls.query_big_query(key_file=key_file, bigquerysql = comment_query)
        all_comment_text = cls.get_aggregated_string(query_data)

        question_query = cls.get_question_query(pkg_name)
        question_data = cls.query_big_query(key_file = key_file, bigquerysql = question_query)
        all_text = all_comment_text + cls.get_aggregated_string(question_data)


        answer_query = cls.get_answer_query(pkg_name)
        answer_data = cls.query_big_query(key_file = key_file, bigquerysql = answer_query)
        all_text = all_comment_text + cls.get_aggregated_string(answer_data)

        stackoverflow_query = cls.get_stackoverflow_query(pkg_name)
        stackoverflow_data = cls.query_big_query(key_file = key_file, bigquerysql = stackoverflow_query)
        all_text = all_comment_text + cls.get_aggregated_string(stackoverflow_data)

        overall_score, overall_magnitude_score, all4comment = cls.get_sentiment_score(all_text)


        latest_comment_query = cls.get_latest_comment_query(pkg_name = pkg_name)
        latest_comment_data = cls.query_big_query(key_file = key_file, bigquerysql = latest_comment_query)
        latest_comment_text = cls.get_aggregated_string(latest_comment_data)
        latest_comment_time = cls.get_latest_comment_time(latest_comment_data)
        
        sum_score, magnitude_score, comment = cls.get_sentiment_score(latest_comment_text)
        latest_comment_date_time = ''
        if latest_comment_time:
            latest_comment_date_time = latest_comment_time.strftime("%Y-%m-%d %H:%M:%S")
        filtered_comment = re.sub("'", '', latest_comment_text)

        data = {}
        data['packagename'] = pkg_name
        data['packageid'] = 0
        sentiment_details = {}
        sentiment_details['overall_sentiment_score'] = round(overall_score, 2)
        sentiment_details['overall_magnitude_score'] = round(overall_magnitude_score, 2)
        latest_comment_details = {}
        latest_comment_details['comment'] = filtered_comment
        latest_comment_details[ 'sentiment_score'] = round(sum_score, 2)
        latest_comment_details['magnitude_score'] = round(magnitude_score, 2)
        latest_comment_details['comment_time'] = latest_comment_date_time

        sentiment_details['latest_comment_details'] = latest_comment_details
        data['sentiment_score_details'] = sentiment_details
        return json.dumps(data, indent = 4)




