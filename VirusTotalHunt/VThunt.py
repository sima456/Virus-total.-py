#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Virus Total Hunting Notification version 1.0
This tiny python script allows you to setup daily report about virustotal hunting notification.
You can send the report by email, to telegram or slack and export the result in JSON.

Usage:
python vthunting.py [options]

Install:
pip install requests slackclient==1.0.7 pymsteams
"""

import requests
import json
import datetime as dt
import re
import smtplib
import getopt
import sys
import sqlite3
import pymsteams
import os
from requests import *
from datetime import datetime
from slackclient import SlackClient


# authorship information
__author__ = "Thomas Roccia | @fr0gger_"
__team__ = "ATR"
__version__ = "1.0"
__maintainer__ = "@fr0gger_"
__status__ = "Release 1.0"
__asciiart__ = '''
    __     _______   _   _             _   _
    \ \   / /_   _| | | | |_   _ _ __ | |_(_)_ __   __ _
     \ \ / /  | |   | |_| | | | | '_ \| __| | '_ \ / _` |
      \ V /   | |   |  _  | |_| | | | | |_| | | | | (_| |
       \_/    |_|   |_| |_|\__,_|_| |_|\__|_|_| |_|\__, |
                                                    |___/
        '''
# -----------------------------------------------------------------------
#                               CONFIG INFO
#                       UPDATE WITH YOUR PERSONAL INFO
# -----------------------------------------------------------------------
# Virus Total Intelligence API
VTAPI = os.environ.get('VTAPI')
number_of_result = ""  # fetch this many notifications per API request. 10 by default, 40 max
max_notifications = None  # fetch this many notifications in total
vturl = 'https://www.virustotal.com/api/v3/intelligence/hunting_notifications'

# Create an APP on gmail if you are using double authentication https://support.google.com/accounts/answer/185833
smtp_serv = ""
smtp_port = ""
gmail_login = ""
gmail_pass = ""  # pass from APP
gmail_dest = ""

# Slack Bot config
SLACK_BOT_TOKEN = ""
SLACK_EMOJI = ":rooster:"
SLACK_BOT_NAME = "VT Hunting Bot by @fr0gger_"
SLACK_CHANNEL = ""

# Telegram Bot config
# to get the token just ping @Botfather on telegram and create a new bot /new_bot
# To get a chat id send a message to your bot and go to https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
TOKEN = ""
chat_id = ""
telurl = "https://api.telegram.org/bot{}/".format(TOKEN)

# Microsoft Teams Bot config
TEAMS_CHANNEL_WEBHOOK = ""
# -----------------------------------------------------------------------

# Global Variable
now = dt.datetime.now()
headers = {"x-apikey": VTAPI}
regex = "[A-Fa-f0-9]{64}"  # Detect SHA256
end_message = "From fr0gger with <3"
report_only_unseen_hashes = False
database_connection = sqlite3.connect('vthunting.sqlite')


# Print help
def usage():
    print("usage: vthunting.py [OPTION]")
    print('''    -h, --help              Print this help
    -r, --report            Print the VT hunting report
    -s, --slack_report      Send the report to a Slack channel
    -e, --email_report      Send the report by email
    -t, --telegram_report   Send the report to Telegram
    -m, --teams_report      Send the report to Microsoft Teams
    -j, --json              Print report in json format
    ''')


# Posting to a Slack channel
def send_slack_report(report):
    sc = SlackClient(SLACK_BOT_TOKEN)
    if sc.rtm_connect(with_team_state=False):
        sc.api_call(
            "chat.postMessage",
            icon_emoji=SLACK_EMOJI,
            username=SLACK_BOT_NAME,
            channel=SLACK_CHANNEL,
            text=report
        )
        print("[*] Report have been sent to your Slack channel!")

    else:
        print("[!] Connection failed! Exception traceback printed above.")
        sys.exit()

# Split message to chunks
def split_message(message, chunk_size):
    return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

# Posting to a Telegram channel
def send_telegram_report(report):
    chunk_size=4096
    chunks = split_message(report, chunk_size)
    for chunk in chunks:
        url_gram = telurl + "sendMessage?text={}&chat_id={}".format(chunk, chat_id)
        response = requests.get(url_gram)
        if response:
            response.content.decode("utf8")
            print("[*] Report have been sent to Telegram!")

        else:
            print("[!] Connection to Telegram failed! Check your token or chat id.")

# Posting to a Microsoft Teams channel
def send_teams_report(report):
    try:
        teams_message = pymsteams.connectorcard(TEAMS_CHANNEL_WEBHOOK)
        teams_message.text(report)
        teams_message.send()
        print("[*] Report has been sent to Microsoft Teams!")
    except:
        print("[!] Sending to Microsoft Teams failed!")


# Send email report
def send_email_report(report):
    from_email = gmail_login
    to_email = [gmail_dest]  # ['me@gmail.com', 'bill@gmail.com']
    subject = "Virus Total Hunting Report - " + str(now)
    text = report
    message = 'Subject: {}\n\n{}'.format(subject, text)

    try:
        server = smtplib.SMTP_SSL(smtp_serv, smtp_port)
        server.ehlo()
        server.login(from_email, gmail_pass)
        # Send the mail

        server.sendmail(from_email, to_email, message)
        server.quit()
        print("[*] Report have been sent to your email!")
    except smtplib.SMTPException as e:
        print("[!] SMTP error: " + str(e))
        sys.exit()


def initialize_vthunting_database():
    sql = """
    CREATE TABLE IF NOT EXISTS seen_sha256_hashes (
    sha256 text constraint seen_sha256_hashes_pk primary key,
    notification_date int
    );"""
    try:
        database_connection.execute(sql)
    except Exception as e:
        print("[!] Error with creating the table in the SQLite3 database: " + str(e))
        sys.exit()
    finally:
        database_connection.commit()

def is_notified_on_before(sha256):
    return bool(database_connection.execute(
        'SELECT EXISTS ( SELECT sha256 FROM seen_sha256_hashes WHERE sha256 = ?)', [str(sha256)]).fetchone()[0])


def mark_as_notified_on_before(sha256, notification_date):
    if not is_notified_on_before(sha256):
        try:
            database_connection.execute('INSERT INTO seen_sha256_hashes (sha256, notification_date) values (?, ?)', [str(sha256), int(notification_date)])
        except Exception as e:
            print("[!] Error with storing the hash in the SQLite3 database: " + str(e))
            sys.exit()
        finally:
            database_connection.commit()


# Connect to VT
def api_request():
    fetch_more_notifications = True
    limit = 10
    notifications = []

    if number_of_result:
        limit = int(number_of_result)
    if max_notifications and max_notifications < limit:
        limit = max_notifications

    params = {
        'limit': limit
    }

    while fetch_more_notifications:
        response = requests.get(vturl, params=params, headers=headers)
        result = json.loads(response.text)

        for json_row in result['data']:
            notifications.append(json_row)

        # Response has cursor, more notifications can be fetched
        if 'cursor' in result['meta'].keys():
            params.update({'cursor': result['meta']['cursor']})

            if max_notifications:
                # reached limit, stop fetching more notifications
                if len(notifications) == max_notifications:
                    fetch_more_notifications = False
                # limit amount of notifications to fetch on next iteration, to reach max
                elif len(notifications) + limit > max_notifications:
                    params.update({'limit': max_notifications - len(notifications)})
        else:
            fetch_more_notifications = False

    # print result
    report = ["Latest report from " + str(now),
              "-------------------------------------------------------------------------------------"]

    for json_row in notifications:
        subject = json_row["attributes"]["rule_name"]
        date = json_row["attributes"]["date"]
        tags = json_row["attributes"]["tags"]
        sha2 = re.search(regex, str(tags)).group()
        tags.remove(sha2)

        if not report_only_unseen_hashes or not is_notified_on_before(sha2):
            mark_as_notified_on_before(sha2, date)

            report.append("Rule name: " + subject)
            report.append("Match date: " + datetime.utcfromtimestamp(date).strftime('%d/%m/%Y %H:%M:%S'))
            report.append("SHA256: " + str(sha2))
            report.append("Tags: " + str([str(tags) for tags in tags]).replace("'", ""))

            report.append("-------------------------------------------------------------------------------------")

    report.append(end_message)
    report = ("\n".join(report))

    return report, notifications


def main():
    print(__asciiart__)
    print("\t         " + __team__ + " | " + __author__)
    print("\tGet latest hunting notification from VirusTotal\n")

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hrsetmj",
                                   ["help", "report", "slack_report", "email_report", "telegram_report", "teams_report", "json"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    initialize_vthunting_database()

    try:
        report, result_json = api_request()
    except(ConnectionError, ConnectTimeout, KeyError) as e:
        print("[!] Error with the VT API: " + str(e))
        sys.exit()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-r", "--report"):
            print(report)
        elif o in ("-s", "--slack_report"):
            send_slack_report(report)
        elif o in ("-e", "--email_report"):
            send_email_report(report)
        elif o in ("-t", "--telegram_report"):
            send_telegram_report(report)
        elif o in ("-m", "--teams_report"):
            send_teams_report(report)
        elif o in ("-j", "--json"):
            print(json.dumps(result_json, sort_keys=True, indent=4))

    database_connection.close()


if __name__ == '__main__':
    main()
