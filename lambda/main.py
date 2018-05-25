#!/usr/bin/env python

import os
import socket
import ssl
import datetime
import logging

import boto3
from botocore.vendored import requests

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


# Credit to https://serverlesscode.com/post/ssl-expiration-alerts-with-lambda/
def ssl_expiry_datetime(hostname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, 443))
    except socket.gaierror:
        return "Not a valid site"
    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)

def ssl_valid_time_remaining(hostname):
    """Get the number of days left in a cert's lifetime."""
    expires = ssl_expiry_datetime(hostname)
    try:
        logger.debug(
            "SSL cert for %s expires at %s",
            hostname, expires.isoformat()
        )
        return expires - datetime.datetime.utcnow()
    except AttributeError:
        return "Not a valid site"

def ssl_expires_in(hostname, buffer_days=14):
    """Check if `hostname` SSL cert expires is within `buffer_days`.

    Raises `AlreadyExpired` if the cert is past due
    """
    remaining = ssl_valid_time_remaining(hostname)

    # if the cert expires in less than two weeks, we should reissue it
    try:
        if remaining < datetime.timedelta(days=0):
            # cert has already expired - uhoh!
            raise AlreadyExpired("Cert expired %s days ago" % remaining.days)
        elif remaining < datetime.timedelta(days=buffer_days):
            # expires sooner than the buffer
            print('{} Expires in {}'.format(hostname, remaining <
                datetime.timedelta(days=buffer_days)))
            return True
        else:
            # everything is fine
            print('{} Expires in {}'.format(hostname, remaining))
            return False
    except TypeError:
        return "Not a valid site"

def handler(event, context):
    # event is a cron like event, not interesting.
    client = boto3.client('ssm')
    paginator = client.get_paginator('get_parameters_by_path')
    response_iterator = paginator.paginate(Path=os.environ['APP_PATH'])
    for i in response_iterator:
        for j in i['Parameters']:
            site = os.path.basename(j['Name'])
            pd_routing_key = j['Value']
            ssl_expires_in(site, 14)

if __name__== "__main__":
    event = {}
    context = {}
    os.environ['AWS_DEFAULT_REGION'] = 'ca-central-1'
    os.environ['APP_PATH'] = '/testpath'
    handler(event, context)

