# reference example from: https://slack.dev/bolt-python/concepts#lazy-listeners
# https://www.xiegerts.com/post/slack-app-bolt-python-amplify/

# sudo pipenv shell
# To update AWS run amplify push
# SUGGEST: CUSTOM LOGIC (FOR EXAMPLE, WARNING MESSAGE IF > 1 SPF RECORD)

import time
from distutils.debug import DEBUG
from posixpath import split
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
import dns.resolver
from datetime import datetime, timedelta
import whois
import logging
import traceback


# process_before_response must be True when running on FaaS
app = App(process_before_response=True)


def respond_to_slack_within_3_seconds(body, ack):
    print(body)
    print(ack)
    text = body.get("text")
    print(text)

    if text is None or len(text.split()) != 2:
        ack("To command me, please use the following convention: /records + 'domain name' + 'selector'. If you don't know selector, just type 'google'. Ex: /records pyrashyut.com google ")
    else:
        ack(f"Checking domain, SPF, DMARC and DKIM records for {text}")


def check_records(respond, body):
    time.sleep(6)  # longer than 3 seconds

    split_body = body['text'].split()

    # Decouple request into args
    domain = split_body[0]
    selector = split_body[1]

# Testing SPF
#
    try:
        test_spf = dns.resolver.resolve(domain, 'TXT')
        for dns_data in test_spf:
            if 'spf1' in str(dns_data):
                respond(f"  [PASS] SPF record found   :{dns_data}")
    except:
        respond("  [FAIL] SPF record not found.")
        pass

    # Testing DMARC
#
    try:
        test_dmarc = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for dns_data in test_dmarc:
            if 'DMARC1' in str(dns_data):
                respond(f"  [PASS] DMARC record found  : {dns_data}")
    except:
        respond("  [FAIL] DMARC record not found.")
        pass

# Testing DKIM
#
    try:
        test_dkim = dns.resolver.resolve(
            selector + '._domainkey.' + domain, 'TXT')
        for dns_data in test_dkim:
            if 'DKIM1' in str(dns_data):
                respond(f"  [PASS] DKIM record found  : {dns_data}")
    except:
        respond("  [FAIL] DKIM record not found.")
        pass

    respond(
        f"That's it. If you want to validate your results for domain {domain} with selector {selector}, go to mxtoolbox.com. To check MX Records, use '/mx {domain}' command.")


# Checking Domain
# REFERENCE https://github.com/averi/python-scripts/blob/master/check-domain-expiration.py


def check_domain(respond, body):
    time.sleep(4)

    split_body = body['text'].split()

    # Decouple request into args
    domain = split_body[0]
    now = datetime.now()

    try:
        domain_data = whois.whois(domain)
    except whois.parser.PywhoisError as e:
        print(e)
        respond(" [FAIL] Domain Creation Date Not Found")

    if type(domain_data.creation_date) == list:
        domain_data.creation_date = domain_data.creation_date[0]
    else:
        domain_data.creation_date = domain_data.creation_date

    domain_creation_date = str(
        domain_data.creation_date.day) + '/' + str(domain_data.creation_date.month) + '/' + str(domain_data.creation_date.year)

    timedelta = now - domain_data.creation_date
    days_from_creation = timedelta.days

    if days_from_creation <= 90:
        respond(
            f"Domain was created on {domain_creation_date}, {days_from_creation} days ago. Oops, this domain can be too fresh to start campaigns.")
    else:
        respond(
            f"Domain was created on {domain_creation_date}, {days_from_creation} days ago. This domain is ready for some action.")


def check_mx_records(respond, body):
    # time.sleep(5)
    split_body = body['text'].split()

    # Decouple request into args
    domain = split_body[0]

# Testing MX Record
#
    try:
        test_mx = dns.resolver.resolve(domain, 'MX')
        for dns_data in test_mx:
            if 'mx' in str(dns_data):
                respond(f"  [PASS] MX record found   :{dns_data}")
    except Exception as e:
        print(e)
        respond("  [FAIL] MX record not found.")
        pass


app.command("/records")(
    ack=respond_to_slack_within_3_seconds,  # responsible for calling `ack()`
    # unable to call `ack()` / can have multiple functions
    lazy=[check_records, check_domain]
)

app.command("/mx")(
    ack=respond_to_slack_within_3_seconds,  # responsible for calling `ack()`
    # unable to call `ack()` / can have multiple functions
    lazy=[check_mx_records]
)


def handler(event, context):
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
