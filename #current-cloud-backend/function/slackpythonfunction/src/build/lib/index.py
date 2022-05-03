# reference example from: https://slack.dev/bolt-python/concepts#lazy-listeners
# https://www.xiegerts.com/post/slack-app-bolt-python-amplify/

# sudo pipenv shell
# To update AWS run amplify push
# SUGGEST: CUSTOM LOGIC (FOR EXAMPLE, WARNING MESSAGE IF > 1 SPF RECORD)

from distutils.debug import DEBUG
import time
from posixpath import split
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
import dns.resolver
from datetime import datetime
import whois
import logging
import traceback


# process_before_response must be True when running on FaaS
app = App(process_before_response=True)


def respond_to_slack_within_3_seconds(body, ack):

    text = body.get("text")

    if text is None or len(text.split()) != 2:
        ack("To command me, please use the following convention: /records + 'domain name' + 'selector'. If you don't know selector, just type 'google'. Ex: /records pyrashyut.com google ")
        return
    else:
        ack(f"Checking domain, SPF, DMARC and DKIM records for {text}")


def run_long_process(respond, body):
    time.sleep(8)  # longer than 3 seconds

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
        f"That's it. If you want to validate your results for domain {domain} with selector {selector}, go to mxtoolbox.com")


# Checking Domain
# REFERENCE https://github.com/averi/python-scripts/blob/master/check-domain-expiration.py


def check_domain(respond, body, logger):
    print(1)
    time.sleep(5)
    print(2)

    split_body = body['text'].split()
    print(3)
    # Decouple request into args
    domain = split_body[0]
    print(4)
    try:
        print(5)
        domain = whois.query(domain)
        print(6)
        respond(f"Domain {domain.name} was created {domain.creation_date}")
        print(7)
    except Exception as e:
        print(8)
        print(e)
        logger.error(f"The error2 is {traceback.format_exc()}")
        print(9)
        respond(" [FAIL] Domain Creation Date Not Found")


app.command("/records")(
    ack=respond_to_slack_within_3_seconds,  # responsible for calling `ack()`
    # unable to call `ack()` / can have multiple functions
    lazy=[run_long_process, check_domain]
)


@app.error
def custom_error_handler(error, body, logger):
    logger.exception(f"Error: {error}")
    logger.info(f"Request body: {body}")


def handler(event, context):
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
