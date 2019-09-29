# -*- coding: utf-8 -*-

import base64
import json
import ovh
import random
import string
import time

import dns
import dns.name
import dns.query
import dns.resolver


# this is the entry point
def ovh_update_dns(logger, event, context):
    logger.debug("[route53] Updating DNS configuration")

    sourceIp = event['sourceIp']
    previousIp = event['previousIp']
    domain = event['domain']
    subDomain = event['name']

    if 'dnsAuth' not in event:
        logger.critical('[ovh] Couldn\'t find OVH authentication credentials. Aborting DNS update.')
        return {
            'error': "Couldn't find DNS provider authentication details. DNS not updated.",
            'sourceIp': event['sourceIp'],
            'previousIp': previousIp
        }

    dnsAuth = json.loads(base64.b64decode(event['dnsAuth']))[0]

    client = ovh.Client(**dnsAuth)

    try:
        result = client.get('/domain/zone/{0}/record'.format(domain),
            fieldType='A',
            subDomain=subDomain,
        )
    except ovh.exceptions.InvalidCredential as e:
        logger.error("[ovh] Failed to list DNS zone '{0}'".format(domain))
        logger.error("[ovh] Error: {0}".format(e))
        return {
            'error': "Couldn't not list DNS zone. DNS not updated.",
            'sourceIp': event['sourceIp'],
            'previousIp': previousIp
        }

    if result: # clean the DNS record from all previous value (because it's ephemeral)
        for x in range(len(result)):
            logger.debug("[ovh] Removing DNS entry '/domain/zone/{0}/record/{1}'".format(domain, result[x]))
            client.delete("/domain/zone/{0}/record/{1}".format(domain, result[x]))

    logger.debug("[ovh] The DNS entry '{0}.{1}' doesn't exist".format(subDomain, domain))
    result = client.post('/domain/zone/{0}/record'.format(domain),
        fieldType='A',
        subDomain=subDomain,
        ttl=60,
        target=sourceIp)

    result = client.post('/domain/zone/{0}/refresh'.format(domain))

    # since this is a lambda function, it may not be a good idea to wait for DNS sync
    # especially when hooked to API Gateway as the gateway timeout is 30 seconds
    # _wait_ovh_record_insync(this is not implemented)

    return True


