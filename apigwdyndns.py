# -*- coding: utf-8 -*-

import boto3
import json
import logging
import os
import ovh

import dns
import dns.name
import dns.query
import dns.resolver

from botocore.config import Config
from botocore.exceptions import ClientError
from time import sleep

logger = logging.getLogger("apigw-dyndns")
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

def _get_dns_record(logger, fqdn):
    answer = None

    try:
        r = dns.resolver.query(fqdn, 'A')
    except dns.resolver.NXDOMAIN:
        logger.warning("[GET] Receive exception NXDOMAIN for '{0}'".format(fqdn))
    except dns.resolver.Timeout:
        logger.error("[GET] Receive exception Timeout for '{0}'".format(fqdn))
    except dns.exception.DNSException:
        logger.error("[GET] Receive exception DNSException for '{0}'".format(fqdn))

    if len(r.response.answer[0]) > 0:
        for x in xrange(len(r.response.answer[0])): # if past executions have failed, ensure to iterte over all TXT records
            answer = '{0}'.format(r.response.answer[0][x])
            logger.debug("[GET] Got '{0}', looking for '{1}'".format(answer, fqdn))

    return answer

def _update_security_group(logger, name, sourceIp, rules, region):
    
    ec2 = boto3.client('ec2', region_name=region)

    kwargs = {
        'DryRun': False,
        'GroupNames': [ name ]
    }
    r = ec2.describe_security_groups(**kwargs)
    sg = r['SecurityGroups'][0]
    for ingress in sg['IpPermissions']:
        kwargs = {
            'DryRun': False,
            'GroupName': name,
            'IpPermissions': [ ingress ]
        }
        r2 = ec2.revoke_security_group_ingress(**kwargs)

    for proto, ports in rules.iteritems():
        for port in ports:
            kwargs = {
                'DryRun': False,
                'GroupName': name,
                'IpProtocol': proto,
                'FromPort': port,
                'ToPort': port,
                'CidrIp': '{0}/32'.format(sourceIp)
            }
            r = ec2.authorize_security_group_ingress(**kwargs)

def get_settings_handler(event, context):
    logger.debug("[GET] Starting execution of API Gateway DynDNS")

    domain = event['domain']
    subDomain = event['name']
    previousIp = _get_dns_record(logger, '{0}.{1}'.format(subDomain, domain))

    return {
        'sourceIp': event['sourceIp'],
        'previousIp': previousIp
    }
        

def update_settings_handler(event, context):
    logger.debug("[POST] Starting execution of API Gateway DynDNS")

    sourceIp = event['sourceIp']
    domain = event['domain']
    subDomain = event['name']

    previousIp = _get_dns_record(logger, '{0}.{1}'.format(subDomain, domain))
    if sourceIp == previousIp:
        return {
            'sourceIp': sourceIp,
            'previousIp': previousIp,
            'status': 'NotUpdated',
            'message': "sourceIp and previousIp are identical, DNS record '{0}.{1}' not updated.".format(subDomain, domain)
        }
    event['previousIp'] = previousIp

    dns_provider = "{0}_dns".format(event['dnsProvider'])
    dns_provider_func = "{0}_update_dns".format(event['dnsProvider'])

    dns_provider_update_dns = getattr(__import__(dns_provider, fromlist=[dns_provider_func]), dns_provider_func)
    r = dns_provider_update_dns(logger, event, context)

    if r != True:
        return r

    if event['name'] == 'aurelien' and event['sgname']:
        _update_security_group(logger, event['sgname'], event['sourceIp'], event['sgrules'], event['ec2region'])

    return {
        'sourceIp': event['sourceIp'],
        'previousIp': previousIp,
        'status': 'Updated'
    }


def lambda_handler(event, context):
    logger.debug("[main] Starting execution of API Gateway DynDNS")
    logger.debug(json.dumps(event, ensure_ascii=False, sort_keys=True))
    event['sgrules'] = {
        'udp': { 443 },
        'tcp': { 443, 3129, 5000 },
        'icmp': { -1 }
    }

    routing = {
        'GET': get_settings_handler, 
        'POST': update_settings_handler
    }

    if 'httpMethod' in event.keys() and event['httpMethod'] in routing.keys():
        r = routing[event['httpMethod']](event, context)
    else:
        r =  get_settings_handler(event, context)

    logger.debug(json.dumps(r, ensure_ascii=False, sort_keys=True))

    return r
