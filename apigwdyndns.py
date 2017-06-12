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
handler.setLevel(logging.ERROR)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.ERROR)

def _reset_route53_record(logger, zone_id, zone_name, rr_fqdn):
    """
    Remove previous entry from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4'))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    rr_list = []
    results = r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordType='A',
                StartRecordName=rr_fqdn,
                MaxItems='100')

    while True:
        rr_list = rr_list + results['ResourceRecordSets']
        if results['IsTruncated'] == False:
            break

        results = r53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordType='A',
            StartRecordName=results['NextRecordName'])

    r53_changes = { 'Changes': []}
    for rr in rr_list:
        if rr['Name'] == rr_fqdn and rr['Type'] == 'A':
            r53_changes['Changes'].append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': rr['Name'],
                    'Type': rr['Type'],
                    'TTL': rr['TTL'],
                    'ResourceRecords': rr['ResourceRecords']
                }
            })
            try:
                res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
                logger.info("[route53] Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                logger.error("[route53] Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                logger.error("[route53] Error: {0}".format(e))
                return None

            break

    logger.debug("[route53] No Resource Record to delete.")
    return False

def _create_route53_record(logger, zone_id, zone_name, rr_fqdn, rr_type, rr_value):
    """
    Create the required dns record for letsencrypt to verify
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', ))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = { 'Changes': [{
        'Action': 'CREATE',
        'ResourceRecordSet': {
            'Name': rr_fqdn,
            'Type': rr_type,
            'TTL': 20,
            'ResourceRecords': [{
                'Value': rr_value
            }]
        }
    }]}

    try:
        res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
        logger.info("[route53] Create letsencrypt verification record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        return res

    except ClientError as e:
        logger.error("[route53] Failed to create resource record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

def _wait_record_insync(logger, r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4'))

    logger.info("[route53] Waiting for DNS to synchronize with new value")
    timeout = 60

    status = r53_status['ChangeInfo']['Status']
    while status != 'INSYNC':
        sleep(1)
        timeout = timeout-1
        try:
            r53_status = r53.get_change(Id=r53_status['ChangeInfo']['Id'])
            status = r53_status['ChangeInfo']['Status']

            if timeout == -1:
                return False

        except ClientError as e:
            logger.error("[route53] Failed to retrieve record creation status.")
            logger.error("[route53] Error: {0}".format(e))
            return None

    logger.debug("[route53] Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

def _get_route53_zone_id(logger, zone_name):
    r53 = boto3.client('route53', config=Config(signature_version='v4'))

    if zone_name.endswith('.') is not True:
        zone_name += '.'

    try:
        dn = ''
        zi = ''
        zone_list = r53.list_hosted_zones_by_name(DNSName=zone_name)
        while True:
            for zone in zone_list['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

            if zone_list['IsTruncated'] is not True:
                return None

            dn = zone_list['NextDNSName']
            zi = zone_list['NextHostedZoneId']

            logger.debug("[route53] Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        logger.error("[route53] Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

    return None

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
        print json.dumps(ingress, ensure_ascii=False, sort_keys=True)
        kwargs = {
            'DryRun': False,
            'GroupName': name,
            'IpPermissions': [ ingress ]
        }
        r2 = ec2.revoke_security_group_ingress(**kwargs)
        print json.dumps(r2, ensure_ascii=False, sort_keys=True)
        print ""

    for proto, ports in rules.iteritems():
        for port in ports:
            print "proto: {0}, port: {1}".format(proto, port)
            kwargs = {
                'DryRun': False,
                'GroupName': name,
                'IpProtocol': proto,
                'FromPort': port,
                'ToPort': port,
                'CidrIp': '{0}/32'.format(sourceIp)
            }
            r = ec2.authorize_security_group_ingress(**kwargs)
            print json.dumps(r, ensure_ascii=False, sort_keys=True)
            print ""

    

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


    zone_id = _get_route53_zone_id(logger, domain)

    r = _reset_route53_record(logger, zone_id, domain, '{0}.{1}'.format(subDomain, domain))
    if r != True:
        logger.warning("[POST] Failed to delete DNS record")

    r = _create_route53_record(logger, zone_id, domain, '{0}.{1}'.format(subDomain, domain), 'A', sourceIp)
    if r == None:
        logger.error("[POST] Failed to create DNS entry '{0}.{1}' with value '{2}'.".format(subDomain, domain, sourceIp))
        return {
            'error': "Failed to create DNS entry '{0}.{1}' with value '{2}'.".format(subDomain, domain, sourceIp),
            'sourceIp': event['sourceIp'],
            'previousIp': answer
        }

    # _wait_record_insync(logger, r)

    _update_security_group(logger, event['sgname'], event['sourceIp'], event['sgrules'], event['ec2region'])
    return {
        'sourceIp': event['sourceIp'],
        'previousIp': previousIp,
        'status': 'Updated'
    }


def lambda_handler(event, context):
    logger.debug("[main] Starting execution of API Gateway DynDNS")
    logger.debug(json.dumps(event, ensure_ascii=False, sort_keys=True))
    #event['domain'] = 'menfin.net'
    #event['sgname'] = 'PROXY'
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
