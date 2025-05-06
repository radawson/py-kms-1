#!/usr/bin/env python3

import binascii
import logging
import time
import uuid
import socket

from pykms_Structure import Structure
from pykms_DB2Dict import kmsDB2Dict
from pykms_PidGenerator import epidGenerator
from pykms_Filetimes import filetime_to_dt
from pykms_Misc import logger_create, KmsParserException, KmsParserHelp, kms_parser_get
from pykms_Format import justify, byterize, enco, deco, pretty_printer

#--------------------------------------------------------------------------------------------------------------------------------------------------------

loggersrv = logging.getLogger('logsrv')
loggerclt = logging.getLogger('logclt')

class UUID(Structure):
        commonHdr = ()
        structure = (
                ('raw', '16s'),
        )

        def get(self):
                return uuid.UUID(bytes_le = enco(str(self), 'latin-1'))

class kmsBase:
        def __init__(self, data, srv_config):
                self.data = data
                self.srv_config = srv_config
                
        class kmsRequestStruct(Structure):
                commonHdr = ()
                structure = (
                        ('versionMinor',            '<H'),
                        ('versionMajor',            '<H'),
                        ('isClientVm',              '<I'),
                        ('licenseStatus',           '<I'),
                        ('graceTime',               '<I'),
                        ('applicationId',           ':', UUID),
                        ('skuId',                   ':', UUID),
                        ('kmsCountedId' ,           ':', UUID),
                        ('clientMachineId',         ':', UUID),
                        ('requiredClientCount',     '<I'),
                        ('requestTime',             '<Q'),
                        ('previousClientMachineId', ':', UUID),
                        ('machineName',             'u'),
                        ('_mnPad',                  '_-mnPad', '126-len(machineName)'),
                        ('mnPad',                   ':'),
                )

                def getMachineName(self):
                        return self['machineName'].decode('utf-16le')
                
                def getLicenseStatus(self):
                        return kmsBase.licenseStates[self['licenseStatus']] or "Unknown"

        class kmsResponseStruct(Structure):
                commonHdr = ()
                structure = (
                        ('versionMinor',         '<H'),
                        ('versionMajor',         '<H'),
                        ('epidLen',              '<I=len(kmsEpid)+2'),
                        ('kmsEpid',              'u'),
                        ('clientMachineId',      ':', UUID),
                        ('responseTime',         '<Q'),
                        ('currentClientCount',   '<I'),
                        ('vLActivationInterval', '<I'),
                        ('vLRenewalInterval',    '<I'),
                )

        class GenericRequestHeader(Structure):
                commonHdr = ()
                structure = (
                        ('bodyLength1',  '<I'),
                        ('bodyLength2',  '<I'),
                        ('versionMinor', '<H'),
                        ('versionMajor', '<H'),
                        ('remainder',    '_'),
                )

        licenseStates = {
                0 : "Unlicensed",
                1 : "Activated",
                2 : "Grace Period",
                3 : "Out-of-Tolerance Grace Period",
                4 : "Non-Genuine Grace Period",
                5 : "Notifications Mode",
                6 : "Extended Grace Period",
        }

        licenseStatesEnum = {
                'unlicensed' : 0,
                'licensed' : 1,
                'oobGrace' : 2,
                'ootGrace' : 3,
                'nonGenuineGrace' : 4,
                'notification' : 5,
                'extendedGrace' : 6
        }

        
        def getPadding(self, bodyLength):
                ## https://forums.mydigitallife.info/threads/71213-Source-C-KMS-Server-from-Microsoft-Toolkit?p=1277542&viewfull=1#post1277542
                return 4 + (((~bodyLength & 3) + 1) & 3)

        def serverLogic(self, kmsRequest):
                pretty_printer(num_text = 15, where = "srv")
                kmsRequest = byterize(kmsRequest)
                loggersrv.debug("KMS Request Bytes: \n%s\n" % justify(deco(binascii.b2a_hex(enco(str(kmsRequest), 'latin-1')), 'latin-1')))                         
                loggersrv.debug("KMS Request: \n%s\n" % justify(kmsRequest.dump(print_to_stdout = False)))
                                        
                clientMachineId = kmsRequest['clientMachineId'].get()
                applicationId = kmsRequest['applicationId'].get()
                skuId = kmsRequest['skuId'].get()
                requestDatetime = filetime_to_dt(kmsRequest['requestTime'])
                                
                # Localize the request time, if module "tzlocal" is available.
                try:
                        from tzlocal import get_localzone
                        from pytz.exceptions import UnknownTimeZoneError
                        try:
                                tz = get_localzone()
                                local_dt = requestDatetime.astimezone(tz)
                        except UnknownTimeZoneError:
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}Unknown time zone ! Request time not localized.{end}")
                        except ImportError:
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}Module 'tzlocal' not available ! Request time not localized.{end}")
                                local_dt = requestDatetime
                # *** Add generic exception handler to catch any localization errors ***
                except Exception as e:
                        loggersrv.error("Error during timezone localization: %s", str(e), exc_info=True)
                        pretty_printer(log_obj = loggersrv.error, 
                                       put_text = "{reverse}{red}{bold}Timezone localization failed unexpectedly! Using UTC time.{end}")
                        local_dt = requestDatetime # Fallback to original UTC time

                # Activation threshold.
                # https://docs.microsoft.com/en-us/windows/deployment/volume-activation/activate-windows-10-clients-vamt                
                MinClients = kmsRequest['requiredClientCount'] 
                RequiredClients = MinClients * 2
                if self.srv_config["clientcount"] != None:
                        if 0 < self.srv_config["clientcount"] < MinClients:
                                # fixed to 6 (product server) or 26 (product desktop)
                                currentClientCount = MinClients + 1
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}Not enough clients ! Fixed with %s, but activated client \
could be detected as not genuine !{end}" %currentClientCount)
                        elif MinClients <= self.srv_config["clientcount"] < RequiredClients:
                                currentClientCount = self.srv_config["clientcount"]
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}With count = %s, activated client could be detected as not genuine !{end}" %currentClientCount)
                        elif self.srv_config["clientcount"] >= RequiredClients:
                                # fixed to 10 (product server) or 50 (product desktop)
                                currentClientCount = RequiredClients
                                if self.srv_config["clientcount"] > RequiredClients:
                                        pretty_printer(log_obj = loggersrv.warning,
                                                       put_text = "{reverse}{yellow}{bold}Too many clients ! Fixed with %s{end}" %currentClientCount)
                else:
                        # fixed to 10 (product server) or 50 (product desktop)
                        currentClientCount = RequiredClients     

                        # *** Log calculated client count ***
                        loggersrv.debug("Calculated currentClientCount: %d (Required: %d, Configured: %s)", 
                                        currentClientCount, MinClients, str(self.srv_config.get("clientcount", "Default")))

                        
                # Get a name for SkuId, AppId.        
                kmsdb = kmsDB2Dict()
                appName, skuName = str(applicationId), str(skuId) # Initialize with raw IDs
                foundSku = False
                foundApp = False

                try:
                    appitems = kmsdb[2] # Index 2 should contain AppItems
                    for appitem in appitems:
                        # Try to find App Name first for this AppItem
                        tempAppName = appName # Default to existing appName
                        try:
                            if not foundApp and 'Id' in appitem and uuid.UUID(appitem['Id']) == applicationId:
                                # Get the display name from the AppItem
                                tempAppName = appitem.get('DisplayName', appName)
                                # Special handling for Office products - extract the main product name
                                if 'Office' in tempAppName:
                                    tempAppName = 'Office'
                                foundApp = True # Mark App as found
                        except ValueError:
                             loggersrv.warning("Invalid UUID format for AppItem ID '%s'", appitem.get('Id', 'N/A'))
                        except Exception as e:
                             loggersrv.error("Unexpected error comparing AppID %s with AppItem %s: %s", applicationId, appitem.get('Id', 'N/A'), e, exc_info=True)
                        
                        # Now check KmsItems and SkuItems within this AppItem
                        kmsitems = appitem.get('KmsItems', [])
                        for kmsitem in kmsitems:
                            if foundSku: break # Already found in previous KmsItem
                            skuitems = kmsitem.get('SkuItems', [])
                            for skuitem in skuitems:
                                try:
                                    if 'Id' in skuitem and uuid.UUID(skuitem['Id']) == skuId:
                                        skuName = skuitem.get('DisplayName', skuName)
                                        # If we find the Sku, associate it with the AppName found (or default) for this AppItem loop
                                        appName = tempAppName
                                        foundSku = True
                                        break # Exit skuitems loop
                                except ValueError:
                                    # Log specific error if UUID conversion fails, but don't reset skuName
                                    loggersrv.warning("Invalid UUID format for SkuItem ID '%s' in App '%s'", 
                                                    skuitem.get('Id', 'N/A'), appitem.get('DisplayName', 'Unknown'))
                                except Exception as e:
                                     # Log unexpected errors during comparison
                                     loggersrv.error("Unexpected error comparing SkuID %s with SkuItem %s in App '%s': %s", 
                                                     skuId, skuitem.get('Id', 'N/A'), appitem.get('DisplayName', 'Unknown'), e, exc_info=True)

                            if foundSku:
                                break # Exit kmsitems loop
                        
                        if foundSku:
                            break # Exit appitems loop (we found the Sku and its associated App)

                except IndexError:
                    loggersrv.error("kmsdb structure invalid, index 2 (AppItems) not found.")
                except Exception as e:
                    loggersrv.error("Unexpected error during product name lookup: %s", e, exc_info=True)

                # Log warning only if SkuName wasn't updated
                if not foundSku:
                     pretty_printer(log_obj = loggersrv.warning,
                                    put_text = "{reverse}{yellow}{bold}Can't find a name for this product ! (SkuID: %s){end}" % skuId)
                # Log warning if AppName wasn't updated (optional)
                # if not foundApp:
                #      pretty_printer(log_obj = loggersrv.warning,
                #                     put_text = "{reverse}{yellow}{bold}Can't find a name for this application group ! (AppID: %s){end}" % applicationId)

                # *** Log product name lookup results ***
                loggersrv.debug("Product Name Lookup: AppName='%s', SkuName='%s'", appName, skuName)

                infoDict = {
                        "machineName" : kmsRequest.getMachineName(),
                        "clientMachineId" : str(clientMachineId),
                        "appId" : appName,
                        "skuId" : skuName,
                        "licenseStatus" : kmsRequest.getLicenseStatus(),
                        "requestTime" : int(time.time()),
                        "kmsEpid" : None,
                        "ipAddress" : self.srv_config.get('raddr', ('Unknown', 0))[0]  # Get client IP from raddr tuple
                }

                # Look up names from IDs, default to ID if name not found
                appName = kmsdb.appItems.get(infoDict['appId'], {}).get('DisplayName', infoDict['appId'])
                # Correcting Sku lookup: Iterate through KmsItems to find the SkuItem
                skuName = infoDict['skuId'] # Default to ID
                for kmsItem in kmsdb.kmsItems.values():
                    if infoDict['skuId'] in kmsItem.get('SkuItems', {}):
                        skuName = kmsItem['SkuItems'][infoDict['skuId']].get('DisplayName', infoDict['skuId'])
                        break # Found the SKU, exit loop
                
                infoDict['applicationName'] = appName
                infoDict['skuName'] = skuName

                # Log client info
                loggersrv.info("Machine Name: %s" % infoDict['machineName'])
                loggersrv.info("Client Machine ID: %s" % infoDict["clientMachineId"])
                loggersrv.info("Application ID: %s" % infoDict["appId"])
                loggersrv.info("SKU ID: %s" % infoDict["skuId"])
                loggersrv.info("License Status: %s" % infoDict["licenseStatus"])
                loggersrv.info("Request Time: %s" % local_dt.strftime('%Y-%m-%d %H:%M:%S %Z (UTC%z)'))
                loggersrv.info("Client IP: %s" % infoDict["ipAddress"])
                
                if self.srv_config['loglevel'] == 'MININFO':
                        loggersrv.mininfo("", extra = {'host': str(self.srv_config['raddr']),
                                                       'status' : infoDict["licenseStatus"],
                                                       'product' : infoDict["skuId"]})
                # Update database.
                if self.srv_config.get('db_instance'):
                        try:
                             self.srv_config['db_instance'].update_client(infoDict)
                             loggersrv.debug("Database updated for client %s", infoDict["clientMachineId"])
                        except Exception as e:
                             loggersrv.error("Failed to update database for client %s: %s", infoDict["clientMachineId"], e, exc_info=True)
                # else:
                     # Legacy database handling (commented out)
                     # if self.srv_config['sqlite']:
                     #         sql_initialize(self.srv_config['sqlite'])
                     #         sql_update(self.srv_config['sqlite'], infoDict)

                # *** Log before calling createKmsResponse ***
                loggersrv.debug("Calling createKmsResponse with currentClientCount: %d", currentClientCount)

                return self.createKmsResponse(kmsRequest, currentClientCount, appName)

        def createKmsResponse(self, kmsRequest, currentClientCount, appName):
                # *** Wrap in try/except to catch errors during response creation ***
                try:
                        response = self.kmsResponseStruct()
                        response['versionMinor'] = kmsRequest['versionMinor']
                        response['versionMajor'] = kmsRequest['versionMajor']
                        
                        if not self.srv_config.get("epid"): # Use .get() for safer access
                                response["kmsEpid"] = epidGenerator(kmsRequest['kmsCountedId'].get(), kmsRequest['versionMajor'],
                                                                    self.srv_config.get("lcid", 1033)).encode('utf-16le') # Provide default LCID
                        else:
                                response["kmsEpid"] = self.srv_config["epid"].encode('utf-16le')

                        response['clientMachineId'] = kmsRequest['clientMachineId']
                        # rule: timeserver - 4h <= timeclient <= timeserver + 4h, check if is satisfied (TODO).
                        response['responseTime'] = kmsRequest['requestTime']
                        response['currentClientCount'] = currentClientCount
                        response['vLActivationInterval'] = self.srv_config.get("activation", 120) # Use .get() and provide defaults
                        response['vLRenewalInterval'] = self.srv_config.get("renewal", 10080)

                        # Update database if enabled
                        if self.srv_config.get('db_instance'):
                                self.srv_config['db_instance'].update_epid(kmsRequest, response, appName)
                        # else:
                                # Update legacy sqlite if enabled
                                # if self.srv_config['sqlite']:
                                #      sql_update_epid(self.srv_config['sqlite'], kmsRequest, response, appName)

                        loggersrv.info("Server ePID: %s" % response["kmsEpid"].decode('utf-16le'))

                        # *** Log the fully populated response structure before returning ***
                        loggersrv.debug("Populated kmsResponseStruct before returning:\n%s", response.dump(print_to_stdout=False))
                                
                        return response
                except Exception as e:
                        loggersrv.error("Error during createKmsResponse: %s", str(e), exc_info=True)
                        # Optionally return None or raise a specific exception to indicate failure
                        return None # Indicate failure to the caller


import pykms_RequestV4, pykms_RequestV5, pykms_RequestV6, pykms_RequestUnknown

def generateKmsResponseData(data, srv_config):
        version = kmsBase.GenericRequestHeader(data)['versionMajor']
        currentDate = time.strftime("%a %b %d %H:%M:%S %Y")

        if version == 4:
                loggersrv.info("Received V%d request on %s." % (version, currentDate))
                messagehandler = pykms_RequestV4.kmsRequestV4(data, srv_config)     
        elif version == 5:
                loggersrv.info("Received V%d request on %s." % (version, currentDate))
                messagehandler = pykms_RequestV5.kmsRequestV5(data, srv_config)
        elif version == 6:
                loggersrv.info("Received V%d request on %s." % (version, currentDate))
                messagehandler = pykms_RequestV6.kmsRequestV6(data, srv_config)
        else:
                loggersrv.info("Unhandled KMS version V%d." % version)
                messagehandler = pykms_RequestUnknown.kmsRequestUnknown(data, srv_config)
                
        return messagehandler.executeRequestLogic()
