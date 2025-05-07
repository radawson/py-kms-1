#!/usr/bin/env python3

import os
import xml.etree.ElementTree as ET

#---------------------------------------------------------------------------------------------------------------------------------------------------------

def kmsDB2Dict():
        """Parses the KmsDataBase.xml file and converts its contents into a structured dictionary.

        The KmsDataBase.xml file contains information about Windows builds, CSVLK items (Volume License Keys),
        and application/SKU details. This function transforms that hierarchical XML data into a more
        easily accessible Python dictionary.

        The structure of the returned dictionary is as follows::

            {
                'winBuilds': [
                    {'WinBuildIndex': '...', 'BuildNumber': '...', 'PlatformId': '...', 'MinDate': '...'},
                    ...
                ],
                'csvlkItems': [
                    {
                        'Key': 'CSVLK', 'Name': '...', 'GroupId': '...', 'MinKeyId': '...', 
                        'MaxKeyId': '...', 'InvalidWinBuild': '...', 'LicHost': '...',
                        'Activate': ['kms_item_id_1', 'kms_item_id_2', ...]
                    },
                    ...
                ],
                'appItems': {
                    'app_id_1_guid': {
                        'Id': 'app_id_1_guid', 'DisplayName': '...',
                        'KmsItems': {
                            'kms_item_id_A': {
                                'Id': 'kms_item_id_A', 'DisplayName': '...',
                                'SkuItems': {
                                    'sku_id_X_guid': {'Id': 'sku_id_X_guid', 'DisplayName': '...', ...},
                                    'sku_id_Y_guid': {'Id': 'sku_id_Y_guid', 'DisplayName': '...', ...}
                                }
                            },
                            'kms_item_id_B': { ... }
                        }
                    },
                    'app_id_2_guid': { ... }
                }
            }

        Each 'Id' for AppItem, KmsItem, and SkuItem is typically a GUID string.

        :raises FileNotFoundError: If KmsDataBase.xml is not found in the same directory.
        :raises xml.etree.ElementTree.ParseError: If KmsDataBase.xml is malformed.
        :return: A dictionary containing structured data from KmsDataBase.xml.
        :rtype: dict
        """
        # Construct the absolute path to KmsDataBase.xml, assuming it's in the same directory as this script.
        path = os.path.join(os.path.dirname(__file__), 'KmsDataBase.xml')
        
        # Parse the XML file. Errors during parsing (e.g., file not found, malformed XML) will raise exceptions.
        root = ET.parse(path).getroot()

        kmsdb_dict = {}  # Initialize the main dictionary to store all parsed data.

        # Section 1: Parse WinBuild elements
        # These elements typically define KMS host OS build information used for ePID generation.
        win_builds_list = []
        for winbuild_element in root.iter('WinBuild'):
                # Each WinBuild element's attributes are directly appended as a dictionary.
                win_builds_list.append(dict(winbuild_element.attrib))
        kmsdb_dict['winBuilds'] = win_builds_list
        
        # Section 2: Parse CsvlkItem elements
        # These items define parameters for different Volume License Keys, including associated KmsItem IDs for activation.
        csvlk_items_list = []
        for csvlk_element in root.iter('CsvlkItem'):
                current_csvlk_activates = []
                # Iterate through nested 'Activate' elements to collect their 'KmsItem' attributes.
                for activate_element in csvlk_element.iter('Activate'):
                        if 'KmsItem' in activate_element.attrib:
                            current_csvlk_activates.append(activate_element.attrib['KmsItem'])
                
                # Create a dictionary from the CsvlkItem's attributes.
                csvlk_data = dict(csvlk_element.attrib)
                # If there were any associated KmsItems for activation, add them as a list to the dictionary.
                if current_csvlk_activates:
                    csvlk_data['Activate'] = current_csvlk_activates
                csvlk_items_list.append(csvlk_data)
        kmsdb_dict['csvlkItems'] = csvlk_items_list

        # Section 3: Parse AppItem elements
        # These items represent applications or product families (e.g., Office, Windows).
        # They contain nested KmsItems, which in turn contain SkuItems.
        app_items_dict = {} # This will be a dictionary mapping AppID (GUID string) to app data.
        for app_element in root.iter('AppItem'):
                app_id = app_element.attrib.get('Id')
                if not app_id:
                    # Log a warning and skip this AppItem if it lacks an 'Id' attribute, which is crucial as a key.
                    print(f"Warning: AppItem found without an Id in KmsDataBase.xml: {app_element.attrib}")
                    continue

                kms_items_dict_for_current_app = {}
                # Iterate through KmsItem elements nested within the current AppItem.
                for kms_element in app_element.iter('KmsItem'):
                        kms_id = kms_element.attrib.get('Id')
                        if not kms_id:
                            # Log a warning and skip this KmsItem if it lacks an 'Id'.
                            print(f"Warning: KmsItem found without an Id in AppItem '{app_id}': {kms_element.attrib}")
                            continue

                        sku_items_dict_for_current_kms = {}
                        # Iterate through SkuItem elements nested within the current KmsItem.
                        for sku_element in kms_element.iter('SkuItem'):
                                sku_id = sku_element.attrib.get('Id')
                                if not sku_id:
                                    # Log a warning and skip this SkuItem if it lacks an 'Id'.
                                    print(f"Warning: SkuItem found without an Id in KmsItem '{kms_id}' (App '{app_id}'): {sku_element.attrib}")
                                    continue
                                # Store SkuItem data, keyed by its SkuID.
                                sku_items_dict_for_current_kms[sku_id] = dict(sku_element.attrib)
                        
                        # Create a dictionary from the KmsItem's attributes.
                        kms_data = dict(kms_element.attrib)
                        # If there were any SkuItems, add them as a nested dictionary.
                        if sku_items_dict_for_current_kms:
                            kms_data['SkuItems'] = sku_items_dict_for_current_kms
                        # Store KmsItem data, keyed by its KmsID, within the current app's KmsItems.
                        kms_items_dict_for_current_app[kms_id] = kms_data
                
                # Create a dictionary from the AppItem's attributes.
                app_data = dict(app_element.attrib)
                # If there were any KmsItems, add them as a nested dictionary.
                if kms_items_dict_for_current_app:
                    app_data['KmsItems'] = kms_items_dict_for_current_app
                # Store AppItem data, keyed by its AppID, in the main app_items_dict.
                app_items_dict[app_id] = app_data
                
        kmsdb_dict['appItems'] = app_items_dict

        return kmsdb_dict
