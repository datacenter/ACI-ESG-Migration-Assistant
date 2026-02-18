import logging
import argparse
import sys
import pdb
import os
import gc
import pickle
import xml.etree.ElementTree as ET
import json
import yaml
import re
import ipaddress
from collections import defaultdict
from util import RemoteCommandMo, chomp, parseDnStr, tree, catchException, reportAFailure, Mo, Mit, ParserStub, globalValues,\
     getNameFromDn, getTenantFromDn, getAppProfileFromDn, getL3OutFromDn, getPodIdFromDn, getNodeIdFromDn,\
     isValidDn, getNewContractDn, getNewContractIfDn, getMgmtPFromDn, getRelationDescription, makeDn, spinner
import pyaci
from pyaci import Node
import time
from enum import IntFlag, Enum
from pygments import highlight
from pygments.lexers import XmlLexer
from pygments.formatters import TerminalFormatter
import paramiko
import tarfile
import requests
import urllib3

TOOL_NAME_STR = "ESG_Migration_Assistant"
ND_NAME_STR = "Nexus_Dashboard"
# Length of the minimum ambigous subcommand
MINCMDALIASLEN = 4
XMLPOST_LEVEL_NUM = 25
CONFIG_TIMEOUT = 30  # seconds
# ANSI color codes
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[33m"
BLUE = "\033[94m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
BOLD_RED = "\033[1;91m"
BOLD_YELLOW = "\033[1;33m"
BOLD_BLUE = "\033[1;94m"
BOLD_MAGENTA = "\033[1;95m"

class ReturnCode(IntFlag):
    SUCCESS = 0
    GETFAILED = 1
    POSTFAILED = 2
    FILEWRITEFAILED = 4
    USERSKIPPED = 8
    CONFIG_TIMEOUT = 16
    CONFIG_FAILED = 32
    VALIDATION_FAILED = 64

    def __str__(self):
            if self == ReturnCode.SUCCESS:
                return "SUCCESS"
            return "|".join(flag.name for flag in ReturnCode if flag and flag in self)

class ConfigStrategy(Enum):
    INTERACTIVE = "interactive"
    VRF = "vrf"
    GLOBAL = "global"

def colored(text, color="green", bold=False, underline=False):
    colors = {
        "green": "32",
        "red": "31",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "black": "90",
    }

    attrs = []
    if bold:
        attrs.append("1")
    if underline:
        attrs.append("4")
    if color:
        attrs.append(colors.get(color, "32"))
    return text if not attrs else f"\033[{';'.join(attrs)}m{text}\033[m"

def contractTypeToStr(contractType):
    if contractType == 'prov':
        return 'Provider'
    elif contractType == 'cons':
        return 'Consumer'
    elif contractType == 'consif':
        return 'Consumer Interface'
    elif contractType == 'intraepg':
        return 'Intra EPG Isolation'
    else:
        return 'Unknown'

def epgDnToStr(epgDn):
    if isValidDn(epgDn, ['uni', 'tn-', 'ap-', 'epg-']):
        return 'Application EPG'
    elif isValidDn(epgDn, ['uni', 'tn-', 'out-', 'instP-']):
        return 'External EPG'
    elif isValidDn(epgDn, ['uni', 'tn-', 'ctx-', 'any']):
        return 'vzAny'
    elif isValidDn(epgDn, ['uni', 'tn-', 'mgmtp-', 'inb-']):
        return 'Inband EPG'
    elif isValidDn(epgDn, ['uni', 'tn-', 'ap-', 'esg-']):
        return 'ESG'
    return 'Unknown EPG'

inputHandler = None

class InputHandler:
    def __init__(self):
        self.lastUserInput = None

    def getInput(self, prompt, validReply):
        if self.lastUserInput == 'a':
            userInput = 'y'
        else:
            userInput = input(prompt).strip().lower()
            while userInput not in validReply:
                print("Invalid input. Please enter {} or {}".format(", ".join(validReply).upper(), ", ".join(validReply)))
                userInput = input(prompt).strip().lower()
            self.lastUserInput = userInput
        return userInput

    def isYesToAll(self):
        return self.lastUserInput == 'a'

    def reset(self):
        self.lastUserInput = None

def downloadAciMetaFile(nodeUrl, args):
    logger = logging.getLogger(globalValues['logger'])

    # If aci-meta is the default, try to download a fresh copy from the APIC
    if args.acimeta == "aci-meta.json":
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            r = requests.get(nodeUrl + "/doc/jsonmeta/aci-meta.json", verify=False, allow_redirects=True, proxies={"http": None, "https": None})
            r.raise_for_status()
            with open("aci-meta.json", "wb") as f:
                f.write(r.content)
        except Exception as e:
            logger.error("Failed to download ACI meta file due to:")
            logger.error("{}".format(e))
            logger.error("Please make sure URL {} is correct and the APIC is reachable.".format(nodeUrl))
            sys.exit(1)

def apicLoginGetNodeAndVersionCheck(args):
    logger = logging.getLogger(globalValues['logger'])

    spinner.text = "Connecting to APIC and check version"

    nodeUrl = 'https://localhost' if args.fromApic else 'https://{}'.format(args.apic)
    downloadAciMetaFile(nodeUrl, args)

    node = Node(nodeUrl, aciMetaFilePath=args.acimeta, userProxies={"http": None, "https": None})
    if not args.fromApic:
        try:
            node.methods.Login(args.username, args.password, autoRefresh=True).POST()
        except Exception as e:
            imdata = ET.fromstring(str(e))
            # Grab the <error> element
            error_elem = imdata.find("error")
            error = f'error code="{error_elem.attrib["code"]}" text="{error_elem.attrib["text"].strip()}"'
            logger.error("Failed to login to APIC {} with user {} due to:\n{}".format(args.apic, args.username, error))
            sys.exit(1)
    else:
        try:
            with open('/.aci/.sessions/.token') as tokenF:
                token = tokenF.read().strip()
        except Exception as e:
            logger.error("Failed to read webtoken due to:\n{}".format(e))
            sys.exit(1)
        # Add session token to node object
        node.session.cookies["APIC-cookie"] = token

    # Version check
    # Version 6.1.4 and above supports external subnet selector and L3Out ESG
    minVersionRequired = "6.1(4)"
    if not checkApicVersionCompatibility(node, minVersionRequired):
        logger.error("APIC version check: failed")
        sys.exit(1)

    return node

def addXmlChildtoMit(element, mit, metaData, parentDn):
    logger = logging.getLogger(globalValues['logger'])

    try:
        moClass = element.tag
        moDn = element.attrib.get('dn', None)

        if not moDn:
            rnFormat = metaData["classes"][moClass]["rnFormat"]
            rnIdentifiers = {}
            for identifier in metaData["classes"][moClass]["identifiedBy"]:
                rnIdentifiers[identifier] = element.attrib.get(identifier)

            rn = rnFormat.format(**rnIdentifiers)
            moDn = parentDn + '/' + rn

        props = {}
        for key, value in element.attrib.items():
            props[key] = value

        mit.addMo(moDn, moClass, props)
        for child in element:
            addXmlChildtoMit(child, mit, metaData, moDn)
    except Exception as e:
        logger.debug("Exception {} occurred while processing addXmlChildtoMit".format(e))

def addJsonChildToMit(subtree, mit, metaData, parentDn):
    logger = logging.getLogger(globalValues['logger'])

    try:
        for moClass, mo in subtree.items():
            if 'attributes' not in mo:
                logger.warning("Skipping class {} as it has no attributes".format(moClass))
                return
            moDn = mo['attributes'].get('dn', None)

            # DN not present, construct from parent and RN specifiers
            if not moDn:
                rnFormat = metaData["classes"][moClass]["rnFormat"]
                rnIdentifiers = {}
                for identifier in metaData["classes"][moClass]["identifiedBy"]:
                    rnIdentifiers[identifier] = mo['attributes'].get(identifier)

                rn = rnFormat.format(**rnIdentifiers)
                moDn = parentDn + '/' + rn

            props = {}
            for key, value in mo['attributes'].items():
                props[key] = value

            mit.addMo(moDn, moClass, props)
            for child in mo.get('children', []):
                addJsonChildToMit(child, mit, metaData, moDn)
    except Exception as e:
        logger.debug("Exception {} occurred while processing addJsonChildToMit".format(e))

def loadMitFromPickle(pickleFile):
    logger = logging.getLogger(globalValues['logger'])
    mit = None
    if os.path.exists(pickleFile):
        try:
            with open(pickleFile, "rb") as pickleF:
                spinner.text = "Loading MIT from pickle file"
                mit = pickle.load(pickleF)
                logger.info("Loaded the MIT from: {}".format(pickleFile))
        except Exception as e:
            logger.error("Met corrupted pickle file: {} with exception: {}".format(pickleFile, e))
            os.unlink(pickleFile)
    return mit

def writeMitToPickle(mit, pickleFile):
    logger = logging.getLogger(globalValues['logger'])
    try:
        with open(pickleFile, "wb") as pickleF:
            pickle.dump(mit, pickleF)
            logger.info("Wrote MIT to pickle file: {}".format(pickleFile))
    except Exception as e:
        logger.error("Failed to write MIT to pickle file: {} with exception: {}".format(pickleFile, e))

def xmlToMit(inXmlFile, args):
    logger = logging.getLogger(globalValues['logger'])
    logger.info("Parsing XML file: {}".format(inXmlFile))
    spinner.text = "Parsing"
    pickleFile = "{}.pickle".format(inXmlFile)
    aciMetaFilePath = args.acimeta
    mit = loadMitFromPickle(pickleFile)

    if mit is None:
        mit = Mit(aciMetaFilePath)
        if mit is None:
            logger.error("MIT not found")
            return mit

        # Metadata for the object tree
        try:
            with open(aciMetaFilePath, "r") as metaFile:
                metaData = json.load(metaFile)

                tree = ET.parse(inXmlFile)
                root = tree.getroot()
                moDn = None
                addXmlChildtoMit(root, mit, metaData, moDn)

                writeMitToPickle(mit, pickleFile)

        except Exception as e:
            logger.error(f"Error parsing XML file {inXmlFile} : {e}")
            sys.exit(1)

    return mit

def dbXmlToMit(inDbXmlFile, args):
    """
    Routine that takes in input an XML file coming from a DB
    conversion and then organized in an MIT tree, and on need also
    save it in tree XML file as well in a pickle structure ... if
    needed.
    Parameters are:
    inDbXmlFile: XML file coming from the db files of techsupport
    args: arguments passed by the parser
    """
    logger = logging.getLogger(globalValues['logger'])
    logger.info("Parsing XML DB file: {}".format(inDbXmlFile))
    spinner.text = "Parsing"
    pickleFile = "{}.pickle".format(inDbXmlFile)
    mit = loadMitFromPickle(pickleFile)

    if mit is None:
        mit = Mit(aciMetaFilePath=args.acimeta)
        if mit is None:
            logger.error("MIT not found")
            return mit
        try:
            with open(inDbXmlFile, "r") as dbxmlFile:
                completeLine = []
                i = 0
                for line in dbxmlFile:
                    i = i + 1
                    if i % 1000 == 0:
                        spinner.text = "Processed {} records".format(i)
                    t = None
                    line = chomp(line)
                    completeLine.append(line)
                    if not line.endswith('/>'):
                        continue
                    try:
                        t = ET.fromstring("\n".join(completeLine))
                        completeLine.clear()
                    except Exception as e:
                        logger.error("Met exception: {} on line: {}".format(e, line))
                        completeLine.clear()
                        continue
                    if t is None:
                        continue
                    props = {}
                    for key, value in t.attrib.items():
                        props[key] = value
                    mit.addMo(t.attrib['dn'], t.tag, props)

                if (i > 0):
                    writeMitToPickle(mit, pickleFile)
                else:
                    logger.error("No configuration found in DB XML file: {}".format(inDbXmlFile))
                    sys.exit(1)

        except Exception as e:
            logger.error(f"Error parsing DBXML file {inDbXmlFile} : {e}")
            sys.exit(1)

    return mit

def jsonToMit(inDbJsonFile, args):
    """
    Routine that takes in input a JSON file coming from a DB
    conversion and then organized in an MIT tree, and on need also
    save it in tree XML file as well in a pickle structure ... if
    needed.
    Parameters are:
    inDbJsonFile: JSON file
    args: arguments passed by the parser
    """
    logger = logging.getLogger(globalValues['logger'])
    logger.info("Parsing JSON DB file: {}".format(inDbJsonFile))
    spinner.text = "Parsing"
    pickleFile = "{}.pickle".format(inDbJsonFile)
    aciMetaFilePath = args.acimeta
    mit = loadMitFromPickle(pickleFile)

    if mit is None:
        mit = Mit(aciMetaFilePath)
        if mit is None:
            logger.error("MIT not found")
            return mit

        # Metadata for the object tree
        try:
            with open(aciMetaFilePath, "r") as metaFile:
                metaData = json.load(metaFile)

                with open(inDbJsonFile, "r") as jsonFile:
                    jsonConfig = json.load(jsonFile)
                    for moClass, mo in jsonConfig.items():
                        if 'attributes' not in mo:
                            logger.warning("Skipping class {} as it has no attributes".format(moClass))
                            continue
                        moDn = mo['attributes'].get('dn', None)
                        if not moDn:
                            logger.warning("Skipping class {} as it has no dn".format(moClass))
                            continue
                        props = {}
                        for key, value in mo['attributes'].items():
                            props[key] = value
                        mit.addMo(moDn, moClass, props)
                        for child in mo.get('children', []):
                            addJsonChildToMit(child, mit, metaData, moDn)

                    writeMitToPickle(mit, pickleFile)

        except Exception as e:
            logger.error(f"Error parsing JSON file {inDbJsonFile} : {e}")
            sys.exit(1)
    return mit

def snapshotToMit(inSnapJsonFileStr, path, args):
    mit = None
    logger = logging.getLogger(globalValues['logger'])

    # SSH connection details
    tarPath = path + inSnapJsonFileStr
    snapshotJson = inSnapJsonFileStr.replace(".tar.gz", "_1.json")
    pickleFile = "{}.pickle".format(snapshotJson)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(args.apic, username=args.username, password=args.password)

    sftp = ssh.open_sftp()

    spinner.text = "Waiting for snapshot file to be ready"
    counter = 0
    while counter < 15:
        try:
            sftp.stat(tarPath)
            break
        except Exception as e:
            pass
        time.sleep(1)
        counter += 1

    logger.info("Parsing Snapshot file: {}".format(inSnapJsonFileStr))
    spinner.text = "Parsing"
    time.sleep(3)

    try:
        with sftp.open(tarPath, "rb") as tar_file:
            with tarfile.open(fileobj=tar_file, mode="r:gz") as tar:
                for member in tar:
                    if member.name == snapshotJson or member.name.endswith("_1.json"):
                        inSnapJsonFile = tar.extractfile(member)

                        aciMetaFilePath = args.acimeta
                        mit = Mit(aciMetaFilePath)
                        if mit is None:
                            logger.error("MIT not found")
                            return mit

                        # Metadata for the object tree
                        with open(aciMetaFilePath, "r") as metaFile:
                            metaData = json.load(metaFile)

                            jsonConfig = json.load(inSnapJsonFile)
                            for moClass, mo in jsonConfig.items():
                                if 'attributes' not in mo:
                                    logger.warning("Skipping class {} as it has no attributes".format(moClass))
                                    continue
                                moDn = mo['attributes'].get('dn', None)
                                if not moDn:
                                    logger.warning("Skipping class {} as it has no dn".format(moClass))
                                    continue
                                props = {}
                                for key, value in mo['attributes'].items():
                                    props[key] = value
                                mit.addMo(moDn, moClass, props)
                                for child in mo.get('children', []):
                                    addJsonChildToMit(child, mit, metaData, moDn)

                            writeMitToPickle(mit, pickleFile)
                            break
    except Exception as e:
        logger.error(f"Error parsing Snapshot JSON file {inSnapJsonFileStr} : {e}")
        sys.exit(1)

    sftp.close()
    ssh.close()

    return mit


def snapshotToMitLocal(inSnapJsonFileStr, path, args):
    logger = logging.getLogger(globalValues['logger'])

    tarPath = path + inSnapJsonFileStr
    inSnapJsonFileName = inSnapJsonFileStr.split('/')[-1]
    snapshotJson = inSnapJsonFileName.replace(".tar.gz", "_1.json")
    pickleFile = "./{}.pickle".format(snapshotJson)
    mit = loadMitFromPickle(pickleFile)

    if mit is None:
        spinner.text = "Waiting for snapshot file to be ready"
        while not os.path.exists(tarPath):
            time.sleep(1)
        logger.info("Parsing Snapshot file: {}".format(inSnapJsonFileStr))
        spinner.text = "Parsing"
        time.sleep(3)
        try:
            with open(tarPath, "rb") as tar_file:
                with tarfile.open(fileobj=tar_file, mode="r:gz") as tar:
                    for member in tar:
                        if member.name == snapshotJson or member.name.endswith("_1.json"):
                            inSnapJsonFile = tar.extractfile(member)

                            aciMetaFilePath = args.acimeta
                            mit = Mit(aciMetaFilePath)
                            if mit is None:
                                logger.error("MIT not found")
                                return mit

                            # Metadata for the object tree
                            with open(aciMetaFilePath, "r") as metaFile:
                                metaData = json.load(metaFile)

                                jsonConfig = json.load(inSnapJsonFile)
                                for moClass, mo in jsonConfig.items():
                                    if 'attributes' not in mo:
                                        logger.warning("Skipping class {} as it has no attributes".format(moClass))
                                        continue
                                    moDn = mo['attributes'].get('dn', None)
                                    if not moDn:
                                        logger.warning("Skipping class {} as it has no dn".format(moClass))
                                        continue
                                    props = {}
                                    for key, value in mo['attributes'].items():
                                        props[key] = value
                                    mit.addMo(moDn, moClass, props)
                                    for child in mo.get('children', []):
                                        addJsonChildToMit(child, mit, metaData, moDn)

                                writeMitToPickle(mit, pickleFile)
                                break
        except Exception as e:
            logger.error(f"Error parsing Snapshot JSON file {inSnapJsonFileStr} : {e}")
            sys.exit(1)

    return mit


def waitForCondition(conditionFn, description, timeout, ih, checkInterval=1, onSuccess=None, onFailure=None):
    """
    Generic retry/wait loop for asynchronous conditions.

    Args:
        conditionFn: function returning a truthy value when done/successful
        description: str, description of what we're waiting for
        timeout: int, seconds before asking the user
        ih: InputHandler instance for interactive user decisions
        checkInterval: int, seconds between checks
        onSuccess: optional function(result) called when condition succeeds
        onFailure: optional function() called when user opts to stop waiting
    """
    logger = logging.getLogger(globalValues['logger'])

    counter = 0
    while True:
        result = conditionFn()

        if result:
            sys.stdout.write("\r " + " " * 80 + "\r")
            sys.stdout.flush()
            if onSuccess:
                onSuccess(result)
            return result

        elapsed = counter * checkInterval
        sys.stdout.write(f"\rWaiting for {description}... (elapsed {elapsed}s)  \r")
        sys.stdout.flush()
        time.sleep(checkInterval)

        counter += 1
        if counter >= timeout:
            sys.stdout.write("\r " + " " * 160 + "\r")
            sys.stdout.flush()
            userInput = ih.getInput("Configuration is taking more than {} seconds. Do you want to continue waiting (Y-Yes, N-No, Q-Quit): ".format(int(timeout)),
                                    ['y', 'n', 'q'])
            if userInput == "q":
                sys.exit(0)
            elif userInput == "n":
                logger.warning(f"Timeout waiting for {description}")
                if onFailure:
                    onFailure()
                return None
            else:
                counter = 0  # reset timer and keep waiting

def logAndPostHandler(outputElem, node, outputFile = None, noConfig = True, step = None, allowYesToAll = False):
    logger = logging.getLogger(globalValues['logger'])

    def xmlWithComment(mo):
        def element(mo):
            elem = ET.Element(mo._className)

            for key, value in mo._properties.items():
                if value is not None:
                    elem.set(key, value)

            for child in mo.Children:
                for node in element(child):
                    elem.append(node)

            nodes = []

            # if comment exists, put it BEFORE the element
            if hasattr(mo, "xmlcomment") and mo.xmlcomment:
                nodes.append(ET.Comment(mo.xmlcomment))

            nodes.append(elem)

            return nodes

        root_nodes = element(mo)
        root = root_nodes[-1]

        ET.indent(root)
        return ET.tostring(root, encoding="unicode")

    def postWithTokenRetry(node, outputElem):
        try:
            return outputElem.POST(format='xml')
        except Exception as e:
            # check if it's a token timeout
            if 'Token was invalid' in str(e) or 'Token timeout' in str(e) or 'code="403"' in str(e):
                print("Session token expired, refreshing token and retrying POST...")

                with open('/.aci/.sessions/.token') as tokenF:
                    token = tokenF.read().strip()
                node.session.cookies["APIC-cookie"] = token
                # retry once
                return outputElem.POST(format='xml')
            raise

    rc = ReturnCode.SUCCESS
    logger.xmlpost(xmlWithComment(outputElem))

    if step:
       stepStr = "[{}/{}] ".format(step['current'], step['total'])
       step['current'] = step['current'] + 1
    else:
       stepStr = ""
    if allowYesToAll:
        if noConfig:
            prompt = "Skipping POST since --noconfig option was specified. Do you want continue Y-Yes, A-Yes to All, Q-Quit: {}".format(stepStr)
            validReply = ['y', 'a', 'q']
        else:
            prompt = "Do you want to POST this configuration Y-Yes, A-Yes to All, N-No, Q-Quit: {}".format(stepStr)
            validReply = ['y', 'a', 'n', 'q']
    else:
        if noConfig:
            prompt = "Skipping POST since --noconfig option was specified. Do you want continue Y-Yes, Q-Quit: {}".format(stepStr)
            validReply = ['y', 'q']
        else:
            prompt = "Do you want to POST this configuration Y-Yes, N-No, Q-Quit: {}".format(stepStr)
            validReply = ['y', 'n', 'q']

    userInput = inputHandler.getInput(prompt, validReply)
    if userInput == 'q':
        sys.exit(0)
    elif userInput == 'y' or userInput == 'a':
        try:
            # If the POST is failing, do not write the XML into outputFile
            # Exception will occur on validation failure
            if not noConfig:
                postWithTokenRetry(node, outputElem)

                params = {'query-target-filter': 'eq(configpushTxCont.failedUpdate,"no")'}
                def conditionFn():
                    result = node.methods.ResolveClass('configpushTxCont').GET(**params)
                    return not bool(result)  # True when push complete (no results)

                def onSuccess(_):
                    logger.info("POST successful")

                result = waitForCondition(
                    conditionFn = conditionFn,
                    description = "config push to complete",
                    timeout = CONFIG_TIMEOUT,
                    ih = InputHandler(),
                    onSuccess = onSuccess)

                if result is None:
                    rc |= ReturnCode.CONFIG_TIMEOUT
            if outputFile:
                try:
                    if outputFile.endswith(".xml"):
                        with open(outputFile, "a") as f:
                            f.write(outputElem.GetXml() + "\n")
                    elif outputFile.endswith(".json"):
                        with open(outputFile, "a") as f:
                            f.write(outputElem.Json + "\n")
                except Exception as fe:
                    logger.error("Failed to write output config to file {} due to {}".format(outputFile, fe))
                    rc |= ReturnCode.FILEWRITEFAILED
        except Exception as e:
            # Parse XML
            imdata = ET.fromstring(str(e))
            # Grab the <error> element
            error_elem = imdata.find("error")
            error = f'error code="{error_elem.attrib["code"]}" text="{error_elem.attrib["text"].strip()}"'
            logger.error("POST failure due to:\n{}\n".format(error))
            rc |= ReturnCode.POSTFAILED
    else:
        logger.info("POST skipped by user")
        rc |= ReturnCode.USERSKIPPED

    print()
    return rc

def buildReverseRelation(parentDn: str, targetDn: str, className: str):
    """
    Build the DN and properties for a reverse relation (fvRt*, vzRt*, etc.)

    Args:
        parentDn (str): DN of the parent of the fvRs*
        targetDn (str): tDn resolved for the fvRs* relation
        className (str): Class name of the reverse relation (e.g., 'fvRtBd')

    Returns:
        str: The DN of the reverse relation
    """
    relationDesc = getRelationDescription()
    if className not in relationDesc:
        raise ValueError(f"Unknown relation class: {className}")

    return f"{targetDn}/{relationDesc[className]['rnFormat']}[{parentDn}]"

def relationFramework(mit):
    """
    This function processes relations in the MIT to set the tDn property
    based on the target class and naming properties.
    """
    logger = logging.getLogger(globalValues['logger'])

    logger.info("Starting relation framework analysis")
    spinner.text = "Processing relations"

    relationDesc = getRelationDescription()
    for relation, relationProperty in relationDesc.items():
        namingRelation = relationProperty.get('namingProperty', '')
        allRelations = mit.lookupByClass(relation)

        if not allRelations:
            continue

        for moDn, mo in allRelations:
            targetDn = mo.getProp('tDn')
            if not targetDn:
                relationTenant = getTenantFromDn(moDn)
                if not relationTenant:
                    logger.warning("No tenant found for relation DN: {}".format(moDn))
                    continue

                targetName = mo.getProp('{}'.format(namingRelation))
                if not targetName:
                    targetName = "default"

                userTargetDn = makeDn(relationProperty['targetClass'], relationTenant, targetName)
                commonTargetDn = makeDn(relationProperty['targetClass'], "common", targetName)
                if mit.lookupByDn(userTargetDn):
                    targetDn = userTargetDn
                elif mit.lookupByDn(commonTargetDn):
                    targetDn = commonTargetDn

                mo.setProp('tDn', targetDn)

                logger.debug("Processed {}: {} - {}: {} - Resolved tDn: {}".format(relation, moDn, namingRelation, targetName, targetDn))
            else:
                logger.debug("Skipping {} as it already has tDn set: {}".format(moDn, targetDn))

            if targetDn:
                parent = mo.Parent
                if parent:
                    rtDn = buildReverseRelation(parent.Dn, targetDn, relation)
                    rtProps = {'tDn': parent.Dn, 'tCl': parent.ClassName}
                    mit.addMo(rtDn, relationProperty['rtClass'], rtProps)
                    logger.debug("Created reverse relation {}: {} - {}".format(relationProperty['rtClass'], rtDn, rtProps))

    return 0

#########################################################
# DRY RUN PHASE
#########################################################
def generateDryrunConfig(mit, mode, ndCompliant, yamlOutputFile, namePrefix, nameSuffix, filterVrfDns=[], filterTenantDns=[], showStats=False):

    if namePrefix:
        namePrefix = namePrefix + "_"
    if nameSuffix:
        nameSuffix = "_" + nameSuffix

    def contractReltoPrefix(className):
        if className == "fvRsProv" or className == "vzRsAnyToProv":
            return "prov"
        elif className == "fvRsCons" or className == "vzRsAnyToCons":
            return "cons"
        elif className == "fvRsIntraEpg":
            return "intraepg"
        elif className == "fvRsConsIf" or className == "vzRsAnyToConsIf":
            return "consif"
        else:
            raise Exception("Unknown contract relation class: {}".format(className))

    def processInheritedContracts(epg, masterEpgs, visited=None):
        """
        Nested helper function.
        Recursively walks over epgs where contracts are inherited from.
        Once epg with no further inheritance is found, epgLayout is updated with inherited contracts.
        """
        if not masterEpgs:
            return
        if visited is None:
            visited = set()

        for masterEpg in list(masterEpgs):
            if masterEpg in visited:
                continue
            visited.add(masterEpg)
            if masterEpg in inheritedFrom:
                processInheritedContracts(masterEpg, inheritedFrom[masterEpg], visited)
            masterContracts = epgLayout.get(masterEpg, {}).get('contracts', set())
            if masterContracts:
                epgLayout[epg]['contracts'].update(masterContracts)
                epgLayout[epg]['hasInheritedContracts'] = True
            inheritedFrom[epg].discard(masterEpg)

    def addEsgGroupDebugInfo(esgJson, vrfDn, debugInfo):
        lenEpgSelectors = len(esgJson['epgs'])
        debugInfo += "Group of {} {}EPG{}".format(
            lenEpgSelectors, "similar "if lenEpgSelectors > 1 else "", "s"if lenEpgSelectors > 1 else "")
        if esgJson['externalSubnets']:
            debugInfo += " and {} External Subnet Selector{}".format(
                len(esgJson['externalSubnets']), "s"if len(esgJson['externalSubnets']) > 1 else "")
        debugInfo += " in VRF {}".format(vrfDn)
        if lenEpgSelectors > 0:
            debugInfo += ":\n\t{}".format('\n\t'.join(esgJson['epgs']))
        if esgJson['externalSubnets']:
            debugInfo += "\n      External Subnet Selectors:\n\t{}".format(
                ',\n\t'.join(f"{subnet['ip']} ({subnet['scope']})" for subnet in esgJson['externalSubnets']))
        if contracts:
            debugInfo += "\n      Layout of contracts:\n\t{}".format(',\n\t'.join(contracts))
        else:
            debugInfo += "\n      No contracts associated"
        return debugInfo

    def addLeakRouteDebugInfo(leakInternal, leakExternal, leakToVrfs, vrfDn, esgJson, debugInfo):
        if leakToVrfs:
            if esgJson == None:
                debugInfo += "Leak routes from VRF {}".format(vrfDn)
            if leakInternal:
                debugInfo += "\n      Leak Internal Subnets:\n\t{}".format(
                    ',\n\t'.join(f"{ip} ({scope})" for ip, scope in sorted(list(leakInternal))))
            if leakExternal:
                debugInfo += "\n      Leak External Prefixes:\n\t{}".format(
                    ',\n\t'.join(f"{ip} {aggregate}" for ip, aggregate in sorted(list(leakExternal))))
            debugInfo += "\n      Leak Target VRFs: \n\t{}".format(
                ',\n\t'.join(sorted(list(leakToVrfs))))
        return debugInfo

    logger = logging.getLogger(globalValues['logger'])

    #
    # Step 1: collect all the EPGs in the system. If there are no EPGs, stop the analysis
    #
    allEpgMos = []
    # AEPGs
    fvAEpgMos = mit.lookupByClass('fvAEPg')
    if fvAEpgMos:
        allEpgMos.extend(fvAEpgMos)
    else:
        logger.info("No fvAEPg found.")
    # External EPGs
    l3extInstpMos = mit.lookupByClass('l3extInstP')
    if l3extInstpMos:
        allEpgMos.extend(l3extInstpMos)
    else:
        logger.info("No l3extInstP found.")
    # MgmtInB EPGs
    mgmtInbMos = mit.lookupByClass('mgmtInB')
    if mgmtInbMos:
        allEpgMos.extend(mgmtInbMos)
    else:
        logger.info("No mgmtInB found.")
    logger.debug("Found {} EPGs (fvAEPg, l3extInstP, mgmtInB)".format(len(allEpgMos)))
    # vzAny
    vzAnyMos = mit.lookupByClass('vzAny')
    if vzAnyMos:
        allEpgMos.extend(vzAnyMos)
    else:
        logger.info("No vzAny found.")
    if not allEpgMos:
        logger.error("No EPGs (fvAEPg or l3extInstP or mgmtInB or vzAny) found in the MIT.")
        return

    #
    # Step 2: pre-collect:
    # - BD-to-CTX relations
    # - BD Subnets with shared flag
    # - l3extOut-to-CTX relations
    # - vzCPIf-to-vzBrCP relations
    # - vzBrCP-to-Consumer relations
    # - EPGs assigned to selectors
    # - VRF assigned to tenant in filter lists
    # - VRF level Preferred Group config
    # - EPGs and Contracts with unsupported features
    #
    bdToCtx = {}
    bdToSharedSubnet = {}
    outToCtx = {}
    cpIfToContract = {}
    brCPToConsumer = {}
    brCPToProvider = {}
    vzAnyPrefGrMembrship = {}
    epgsAssignedToSelector = set()
    vrfsWithVzAnyContract = set()
    epgsWithUnsupportedFeatures = {}
    contractsWithUnsupportedFeatures = {}
    perVrfExternalSubnetSelectors = {}

    noFiltersUsed = not filterVrfDns and not filterTenantDns
    filtersUsed = not noFiltersUsed

    # Pre-Collect VRFs assigned to tenant in filter lists
    iter = mit.lookupByClass('fvCtx')
    if iter:
        logger.debug("Found {} VRFs.".format(len(iter)))
        for ctxDn, _ in iter:
            tenantName = getTenantFromDn(ctxDn)
            tenantDn = "uni/tn-{}".format(tenantName)
            if tenantDn in filterTenantDns:
                if ctxDn not in filterVrfDns:
                    filterVrfDns.append(ctxDn)
    # Pre-Collect BD to CTX mapping for fvAEPg
    iter = mit.lookupByClass('fvBD')
    if iter:
        for bdDn, bdMo in iter:
            bdToSharedSubnet.setdefault(bdDn, [])
            for mo in bdMo.Children:
                if mo.ClassName == "fvRsCtx":
                    bdToCtx[bdDn] = mo.getProp('tDn')
                elif mo.ClassName == "fvSubnet":
                    scopeFlags = [flag.strip() for flag in mo.getProp('scope').split(",")]
                    if "shared" in scopeFlags:
                        ip = ipaddress.ip_network(mo.getProp('ip'), strict=False)
                        bdToSharedSubnet[bdDn].append((str(ip), "public" if "public" in scopeFlags else "private"))
    logger.debug("Found {} BDs (out of {}) associated to a VRF".format(len(bdToCtx), len(iter)))
    # Pre-Collect L3Out to CTX mapping for l3extInstP
    iter = mit.lookupByClass('l3extOut')
    if iter:
        for l3extOutDn, l3extOutMo in iter:
            for mo in l3extOutMo.Children:
                if mo.ClassName == "l3extRsEctx":
                    outToCtx[l3extOutDn] = mo.getProp('tDn')
    logger.debug("Found {} l3extOuts associated to a VRF".format(len(outToCtx)))
    # Pre-Collect vzCPIf to vzBrCP mapping
    iter = mit.lookupByClass('vzCPIf')
    if iter:
        for vzCPIfDn, vzCPIfMo in iter:
            for mo in vzCPIfMo.Children:
                if mo.ClassName == "vzRsIf":
                    cpIfToContract[vzCPIfDn] = mo.getProp('tDn')
    logger.debug("Found {} vzCPIf associated to vzBrCP (contract).".format(len(cpIfToContract)))
    # Pre-Collect vzBrCP to Provider/Consumer mapping
    iter = mit.lookupByClass('vzBrCP')
    if iter:
        for vzBrCPDn, vzBrCPMo in iter:
            targetProvEpgDns = set()
            targetConsEpgDns = set()
            for childMo in vzBrCPMo.Children:
                if childMo.ClassName == "vzRtProv":
                    targetEpgDn = childMo.getProp('tDn')
                    if targetEpgDn:
                        targetProvEpgDns.add(targetEpgDn)
                if childMo.ClassName == "vzRtCons":
                    targetEpgDn = childMo.getProp('tDn')
                    if targetEpgDn:
                        targetConsEpgDns.add(targetEpgDn)
                elif childMo.ClassName == "vzRtIf":
                    targetIfDn = childMo.getProp('tDn')
                    if targetIfDn:
                        vzCPIfMo = mit.lookupByDn(targetIfDn)
                        for cpChildMo in vzCPIfMo.Children:
                            if cpChildMo.ClassName == "vzRtConsIf":
                                targetEpgDn = cpChildMo.getProp('tDn')
                                if targetEpgDn:
                                    targetConsEpgDns.add(targetEpgDn)
                            elif cpChildMo.ClassName == "vzRtAnyToConsIf":
                                targetEpgDn = cpChildMo.getProp('tDn')
                                if targetEpgDn:
                                    targetConsEpgDns.add(targetEpgDn)
                                    vrfsWithVzAnyContract.add(targetEpgDn.rsplit('/', 1)[0])
                elif childMo.ClassName == "vzRtAnyToProv":
                    targetEpgDn = childMo.getProp('tDn')
                    if targetEpgDn:
                        targetProvEpgDns.add(targetEpgDn)
                        vrfsWithVzAnyContract.add(targetEpgDn.rsplit('/', 1)[0])
                elif childMo.ClassName == "vzRtAnyToCons":
                    targetEpgDn = childMo.getProp('tDn')
                    if targetEpgDn:
                        targetConsEpgDns.add(targetEpgDn)
                        vrfsWithVzAnyContract.add(targetEpgDn.rsplit('/', 1)[0])
            brCPToProvider[vzBrCPDn] = targetProvEpgDns
            brCPToConsumer[vzBrCPDn] = targetConsEpgDns
            if vzBrCPMo.getProp('scope') == 'application-profile':
                contractsWithUnsupportedFeatures.setdefault(vzBrCPDn, set())
                contractsWithUnsupportedFeatures[vzBrCPDn].add("Contract scope application-profile")

        logger.debug("Found {} vzBrCP (contracts): {} Provider relations and {} Consumer relations".format(len(iter), sum(len(v) for v in brCPToProvider.values()), sum(len(v) for v in brCPToConsumer.values())))
    # Pre-Collect EPGs assigned to selectors
    iter = mit.lookupByClass('fvEPgSelector')
    if iter:
        for _, selectorMo in iter:
            epgsAssignedToSelector.add(selectorMo.getProp('matchEpgDn'))
        logger.debug("Found {} EPGs assigned to EPG selectors.".format(len(epgsAssignedToSelector)))

    # Pre-Collect Preferred Group Membership Config at the VRF level
    for _, vzAnyMo in vzAnyMos:
        vrfDn = vzAnyMo.Parent.Dn
        vzAnyPrefGrMembrship[vrfDn] = vzAnyMo.getProp('prefGrMemb')

    # Pre-Collect all Per-VRF External Subnet Selectors and extend allEpgMos to include ESGs
    esgsMos = mit.lookupByClass('fvESg')
    if esgsMos:
        allEpgMos.extend(esgsMos)
        for _, esgMo in esgsMos:
            esgExternalSubnetSelectors = set()
            esgVrfDn = None
            for mo in esgMo.Children:
                if mo.ClassName == "fvExternalSubnetSelector":
                    esgExternalSubnetSelectors.add(ipaddress.ip_network(mo.getProp('ip'), strict=False))
                elif mo.ClassName == "fvRsScope":
                    esgVrfDn = mo.getProp('tDn')
            if esgExternalSubnetSelectors and esgVrfDn:
                perVrfExternalSubnetSelectors.setdefault(esgVrfDn, set())
                perVrfExternalSubnetSelectors[esgVrfDn].update(esgExternalSubnetSelectors)
        logger.debug("Found {} VRFs with External Subnet Selectors.".format(len(perVrfExternalSubnetSelectors)))

    # Pre-Collect EPGs and Contracts with unsupported features
    unsupportedObjects = {'vzConsLbl': "Consumer Label (vzConsLbl)", 'vzProvLbl': "Provider Label (vzProvLbl)",
                          'vzProvSubjLbl': "Provider Subject Label (vzProvSubjLbl)", 'vzConsSubjLbl': "Consumer Subject Label (vzConsSubjLbl)",
                          'vzProvCtrctLbl': "Provider Contract Label (vzProvCtrctLbl)", 'vzConsCtrctLbl': "Consumer Contract Label (vzConsCtrctLbl)",
                          'vzException': "Contract Exception (vzException)", 'fvRsProtBy': "Taboo Contract (fvRsProtBy)"}
    for className, description in unsupportedObjects.items():
        mos = mit.lookupByClass(className)
        if mos:
            for _, mo in mos:
                parentMo = mo.getParentByClass('fvAEPg')
                if parentMo:
                    epgsWithUnsupportedFeatures.setdefault(parentMo.Dn, set())
                    epgsWithUnsupportedFeatures[parentMo.Dn].add(description)
                parentMo = mo.getParentByClass('l3extInstP')
                if parentMo:
                    epgsWithUnsupportedFeatures.setdefault(parentMo.Dn, set())
                    epgsWithUnsupportedFeatures[parentMo.Dn].add(description)
                parentMo = mo.getParentByClass('mgmtInB')
                if parentMo:
                    epgsWithUnsupportedFeatures.setdefault(parentMo.Dn, set())
                    epgsWithUnsupportedFeatures[parentMo.Dn].add(description)
                parentMo = mo.getParentByClass('vzAny')
                if parentMo:
                    epgsWithUnsupportedFeatures.setdefault(parentMo.Dn, set())
                    epgsWithUnsupportedFeatures[parentMo.Dn].add(description)
                parentMo = mo.getParentByClass('vzBrCP')
                if parentMo:
                    contractsWithUnsupportedFeatures.setdefault(parentMo.Dn, set())
                    contractsWithUnsupportedFeatures[parentMo.Dn].add(description)
    epgsWithUnsupportedFeaturesLen = len(epgsWithUnsupportedFeatures)
    contractsWithUnsupportedFeaturesLen = len(contractsWithUnsupportedFeatures)
    if epgsWithUnsupportedFeaturesLen > 0:
        logger.warning("Found {} EPGs with unsupported features".format(epgsWithUnsupportedFeaturesLen))
    else:
        logger.info("No EPGs with unsupported features found")
    if contractsWithUnsupportedFeaturesLen > 0:
        logger.warning("Found {} Contracts with unsupported features".format(contractsWithUnsupportedFeaturesLen))
    else:
        logger.info("No Contracts with unsupported features found")

    #
    # Step 3: populate epgLayout variable for all EPGs. Skip EPGs with no VRF assigned
    #
    epgLayout = {}
    externalSubnetLayout = {}
    inheritedFrom = defaultdict(set)

    for epgDn, epgMo in allEpgMos:
        epgDescriptor = {
            'className': epgMo.ClassName,
            'vrf': None,
            'bd': None,
            'contracts': set(),
            'hasInheritedContracts': False,
            'epgTennant': getTenantFromDn(epgDn),
            'pcEnfPref': 'unenforced' if epgMo.ClassName in ("mgmtInB", "vzAny") else epgMo.getProp('pcEnfPref'),
            'prefGrMemb': 'exclude',
            'appProfileName': getNameFromDn(epgMo.Parent.Dn),
            'ignoreMigration': epgDn in epgsAssignedToSelector,
            'unsupportedFeatures': epgsWithUnsupportedFeatures[epgDn] if epgDn in epgsWithUnsupportedFeatures else set(),
            'inbOrVzany': epgMo.ClassName in ("mgmtInB", "vzAny"),
            'isUseg': epgMo.ClassName == "fvAEPg" and epgMo.getProp("isAttrBasedEPg") == "yes",
            'externalSubnets': [],
            'leakInternalSubnetsFromProv': [],
            'leakInternalSubnetsFromCons': [],
            'leakExternalPrefixes': []
        }

        # Handle AEPg-to-CTX
        if epgMo.ClassName == "fvAEPg":
            for mo in epgMo.Children:
                if mo.ClassName == "fvRsBd":
                    epgDescriptor['bd'] = mo.getProp('tDn')
                    epgDescriptor['vrf'] = bdToCtx.get(mo.getProp('tDn'), None)
                    break

        # Handle l3extInstP-to-CTX
        elif epgMo.ClassName == "l3extInstP":
            # l3extOut is the parent
            epgDescriptor['vrf'] = outToCtx.get(epgMo.Parent.Dn, None)

        # Handle mgmtInB-to-CTX
        elif epgMo.ClassName == "mgmtInB":
            for mo in epgMo.Children:
                if mo.ClassName == "mgmtRsMgmtBD":
                    epgDescriptor['bd'] = mo.getProp('tDn')
                    epgDescriptor['vrf'] = bdToCtx.get(mo.getProp('tDn'), None)
                    break

        # Handle fvESg-to-CTX
        elif epgMo.ClassName == "fvESg":
            esgExternalSubnetSelectors = set()
            for mo in epgMo.Children:
                if mo.ClassName == "fvRsScope":
                    epgDescriptor['vrf'] = mo.getProp('tDn')

        # Handle vzAny-to-CTX
        elif epgMo.ClassName == "vzAny":
            epgDescriptor['vrf'] = epgMo.Parent.Dn

        # Check if EPG has exceptionTag
        if epgMo.ClassName in ("fvAEPg", "l3extInstP", "mgmtInB"):
            if epgMo.getProp('exceptionTag'):
                epgDescriptor['unsupportedFeatures'].add("exceptionTag property")

        # Collect contracts and other properties if VRF is assigned
        if epgDescriptor['vrf']:
            # Update preferred group
            if vzAnyPrefGrMembrship.get(epgDescriptor['vrf'], None)  == 'enabled' and epgMo.getProp('prefGrMemb') == 'include':
                epgDescriptor['prefGrMemb'] = 'include'

            for mo in epgMo.Children:
                className = mo.ClassName
                # Collect contracts
                if className == "fvRsProv" or className == "fvRsCons" or\
                   className == "fvRsIntraEpg" or className == "fvRsConsIf":
                    tDn = mo.getProp('tDn')
                    if (tDn):
                        epgDescriptor['contracts'].add("{}:{}".format(contractReltoPrefix(className), tDn))
                        if tDn in contractsWithUnsupportedFeatures:
                            epgDescriptor['unsupportedFeatures'].update(contractsWithUnsupportedFeatures[tDn])
                elif className == "vzRsAnyToProv" or className == "vzRsAnyToCons"\
                    or className == "vzRsAnyToConsIf":
                    tDn = mo.getProp('tDn')
                    if (tDn):
                        epgDescriptor['contracts'].add("{}:{}".format(contractReltoPrefix(className), tDn))
                        if tDn in contractsWithUnsupportedFeatures:
                            epgDescriptor['unsupportedFeatures'].update(contractsWithUnsupportedFeatures[tDn])
                # Collect internal subnets to be leaked from the Provider EPGs
                elif className == "fvSubnet":
                    scopeFlags = [flag.strip() for flag in mo.getProp('scope').split(",")]
                    if "shared" in scopeFlags:
                        ip = ipaddress.ip_network(mo.getProp('ip'), strict=False)
                        epgDescriptor['leakInternalSubnetsFromProv'].append((str(ip), "public" if "public" in scopeFlags else "private"))
                # Collect external prefixes to be leaked from Provider EPGs and external subnets for selectors
                elif className == "l3extSubnet":
                    scopeFlags = [flag.strip() for flag in mo.getProp('scope').split(",")]
                    aggregateFlags = [flag.strip() for flag in mo.getProp('aggregate').split(",")]
                    if "shared-rtctrl" in scopeFlags:
                        ip = ipaddress.ip_network(mo.getProp('ip'), strict=False)
                        epgDescriptor['leakExternalPrefixes'].append((str(ip), "shared-rtctrl" if "shared-rtctrl" in aggregateFlags else ""))
                    if "import-security" in scopeFlags or "shared-security" in scopeFlags:
                        ip = ipaddress.ip_network(mo.getProp('ip'), strict=False)
                        if ip not in perVrfExternalSubnetSelectors.get(epgDescriptor['vrf'], set()):
                            epgDescriptor['externalSubnets'].append((str(ip), "public" if "shared-security" in scopeFlags else "private"))
                # Collect internal subnets to be leaked from the Consumer EPGs
                if className == "fvRsBd" or className == "mgmtRsMgmtBD":
                    epgDescriptor['leakInternalSubnetsFromCons'] = bdToSharedSubnet.get(mo.getProp('tDn'), [])
                # Collect EPGs from which contracts are inherited
                elif className == "fvRsSecInherited":
                    match = re.search(r"\[(.*?)\]", mo.Dn)
                    if match:
                        tDn = match.group(1)
                        inheritedFrom[epgDn].add(tDn)

            epgLayout[epgDn] = epgDescriptor

            if noFiltersUsed or epgDescriptor['vrf'] in filterVrfDns:
                externalSubnetLayout.setdefault(epgDescriptor['vrf'], {})
                for subnet in epgDescriptor['externalSubnets']:
                    ip = subnet[0]
                    # Check for duplicate l3extSubnet in the same VRF
                    for extEpg, externalSubnets in externalSubnetLayout[epgDescriptor['vrf']].items():
                        for acceptedSubnet in externalSubnets:
                            if ip == acceptedSubnet[0]:
                                logger.error("Aborting analysis since External EPG {} and External EPG {} in VRF {} are mathing the same l3extSubnet {}.\nThis configuration is not supported in ESG since duplicate external subnet selectors in the same VRF are not allowed."
                                             .format(colored(epgDn), colored(extEpg), colored(epgDescriptor['vrf']), colored(ip)))
                                sys.exit(1)
                externalSubnetLayout[epgDescriptor['vrf']][epgDn] = epgDescriptor['externalSubnets']

        else:
            logger.warning("Skipping MO {} since it has no VRF assigned.".format(epgDn))

    for epgDn, masterDns in inheritedFrom.items():
        processInheritedContracts(epgDn, masterDns)

    #
    # Step 4: Group similar EPGs into the same ESG. EPGs are considered similar when they have the same
    # contract providers and consumers.
    #
    jsonResult = {'vrfs': [], 'contractClones': [], 'contractIfClones': []}
    visitedEpgs = set()
    groupCount = 0
    contractDnToESGMapping = {}
    logger.info(colored("------------------------------------", bold=True))
    logger.info(colored("RESULTS - Mode {}".format(mode), bold=True))
    logger.info(colored("------------------------------------", bold=True))
    for epgDn, epgData in epgLayout.items():
        if epgData['ignoreMigration']:
            continue
        vrfDn = epgData['vrf']
        if (not epgData['contracts']) and (vrfDn not in vrfsWithVzAnyContract):
            continue
        tenantName = epgData['epgTennant']
        pcEnfPref = epgData['pcEnfPref']
        prefGrMemb = epgData['prefGrMemb']
        if filtersUsed and vrfDn not in filterVrfDns:
            continue
        if epgDn in visitedEpgs:
            continue
        if epgData['unsupportedFeatures']:
            lenUnsupported = len(epgData['unsupportedFeatures'])
            logger.error("Aborting analysis since EPG {} in VRF {} has unsupported features. The unsupported features {}: {}."
                         .format(colored(epgDn), colored(vrfDn),
                                 "are" if lenUnsupported > 1 else "is", colored(", ".join(sorted(epgData['unsupportedFeatures'])))))
            sys.exit(1)
        epgSelectors = set()
        externalSubnetSelectors = set()
        leakInternalSubnetsFromProv = set()
        leakInternalSubnetsFromCons = set()
        leakExternalPrefixes = set()
        leakToConsumerVrfs = set()
        leakToProviderVrfs = set()
        # EPG Selector is only created for AEPGs and l3extInstP
        if isValidDn(epgDn, ['uni', 'tn-', 'ap-', 'epg-']) or isValidDn(epgDn, ['uni', 'tn-', 'out-', 'instP-']):
            epgSelectors.add(epgDn)
        visitedEpgs.add(epgDn)
        appProfileName = epgData['appProfileName']
        if epgData['externalSubnets']:
            externalSubnetSelectors.update(epgData['externalSubnets'])
        if epgData['leakInternalSubnetsFromProv']:
            leakInternalSubnetsFromProv.update(epgData['leakInternalSubnetsFromProv'])
        if epgData['leakInternalSubnetsFromCons']:
            leakInternalSubnetsFromCons.update(epgData['leakInternalSubnetsFromCons'])
        if epgData['leakExternalPrefixes']:
            leakExternalPrefixes.update(epgData['leakExternalPrefixes'])
        if mode == 'optimized' and \
           not epgData['isUseg'] and \
           not epgData['inbOrVzany']:
            for otherEpgDn, otherEpgData in epgLayout.items():
                if otherEpgData['ignoreMigration']:
                    continue
                if otherEpgDn in visitedEpgs:
                    continue
                # EPGs are grouped together if:
                # - mode is optimized
                # - EPGs have same VRF
                # - EPGs have same Tenant since EPGSelector cannot cross Tenant
                # - EPGs have same pcEnfPref since it is not correct to mix enforced and unenforced EPGs
                # - EPGs have same contract layout (providers and consumers)
                # - EPGs are not USeg
                # - EPGs have same prefGrMemb
                if vrfDn == otherEpgData['vrf'] and \
                   tenantName == otherEpgData['epgTennant'] and \
                   pcEnfPref == otherEpgData['pcEnfPref'] and \
                   not otherEpgData['isUseg'] and \
                   prefGrMemb == otherEpgData['prefGrMemb'] and \
                   epgData['contracts'] == otherEpgData['contracts']:
                    if otherEpgData['unsupportedFeatures']:
                        lenOtherUnsupported = len(otherEpgData['unsupportedFeatures'])
                        logger.error("Aborting analysis since EPG {} in VRF {} has unsupported features. The MO{} found referencing unsupported features {} {}."
                                    .format(colored(epgDn), colored(vrfDn), "s" if lenOtherUnsupported > 1 else "",
                                            "are" if lenOtherUnsupported > 1 else "is", colored(", ".join(sorted(otherEpgData['unsupportedFeatures'])))))
                        sys.exit(1)

                    # EPG Selector is only created for AEPGs and l3extInstP
                    if isValidDn(otherEpgDn, ['uni', 'tn-', 'ap-', 'epg-']) or isValidDn(otherEpgDn, ['uni', 'tn-', 'out-', 'instP-']):
                        epgSelectors.add(otherEpgDn)
                    visitedEpgs.add(otherEpgDn)
                    if otherEpgData['externalSubnets']:
                        externalSubnetSelectors.update(otherEpgData['externalSubnets'])
                    if otherEpgData['leakInternalSubnetsFromProv']:
                        leakInternalSubnetsFromProv.update(otherEpgData['leakInternalSubnetsFromProv'])
                    if otherEpgData['leakInternalSubnetsFromCons']:
                        leakInternalSubnetsFromCons.update(otherEpgData['leakInternalSubnetsFromCons'])
                    if otherEpgData['leakExternalPrefixes']:
                        leakExternalPrefixes.update(otherEpgData['leakExternalPrefixes'])

        if epgData['inbOrVzany'] or epgData['className'] == "fvESg":
            esgDn = epgDn
        else:
            if mode == 'one-to-one' or len(epgSelectors) <= 1:
                epgName = getNameFromDn(epgDn)
                name = "ESG_" + epgName
                if re.search(r'(?i)epg', epgName) is not None:
                    name = re.sub(r'(?i)epg',
                                  lambda m: "ESG" if m.group().isupper()
                                                  else "esg" if m.group().islower()
                                                  else "Esg",
                                  epgName)
            else:
                groupCount += 1
                name = "ESG_{}_{}_{}".format(tenantName, appProfileName, groupCount)
            esgDn = "uni/tn-{}/ap-{}/esg-{}".format(tenantName, appProfileName, name)

        esgProv = []
        esgCons = []
        esgConsif = []
        esgIntraepg = []
        contracts = sorted(list(epgData['contracts']))
        for contract in contracts:
            extractedDn = contract.split(':', 1)[1]
            if contract.startswith('consif:'):
                contractDn = cpIfToContract.get(extractedDn, '')
            else:
                contractDn = extractedDn
            if contractDn not in contractDnToESGMapping:
                contractDnToESGMapping[contractDn] = {'prov': set(), 'cons': set(), 'consif': set(), 'intraepg': set()}

            if contract.startswith('prov:'):
                esgProv.append(contractDn)
                contractDnToESGMapping[contractDn]['prov'].add(esgDn)
                # Get Target VRFs if leak subnets are present
                if leakInternalSubnetsFromProv or leakExternalPrefixes:
                    consumerEPGs = brCPToConsumer.get(contractDn, set())
                    for consumerEpg in consumerEPGs:
                        consumerVrfDn = epgLayout.get(consumerEpg, {}).get("vrf", None)
                        if not consumerVrfDn:
                            logger.warning("Cannot find Vrf for epg: {}".format(consumerEpg))
                        elif vrfDn != consumerVrfDn:
                            leakToConsumerVrfs.add(consumerVrfDn)
            elif contract.startswith('cons:'):
                esgCons.append(contractDn)
                contractDnToESGMapping[contractDn]['cons'].add(esgDn)
                # Get Target VRFs if leak subnets are present
                if leakInternalSubnetsFromCons or leakExternalPrefixes:
                    providerEPGs = brCPToProvider.get(contractDn, set())
                    for providerEpg in providerEPGs:
                        providerVrfDn = epgLayout.get(providerEpg, {}).get("vrf", None)
                        if not providerVrfDn:
                            logger.warning("Cannot find Vrf for epg: {}".format(providerEpg))
                        elif vrfDn != providerVrfDn:
                            leakToProviderVrfs.add(providerVrfDn)
            elif contract.startswith('consif:'):
                esgConsif.append(extractedDn)
                contractDnToESGMapping[contractDn]['consif'].add((extractedDn, esgDn))
                # Get Target VRFs if leak subnets are present
                if leakInternalSubnetsFromCons or leakExternalPrefixes:
                    providerEPGs = brCPToProvider.get(contractDn, set())
                    for providerEpg in providerEPGs:
                        providerVrfDn = epgLayout.get(providerEpg, {}).get("vrf", None)
                        if not providerVrfDn:
                            logger.warning("Cannot find Vrf for epg: {}".format(providerEpg))
                        elif vrfDn != providerVrfDn:
                            leakToProviderVrfs.add(providerVrfDn)
            elif contract.startswith('intraepg:'):
                esgIntraepg.append(contractDn)
                contractDnToESGMapping[contractDn]['intraepg'].add(esgDn)

        # If the epgData is for an ESG, reach this point so that the contracts are properly
        # mapped in contractDnToESGMapping, but skip the rest of the processing
        if epgData['className'] == "fvESg":
            continue

        if filterVrfDns:
            missingVrfs = (leakToConsumerVrfs | leakToProviderVrfs) - set(filterVrfDns)
            if missingVrfs:
                text = "\nEPGs in VRF {} are configured with shared services pointing to VRFs that are not included in the current VRF or Tenant filter lists.\n".format(vrfDn)
                text += "The missing target VRF{}: {}\n".format('s are' if len(missingVrfs) > 1 else ' is', ','.join(sorted(list(missingVrfs))))
                text += "Migrating a VRF without its required target VRFs is not supported. To resolve this please:\n"
                text += "  1) Add the missing VRFs to the VRF filter list, or\n"
                text += "  2) Add the corresponding Tenants to the Tenant filter list, or\n"
                text += "  3) Run the script for the entire Fabric without using any VRF/Tenant filters.\n"
                text += "Filter lists can be combined.\n"
                text += "Current filter used:\n "
                if filterTenantDns:
                    text += "--tenantdns {} ".format(",".join(filterTenantDns))
                filteredVrfs = [
                    vrf for vrf in filterVrfDns
                    if not any(vrf.startswith(tenant + "/") for tenant in filterTenantDns)
                ]
                if filteredVrfs:
                    text += "--vrfdns {}".format(",".join(filteredVrfs))
                text += "\nNew suggested filter:\n "
                if filterTenantDns:
                    text += "--tenantdns {} ".format(",".join(filterTenantDns))
                filteredVrfs = [
                    vrf for vrf in set(filterVrfDns) | missingVrfs
                    if not any(vrf.startswith(tenant + "/") for tenant in filterTenantDns)
                ]
                text += "--vrfdns {}".format(",".join(filteredVrfs))
                logger.error(text)
                sys.exit(1)

        debugInfo = ""
        # Populate JSON result only if there are EPG selectors or External Subnet selectors
        esgJson = None
        if epgSelectors or externalSubnetSelectors:
            esgJson = {'name': name,
                       'applicationProfile': appProfileName,
                       'pcEnfPref': pcEnfPref,
                       'prefGrMemb': prefGrMemb,
                       'epgs':  sorted(list(epgSelectors)),
                       'externalSubnets': [{'ip': ip, 'scope': scope} for ip, scope in externalSubnetSelectors],
                       'prov': esgProv, 'cons': esgCons, 'consif': esgConsif, 'intraepg': esgIntraepg}
            debugInfo = addEsgGroupDebugInfo(esgJson, vrfDn, debugInfo)

            vrfPresent = False
            for vrf in jsonResult['vrfs']:
                if vrf['vrf'] == vrfDn:
                    vrfPresent = True
                    vrf['esgs'].append(esgJson)
                    break
            if not vrfPresent:
                # Create new VRF entry if not present
                jsonResult['vrfs'].append({'vrf': vrfDn, 'esgs': [esgJson], 'leakInternalSubnets': [], 'leakExternalPrefixes': []})

        # Handle leak subnets and prefixes
        # Populate leak subnets and prefixes at the VRF level
        if (leakInternalSubnetsFromProv or leakExternalPrefixes) and (leakToConsumerVrfs):
            for vrf in jsonResult['vrfs']:
                if vrf['vrf'] == vrfDn:
                    for ip, scope in leakInternalSubnetsFromProv:
                        found = False
                        for entry in vrf['leakInternalSubnets']:
                            if entry['ip'] == ip and entry['scope'] == scope:
                                entry['leakTo'].update(leakToConsumerVrfs)
                                found = True
                                break
                        if not found:
                            vrf['leakInternalSubnets'].append({'ip': ip, 'scope':scope, 'leakTo': leakToConsumerVrfs})
                    for prefix, aggregate in leakExternalPrefixes:
                        found = False
                        for entry in vrf['leakExternalPrefixes']:
                            if entry['ip'] == prefix:
                                entry['leakTo'].update(leakToConsumerVrfs)
                                if aggregate == "shared-rtctrl":
                                    entry['le'] = 32 if ipaddress.ip_network(prefix).version == 4 else 128
                                found = True
                                break
                        if not found:
                            le = 'unspecified'
                            ge = 'unspecified'
                            if aggregate == "shared-rtctrl":
                                le = 32 if ipaddress.ip_network(prefix).version == 4 else 128
                            vrf['leakExternalPrefixes'].append({'ip': prefix, 'le': le, 'ge': ge, 'leakTo': leakToConsumerVrfs})
                    break
            debugInfo = addLeakRouteDebugInfo(leakInternalSubnetsFromProv, leakExternalPrefixes, leakToConsumerVrfs, vrfDn, esgJson, debugInfo)

        if (leakInternalSubnetsFromCons or leakExternalPrefixes) and (leakToProviderVrfs):
            for vrf in jsonResult['vrfs']:
                if vrf['vrf'] == vrfDn:
                    for ip, scope in leakInternalSubnetsFromCons:
                        found = False
                        for entry in vrf['leakInternalSubnets']:
                            if entry['ip'] == ip and entry['scope'] == scope:
                                entry['leakTo'].update(leakToProviderVrfs)
                                found = True
                                break
                        if not found:
                            vrf['leakInternalSubnets'].append({'ip': ip, 'scope':scope, 'leakTo': leakToProviderVrfs})
                    for prefix, aggregate in leakExternalPrefixes:
                        found = False
                        for entry in vrf['leakExternalPrefixes']:
                            if entry['ip'] == prefix:
                                entry['leakTo'].update(leakToProviderVrfs)
                                if aggregate == "shared-rtctrl":
                                    entry['le'] = 32 if ipaddress.ip_network(prefix).version == 4 else 128
                                found = True
                                break
                        if not found:
                            le = 'unspecified'
                            ge = 'unspecified'
                            if aggregate == "shared-rtctrl":
                                le = 32 if ipaddress.ip_network(prefix).version == 4 else 128
                            vrf['leakExternalPrefixes'].append({'ip': prefix, 'le': le, 'ge': ge, 'leakTo': leakToProviderVrfs})
                    break
            debugInfo = addLeakRouteDebugInfo(leakInternalSubnetsFromCons, leakExternalPrefixes, leakToProviderVrfs, vrfDn, esgJson, debugInfo)

        if debugInfo:
            logger.info(debugInfo)

    # Sort the leak subnets and prefixes and the contract clones for consistent output
    # Get the list of contracts references
    # Cleanup unused fields
    contractsReferences = set()
    for vrf in jsonResult['vrfs']:
        vrf['leakInternalSubnets'] = sorted(vrf['leakInternalSubnets'], key=lambda x: x['ip'])
        vrf['leakExternalPrefixes'] = sorted(vrf['leakExternalPrefixes'], key=lambda x: x['ip'])
        for esg in vrf['esgs']:
            if esg['externalSubnets']:
                esg['externalSubnets'] = sorted(esg['externalSubnets'], key=lambda x: x['ip'])
            else:
                del esg['externalSubnets']
            for key in ['prov', 'cons', 'consif', 'intraepg']:
                for contractDn in esg[key]:
                    contractsReferences.add(contractDn)
            if esg['pcEnfPref'] == "unenforced":
                del esg['pcEnfPref']
            if esg['prefGrMemb'] == "exclude":
                del esg['prefGrMemb']
        for leakInternalSubnet in vrf['leakInternalSubnets']:
            leakInternalSubnet['leakTo'] = sorted(leakInternalSubnet['leakTo'])
        for leakExternalPrefix in vrf['leakExternalPrefixes']:
            leakExternalPrefix['leakTo'] = sorted(leakExternalPrefix['leakTo'])
            if leakExternalPrefix['le'] == 'unspecified':
                del leakExternalPrefix['le']
            if leakExternalPrefix['ge'] == 'unspecified':
                del leakExternalPrefix['ge']

    # Create contractIfClones and contractClones and handle 2 corner cases:
    # - In non ndCompliant mode, only create clones for contracts that are referenced by at least one ESG
    #   This can happen if a contract in contractDnToESGMapping is attached to a vzAny or mgmtInB EPG and
    #   that contract is not used by any other EPGs
    # - In ndCompliant mode, create clones for combinations of provider/consumer/intraepg. If a contract
    #   does not have a pairing provider/consumer/intraepg, the reference needs to be removed from the ESG.
    #   This can happen only when a contract is attached to one side (partial unused contract).
    clonedFromDns = set()
    for contractDn in sorted(contractDnToESGMapping.keys()):
        if not ndCompliant:
            if contractDn not in contractsReferences:
                continue
            consifUnique = set()
            for consif in contractDnToESGMapping[contractDn]['consif']:
                cloneFromDn = consif[0]
                if cloneFromDn in consifUnique:
                    continue
                consifUnique.add(cloneFromDn)
                contractName = getNameFromDn(cloneFromDn)
                jsonResult['contractIfClones'].append(
                    {'cloneName': namePrefix + contractName + nameSuffix,
                    'cloneFromDn': cloneFromDn,
                    'exportedFromDn': contractDn})
                clonedFromDns.add(contractDn)
                clonedFromDns.add(cloneFromDn)
        else:
            count = 0
            for consif in contractDnToESGMapping[contractDn]['consif']:
                cloneFromDn = consif[0]
                contractName = getNameFromDn(cloneFromDn)
                count += 1
                jsonResult['contractIfClones'].append(
                    {'cloneName': namePrefix + contractName + nameSuffix + '_' + str(count),
                    'cloneFromDn': cloneFromDn,
                    'exportedFromDn': contractDn,
                    'consumerESG': consif[1]})
                clonedFromDns.add(contractDn)
                clonedFromDns.add(cloneFromDn)

    for contractDn in sorted(contractDnToESGMapping.keys()):
        contractName = getNameFromDn(contractDn)
        if not ndCompliant:
            if contractDn not in contractsReferences:
                continue
            jsonResult['contractClones'].append(
                {'cloneName': namePrefix + contractName + nameSuffix,
                'cloneFromDn': contractDn})
            clonedFromDns.add(contractDn)
        else:
            count = 0
            for prov in contractDnToESGMapping[contractDn]['prov']:
                for cons in contractDnToESGMapping[contractDn]['cons']:
                    count += 1
                    jsonResult['contractClones'].append(
                        {'cloneName': namePrefix + contractName + nameSuffix + '_' + str(count),
                        'cloneFromDn': contractDn,
                        'providerESG': prov,
                        'consumerESG': cons})
                    clonedFromDns.add(contractDn)
            for prov in contractDnToESGMapping[contractDn]['prov']:
                for consif in contractDnToESGMapping[contractDn]['consif']:
                    for contractIfClones in jsonResult['contractIfClones']:
                        if contractIfClones['cloneFromDn'] == consif[0]:
                            count += 1
                            jsonResult['contractClones'].append(
                                {'cloneName': namePrefix + contractName + nameSuffix + '_' + str(count),
                                'cloneFromDn': contractDn,
                                'providerESG': prov,
                                'consumerESG': consif[1]})
                            clonedFromDns.add(contractDn)
                            clonedFromDns.add(consif[0])
            for intraepg in contractDnToESGMapping[contractDn]['intraepg']:
                count += 1
                jsonResult['contractClones'].append(
                    {'cloneName': namePrefix + contractName + nameSuffix + '_' + str(count),
                    'cloneFromDn': contractDn,
                    'intraESG': intraepg})
                clonedFromDns.add(contractDn)

    # Now Cleanup ESG references to contracts that are not cloned.
    # This can happen in ndCompliant mode when a contract is partially used.
    # For example, a contract is only used as provider but not as consumer.
    # Delete also empty contract lists
    for vrf in jsonResult['vrfs']:
        for esg in vrf['esgs']:
            for key in ['prov', 'cons', 'consif', 'intraepg']:
                prevous = len(esg[key])
                esg[key] = [c for c in esg[key] if c in clonedFromDns]
                if prevous != len(esg[key]):
                    logger.info("Removed {} references from ESG {} since the contract was not cloned".format(prevous - len(esg[key]), esg['name']))
                if not esg[key]:
                    del esg[key]

    #
    # Step 5: Write the report files and shows stats
    #
    if yamlOutputFile:
        try:
            with open(yamlOutputFile, "w") as yamlFile:
                spinner.text = "Writing ESG analysis to YAML file"
                yamlFile.write("# YAML file generated via ESG Migration Assistant\n")
                yamlFile.write("# Contract cloned using {} style\n".format("Nexus Dashboard" if ndCompliant else "ACI native"))
                yaml.dump(jsonResult, yamlFile, sort_keys=False, default_flow_style=False)
                logger.info("Wrote ESG analysis to YAML file: {}".format(yamlOutputFile))
        except Exception as e:
            logger.error(f"Failed to write YAML file {yamlOutputFile}: {e}")

    if showStats:
        vrfDescriptors = {}
        for vrf in jsonResult['vrfs']:
            vrfDescriptors[vrf['vrf']] = {'BDSet': set(),
                                        'contractSet': set(),
                                        'numAEPGs': 0,
                                        'numExtEPGs': 0,
                                        'numPrefGrMemb': 0,
                                        'numPcEnfPrefEnforced': 0,
                                        'numSecInherited': 0,
                                        'numUsegs': 0,
                                        'numExternalSubnets': 0,}

        for epgDn, epgDescriptor in epgLayout.items():
            vrfDn = epgDescriptor['vrf']
            if vrfDn in vrfDescriptors:
                if epgDescriptor['bd']:
                    vrfDescriptors[vrfDn]['BDSet'].add(epgDescriptor['bd'])
                if epgDescriptor['className'] == "fvAEPg" and not epgDescriptor['isUseg']:
                    vrfDescriptors[vrfDn]['numAEPGs'] += 1
                elif epgDescriptor['className'] == "l3extInstP":
                    vrfDescriptors[vrfDn]['numExtEPGs'] += 1
                if epgDescriptor['prefGrMemb'] == 'include':
                    vrfDescriptors[vrfDn]['numPrefGrMemb'] += 1
                if epgDescriptor['pcEnfPref'] == 'enforced':
                    vrfDescriptors[vrfDn]['numPcEnfPrefEnforced'] += 1
                if epgDescriptor['hasInheritedContracts']:
                    vrfDescriptors[vrfDn]['numSecInherited'] += 1
                if epgDescriptor['isUseg']:
                    vrfDescriptors[vrfDn]['numUsegs'] += 1
                if epgDescriptor['externalSubnets']:
                    vrfDescriptors[vrfDn]['numExternalSubnets'] += len(epgDescriptor['externalSubnets'])
                for provCons in epgDescriptor['contracts']:
                    contract = provCons.split(':', 1)[1]
                    vrfDescriptors[vrfDn]['contractSet'].add(contract)

        print()
        logger.info(colored("VRF Summary:"))
        for vrfDn, vrfDescriptor in vrfDescriptors.items():
            logger.info(colored("VRF: {}".format(vrfDn)))
            logger.info("  Number of BDs: {}".format(len(vrfDescriptor['BDSet'])))
            logger.info("  Number of Application EPGs: {}".format(vrfDescriptor['numAEPGs']))
            logger.info("  Number of Useg EPGs: {}".format(vrfDescriptor['numUsegs']))
            logger.info("  Number of External EPGs: {}".format(vrfDescriptor['numExtEPGs']))
            logger.info("  Number of Contracts: {}".format(len(vrfDescriptor['contractSet'])))
            logger.info("  Number of EPGs with preferred group: {}".format(vrfDescriptor['numPrefGrMemb']))
            logger.info("  Number of EPGs with pcEnfPref enforced: {}".format(vrfDescriptor['numPcEnfPrefEnforced']))
            logger.info("  Number of EPGs inheriting contracts: {}".format(vrfDescriptor['numSecInherited']))
            logger.info("  Number of External Subnets in External EPGs: {}".format(vrfDescriptor['numExternalSubnets']))

    logger.info(colored("------------------------------------", bold=True))
    logger.info(colored("END of dryrun", bold=True))
    logger.info(colored("------------------------------------\n", bold=True))


#########################################################
# CONVERSION PHASE
#########################################################
class ContractConversionDescriptor:
    def __init__(self):
        self._contractDescriptor = {}
        self._contractIfDescriptor = {}

    def addContract(self, newContractDn, newContractMo, cloneFromDn,
                    provider=None, consumer=None, intra=None):

        self._contractDescriptor[newContractDn] = {
            "mo": newContractMo,
            "fromDn": cloneFromDn,
            "providerESG": provider,
            "consumerESG": consumer,
            "intraESG": intra,
            "ndContract": provider is not None or consumer is not None or intra is not None
        }

    def addContractIf(self, newContractIfDn, cloneFromDn, exportedFromDn, consumer=None):
        for newDn, data in self._contractDescriptor.items():
            # If the consumerDn is None (not ndCompliant), find a contracts not ndCompliant
            # If the consumerDn is not None, return only contracts with a providerESG
            if data['fromDn'] == exportedFromDn:
                newExportedFromDn = None
                ndContract = data['ndContract']
                if consumer is not None:
                    if ndContract and data['providerESG'] and data['consumerESG'] == consumer:
                        newExportedFromDn = newDn
                else:
                    if not ndContract:
                        newExportedFromDn = newDn

                if newExportedFromDn:
                    self._contractIfDescriptor[newContractIfDn] = {
                        "exportedFromDn": exportedFromDn,
                        "newExportedFromDn": newExportedFromDn,
                        "fromDn": cloneFromDn,
                        "consumerESG": consumer,
                        "ndContract": consumer is not None
                    }
                    break

    def _getByRole(self, contract, roleKey, provConsDn):
        results = []
        for newDn, data in self._contractDescriptor.items():
            if data['fromDn'] == contract:
                isNdContract = data.get('ndContract', False)
                if not isNdContract or data.get(roleKey) == provConsDn:
                    results.append({"newContractDn": newDn, "mo": data["mo"]})

        return results

    def getByProvider(self, contract, providerDn):
        return self._getByRole(contract, "providerESG", providerDn)

    def getByConsumer(self, contract, consumerDn):
        return self._getByRole(contract, "consumerESG", consumerDn)

    def getByIntraEPG(self, contract, intraDn):
        return self._getByRole(contract, "intraESG", intraDn)

    def getByConsumerIf(self, contractIf, consumerDn):
        results = []
        for newDn, data in self._contractIfDescriptor.items():
            if data['fromDn'] == contractIf:
                ndContract = data['ndContract']
                if not ndContract or data['consumerESG'] == consumerDn:
                    results.append({"newContractDn": newDn, "newExportedFromDn": data["newExportedFromDn"]})
        return results

    def getByAny(self, contract):
        results = []
        for newDn, data in self._contractDescriptor.items():
            if data['fromDn'] == contract:
                results.append({"newContractDn": newDn, "mo": data["mo"]})
        return results

    def getAll(self):
        return list(self._contractDescriptor.values())

def cloneNodeSubtree(apic, sourceDn, targetDn, overrideProps):
    """
    Clone Contract Subtree in pyaci node object for conversion case.
    Only config objects in subtree are cloned.
    Override properties contains properties and vals which should
    be different from source Mo in target Mo.
    Returns cloned subtree.
    """
    def cleanupObj(obj):
        if "attributes" in obj and isinstance(obj["attributes"], dict):
            obj["attributes"].pop("dn", None)
            obj["attributes"].pop("userdom", None)
            for k in list(obj["attributes"].keys()):
                if obj["attributes"][k] in ["", "unspecified"]:
                    obj["attributes"].pop(k, None)

        # recurse into children
        if "children" in obj and isinstance(obj["children"], list):
            for child in obj["children"]:
                for nested in child.values():
                    cleanupObj(nested)

    logger = logging.getLogger(globalValues['logger'])
    sourceSubtree = apic.mit.FromDn(sourceDn).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'config-only'})

    if sourceSubtree and len(sourceSubtree) > 0:
        source = sourceSubtree[0]
    else:
        logger.error(f"Object DN {sourceDn} is not found in the APIC.")
        return None

    # Use source as baseline
    resDict = source._dataDict()

    target = apic.mit.FromDn(targetDn)
    # Now take the props from the target we expect to override
    k = list(resDict.keys())[0]

    for p in target._dataDict()[k]['attributes'].keys():
        resDict[k]['attributes'][p] = target._dataDict()[k]['attributes'][p]

    for overrideProp, overridePropVal in overrideProps.items():
        resDict[k]['attributes'][overrideProp] = overridePropVal

    # Delete unneeded properties before write
    cleanupObj(resDict[k])
    target.Json = json.dumps(resDict, separators=(',', ': '))

    return target

def validateESgToVrf(node, esgToVrfMap, perVrfPreExistingEsgMap):
    """
    Helper function to validate ESG to VRF mapping.
    Validates that all VRFs mapped to ESGs exist and that the mapping
    on APIC matches the mapping in the YAML file.
    1. Get all VRFs configured on APIC.
    2. Validate that all VRFs mapped to ESGs exist.
    3. Get all fvRsScope. Each fvRsScope is created for each ESG and points to the VRF.
    4. Validate that the mapping on APIC matches the mapping in the YAML file.
    Returns ReturnCode.SUCCESS if validation is successful.
    Returns ReturnCode.VALIDATION_FAILED if validation fails.
    """
    logger = logging.getLogger(globalValues['logger'])
    spinner.text = "Validating existing ESG to VRF mapping"

    vrfConfigured = set()
    result = node.methods.ResolveClass('fvCtx').GET()
    for mo in result:
        vrfConfigured.add(mo.dn)

    # Validate that all VRFs mapped to ESGs exist
    for esgDn, (vrfDn, esg_line) in esgToVrfMap.items():
        if vrfDn not in vrfConfigured:
            logger.error("ESG {} (line {}) on YAML file is mapped to VRF {} which does not exist on APIC".format(getNameFromDn(esgDn), esg_line, vrfDn))
            return ReturnCode.VALIDATION_FAILED

    # Get all the fvRsScope. Each fvRsScope is created for each ESG and points to the VRF.
    result = node.methods.ResolveClass('fvRsScope').GET()
    for mo in result:
        if mo.tDn:
            esgDn = mo.Parent.Dn
            if esgDn in esgToVrfMap:
                expectedVrfDn, esg_line = esgToVrfMap[esgDn]
                if mo.tDn != expectedVrfDn:
                    logger.error("ESG {} (line {}) on YAML file is mapped to VRF {} but the same ESG on APIC is mapped to VRF {}".format(getNameFromDn(esgDn), esg_line, expectedVrfDn, mo.tDn))
                    return ReturnCode.VALIDATION_FAILED
            else:
                perVrfPreExistingEsgMap.setdefault(mo.tDn, set()).add(esgDn)

    return ReturnCode.SUCCESS

def validateAndCloneContracts(node, esgDataFromYaml, contractConversionDescriptor):
    """
    Helper function to validate EPG contracts.
    Clones all config objects of EPG contract + subtree and returns it via
    contractConversionDescriptor. This is used for POSTs later during conversion.
    """
    logger = logging.getLogger(globalValues['logger'])

    for contractData in esgDataFromYaml['contractClones']:
        cloneFromDn = contractData['cloneFromDn']
        cloneName = contractData['cloneName']
        newContractDn = getNewContractDn(cloneName, cloneFromDn)
        overrideProps = {'name': cloneName}
        newContractMo = cloneNodeSubtree(node, cloneFromDn, newContractDn, overrideProps)
        if not newContractMo:
            logger.error("Could not clone {} to {}".format(cloneFromDn, newContractDn))
            return ReturnCode.GETFAILED
        contractConversionDescriptor.addContract(newContractDn, newContractMo, cloneFromDn,
                                           provider=contractData.get('providerESG', None),
                                           consumer=contractData.get('consumerESG', None),
                                           intra=contractData.get('intraESG', None))

    for contractIfData in esgDataFromYaml['contractIfClones']:
        cloneFromDn = contractIfData['cloneFromDn']
        cloneName = contractIfData['cloneName']
        newContractIfDn = getNewContractIfDn(cloneName, cloneFromDn)
        contractConversionDescriptor.addContractIf(newContractIfDn, cloneFromDn,
                                                  exportedFromDn=contractIfData['exportedFromDn'],
                                                  consumer=contractIfData.get('consumerESG', None))
    return ReturnCode.SUCCESS

def validateInputYamlData(esgDataFromYaml, esgToVrfMap):
    """
    Helper function to validate Input Yaml file data prior to executing conversion.
    User has the option to modify Yaml file generated in dryrun phase.
    This function validates the user changes to prevent issues during conversion.
    """
    logger = logging.getLogger(globalValues['logger'])

    logger.info("Validate YAML input file data")
    validName = re.compile(r'[^a-zA-Z0-9_.:-]')

    vrfSet = set()
    epgSet = set()

    if 'vrfs' not in esgDataFromYaml or not isinstance(esgDataFromYaml['vrfs'], list) or len(esgDataFromYaml['vrfs']) == 0:
        logger.error("No VRFs defined in YAML file.")
        return False
    if 'contractClones' not in esgDataFromYaml or not isinstance(esgDataFromYaml['contractClones'], list):
        logger.error("No contractClones defined in YAML file.")
        return False
    if 'contractIfClones' not in esgDataFromYaml or not isinstance(esgDataFromYaml['contractIfClones'], list):
        logger.error("No contractIfClones defined in YAML file.")
        return False

    for contractData in esgDataFromYaml['contractClones']:
        line = contractData.get('__line__', '?')
        if 'cloneName' not in contractData or not contractData['cloneName']:
            logger.error("cloneName missing in contractClones entry: {} (line {})".format(contractData, line))
            return False
        cloneName = contractData['cloneName']
        if validName.search(cloneName):
            logger.error("cloneName '{}' contains invalid characters. Only alphanumeric characters, underscores (_), hyphens (-), periods (.), colons (:) are allowed. (line {})".format(cloneName, line))
            return False
        if len(cloneName) > 64:
            logger.error("cloneName '{}' exceeds maximum length of 64 characters. (line {})".format(cloneName, line))
            return False
        if 'cloneFromDn' not in contractData or not contractData['cloneFromDn']:
            logger.error("cloneFromDn missing in contractClones entry with cloneName {}: {} (line {})".format(cloneName, contractData, line))
            return False
        cloneFromDn = contractData['cloneFromDn']
        if not isValidDn(cloneFromDn, ['uni', 'tn-', 'brc-']):
            logger.error("cloneFromDn '{}' in contractClones entry with cloneName {} is not valid. The format should be 'uni/tn-<tenant_name>/brc-<contract_name>' (line {})".format(cloneFromDn, cloneName, line))
            return False
        if 'providerESG' in contractData and 'consumerESG' not in contractData:
            logger.error("consumerESG missing in contractClones entry with cloneName {}: {} (line {})".format(cloneName, contractData, line))
            return False
        if 'consumerESG' in contractData and 'providerESG' not in contractData:
            logger.error("providerESG missing in contractClones entry with cloneName {}: {} (line {})".format(cloneName, contractData, line))
            return False
        if 'intraESG' in contractData:
            if 'providerESG' in contractData or 'consumerESG' in contractData:
                logger.error("intraESG cannot be combined with providerESG or consumerESG in contractClones entry with cloneName {}: {} (line {})".format(cloneName, contractData, line))
                return False
        for type in ['providerESG', 'consumerESG', 'intraESG']:
            if type in contractData:
                provcons = contractData[type]
                if not isValidDn(provcons, ['uni', 'tn-', 'ap-', 'esg-']) and \
                   not isValidDn(provcons, ['uni', 'tn-', 'ctx-', 'any']) and \
                   not isValidDn(provcons, ['uni', 'tn-', 'mgmtp-', 'inb-']):
                    logger.error("{} '{}' in contractClones entry with cloneName {} is not valid.' (line {})".format(type, provcons, cloneName, line))
                    return False
    for contractIfData in esgDataFromYaml['contractIfClones']:
        line = contractIfData.get('__line__', '?')
        if 'cloneName' not in contractIfData or not contractIfData['cloneName']:
            logger.error("cloneName missing in contractIfClones entry: {} (line {})".format(contractIfData, line))
            return False
        cloneName = contractIfData['cloneName']
        if validName.search(cloneName):
            logger.error("cloneName '{}' contains invalid characters. Only alphanumeric characters, underscores (_), hyphens (-), periods (.), colons (:) are allowed. (line {})".format(cloneName, line))
            return False
        if len(cloneName) > 64:
            logger.error("cloneName '{}' exceeds maximum length of 64 characters. (line {})".format(cloneName, line))
            return False
        if 'cloneFromDn' not in contractIfData or not contractIfData['cloneFromDn']:
            logger.error("cloneFromDn missing in contractIfClones entry with cloneName {}: {} (line {})".format(cloneName, contractIfData, line))
            return False
        cloneFromDn = contractIfData['cloneFromDn']
        if not isValidDn(cloneFromDn, ['uni', 'tn-', 'cif-']):
            logger.error("cloneFromDn '{}' in contractIfClones entry with cloneName {} is not valid. The format should be 'uni/tn-<tenant_name>/cif-<contract_if_name>' (line {})".format(cloneFromDn, cloneName, line))
            return False
        if 'exportedFromDn' not in contractIfData or not contractIfData['exportedFromDn']:
            logger.error("exportedFromDn missing in contractIfClones entry with cloneName {}: {} (line {})".format(cloneName, contractIfData, line))
            return False
        exportedFromDn = contractIfData['exportedFromDn']
        if not isValidDn(exportedFromDn, ['uni', 'tn-', 'brc-']):
            logger.error("exportedFromDn '{}' in contractIfClones entry with cloneName {} is not valid. The format should be 'uni/tn-<tenant_name>/brc-<contract_name>' (line {})".format(exportedFromDn, cloneName, line))
            return False
        exportedFromDnFound = False
        for contractData in esgDataFromYaml['contractClones']:
            if contractData.get('cloneFromDn', '') == exportedFromDn:
                exportedFromDnFound = True
                break
        if not exportedFromDnFound:
            logger.error("exportedFromDn '{}' in contractIfClones entry with cloneName {} does not match any cloneFromDn in contractClones entries. (line {})".format(exportedFromDn, cloneName, line))
            return False
        if 'providerESG' in contractIfData or 'intraESG' in contractIfData:
            logger.error("providerESG or intraESG cannot be present in contractIfClones entry with cloneName {}: {} (line {})".format(cloneName, contractIfData, line))
            return False
        if 'consumerESG' in contractIfData:
            consumerESG = contractIfData['consumerESG']
            if not isValidDn(consumerESG, ['uni', 'tn-', 'ap-', 'esg-']) and \
                not isValidDn(consumerESG, ['uni', 'tn-', 'ctx-', 'any']) and \
                not isValidDn(consumerESG, ['uni', 'tn-', 'mgmtp-', 'inb-']):
                logger.error("consumerESG '{}' in contractClones entry with cloneName {} is not valid.' (line {})".format(consumerESG, cloneName, line))
                return False

    for vrfData in esgDataFromYaml['vrfs']:
        line = vrfData.get('__line__', '?')
        perVrfExternalSubnet = {}
        if 'vrf' not in vrfData:
            logger.error("VRF entry missing in YAML file: {} (line {})".format(vrfData, line))
            return False
        vrf = vrfData['vrf']
        if not isValidDn(vrf, ['uni', 'tn-', 'ctx-']):
            logger.error("VRF DN '{}' is not valid. The format should be 'uni/tn-<tenant_name>/ctx-<vrf_name>' (line {})".format(vrf, line))
            return False
        if vrf in vrfSet:
            logger.error("Duplicate VRF entry found in YAML file: {} (line {})".format(vrf, line))
            return False
        else:
            vrfSet.add(vrf)
        if 'esgs' not in vrfData or not isinstance(vrfData['esgs'], list) or len(vrfData['esgs']) == 0:
            logger.error("No ESGs defined for VRF {} in YAML file. (line {})".format(vrf, line))
            return False
        for esg in vrfData['esgs']:
            esg_line = esg.get('__line__', line)
            if 'name' not in esg or not esg['name']:
                logger.error("ESG name missing in VRF {}: {} (line {})".format(vrf, esg, esg_line))
                return False
            esgName = esg['name']
            if validName.search(esgName):
                logger.error("ESG name '{}' in VRF {} contains invalid characters. Only alphanumeric characters, underscores (_), hyphens (-), periods (.), colons (:) are allowed. (line {})".format(esgName, vrf, esg_line))
                return False
            if len(esgName) > 64:
                logger.error("ESG name '{}' in VRF {} exceeds maximum length of 64 characters. (line {})".format(esgName, vrf, esg_line))
                return False
            if 'applicationProfile' not in esg:
                logger.error("Application profile missing in ESG {} in VRF {}. (line {})".format(esgName, vrf, esg_line))
                return False
            apName = esg['applicationProfile']
            if validName.search(apName):
                logger.error("Application Profile name '{}' in ESG {} of VRF {} contains invalid characters. Only alphanumeric characters, underscores (_), hyphens (-), periods (.), colons (:) are allowed. (line {})".format(apName, esgName, vrf, esg_line))
                return False
            if len(apName) > 64:
                logger.error("Application Profile name '{}' in ESG {} of VRF {} exceeds maximum length of 64 characters. (line {})".format(apName, esgName, vrf, esg_line))
                return False
            if 'epgs' not in esg or not isinstance(esg['epgs'], list):
                logger.error("No epgs keyword for ESG {} in VRF {}. (line {})".format(esgName, vrf, esg_line))
                return False
            for epg in esg['epgs']:
                if not isValidDn(epg, ['uni', 'tn-', 'ap-', 'epg-']) and not isValidDn(epg, ['uni', 'tn-', 'out-', 'instP-']):
                    logger.error("EPG DN '{}' in ESG {} of VRF {} is not valid. The format should be 'uni/tn-<tenant_name>/ap-<app_profile_name>/epg-<epg_name>' or 'uni/tn-<tenant_name>/out-<l3out_name>/instP-<instp_name>' (line {})".format(epg, esgName, vrf, esg_line))
                    return False
                if epg in epgSet:
                    logger.error("Duplicate EPG entry '{}' found in ESGs in YAML file (line {})".format(epg, esg_line))
                    return False
                else:
                    epgSet.add(epg)
            tenantName = getTenantFromDn(esg['epgs'][0]) if esg['epgs'] else getTenantFromDn(vrf)
            esgDn = "uni/tn-{}/ap-{}/esg-{}".format(tenantName, esg['applicationProfile'], esgName)
            if esgDn in esgToVrfMap:
                logger.error("Duplicate ESG name '{}' in Application Profile '{}' Tenant '{}'. ESG names must be unique. (line {})".format(esgName, esg['applicationProfile'], tenantName, esg_line))
                return False
            else:
                esgToVrfMap[esgDn] = (vrf, esg_line)
            if 'externalSubnets' in esg:
                if not isinstance(esg['externalSubnets'], list):
                    logger.error("externalSubnets should be a list in ESG {} of VRF {}. (line {})".format(esgName, vrf, esg_line))
                    return False
                for externalSubnet in esg['externalSubnets']:
                    subnet_line = externalSubnet.get('__line__', esg_line)
                    if 'ip' not in externalSubnet or not externalSubnet['ip']:
                        logger.error("IP missing in externalSubnets of ESG {} in VRF {}. (line {})".format(esgName, vrf, subnet_line))
                        return False
                    ip = externalSubnet['ip']
                    try:
                        ipaddress.ip_network(ip, strict=True)
                    except ValueError as ve:
                        logger.error("IP {} in externalSubnets of ESG {} in VRF {} is not a valid IP address or has host bits set: {} (line {})".format(ip, esgName, vrf, ve, subnet_line))
                        return False
                    if ip in perVrfExternalSubnet:
                        logger.error("Duplicate external subnet IP {} between ESG {} and ESG {} in VRF {}. External subnets must be unique across ESGs within the same VRF. (lines {} and {})".format(ip, perVrfExternalSubnet[ip][0], esgName, vrf, perVrfExternalSubnet[ip][1], subnet_line))
                        return False
                    else:
                        perVrfExternalSubnet[ip] = (esgName, subnet_line)
                    if 'scope' not in externalSubnet or externalSubnet['scope'] not in ['private', 'public']:
                        logger.error("Scope missing or invalid in externalSubnets of ESG {} in VRF {}: {}. Valid values are 'private' or 'public'. (line {})".format(esgName, vrf, externalSubnet, subnet_line))
                        return False
            for contractType in ['prov', 'cons', 'consif', 'intraepg']:
                if contractType in esg:
                    if not isinstance(esg[contractType], list):
                        logger.error("Contract type '{}' should be a list in ESG {} of VRF {}. (line {})".format(contractType, esgName, vrf, esg_line))
                        return False
                    for contract in esg[contractType]:
                        if contractType == 'consif':
                            if not isValidDn(contract, ['uni', 'tn-', 'cif-']):
                                logger.error("contract '{}' in 'consif' of ESG {} in VRF {} is not valid. The format should be 'uni/tn-<tenant_name>/cif-<contract_if_name>' (line {})".format(contract, esgName, vrf, esg_line))
                                return False
                            contractFound = False
                            for clone in esgDataFromYaml['contractIfClones']:
                                if contract == clone['cloneFromDn']:
                                    contractFound = True
                                    break
                            if not contractFound:
                                logger.error("contract '{}' in 'consif' of ESG {} in VRF {} does not match any clone. (line {})".format(contract, esgName, vrf, esg_line))
                                return False
                        else:
                            if not isValidDn(contract, ['uni', 'tn-', 'brc-']):
                                logger.error("contract '{}' in '{}' of ESG {} in VRF {} is not valid. The format should be 'uni/tn-<tenant_name>/brc-<contract_name>' (line {})".format(contract, contractType, esgName, vrf, esg_line))
                                return False
                            contractFound = False
                            for clone in esgDataFromYaml['contractClones']:
                                if contract == clone['cloneFromDn']:
                                    contractFound = True
                                    break
                            if not contractFound:
                                logger.error("contract '{}' in '{}' of ESG {} in VRF {} does not match any clone. (line {})".format(contract, contractType, esgName, vrf, esg_line))
                                return False

        if 'leakInternalSubnets' in vrfData:
            for leakInternalSubnet in vrfData['leakInternalSubnets']:
                subnet_line = leakInternalSubnet.get('__line__', line)
                if 'ip' not in leakInternalSubnet or not leakInternalSubnet['ip']:
                    logger.error("IP missing in leakInternalSubnets of VRF {}: {} (line {})".format(vrf, leakInternalSubnet, subnet_line))
                    return False
                ip = leakInternalSubnet['ip']
                try:
                    ipaddress.ip_network(ip, strict=True)
                except ValueError as ve:
                    logger.error("IP {} in leakInternalSubnets of VRF {} is not a valid IP address or network or has host bits set: {} (line {})".format(ip, vrf, ve, subnet_line))
                    return False
                if 'scope' not in leakInternalSubnet or leakInternalSubnet['scope'] not in ['private', 'public']:
                    logger.error("Scope missing or invalid in leakInternalSubnets of VRF {}: {}. Valid values are 'private' or 'public'. (line {})".format(vrf, leakInternalSubnet, subnet_line))
                    return False
                if 'leakTo' not in leakInternalSubnet or not isinstance(leakInternalSubnet['leakTo'], list) or len(leakInternalSubnet['leakTo']) == 0:
                    logger.error("leakTo missing or invalid in leakInternalSubnets of VRF {}: {}. It should be a non-empty list of VRF DNs. (line {})".format(vrf, leakInternalSubnet, subnet_line))
                    return False
        if 'leakExternalPrefixes' in vrfData:
            for leakExternalPrefix in vrfData['leakExternalPrefixes']:
                prefix_line = leakExternalPrefix.get('__line__', line)
                if 'ip' not in leakExternalPrefix or not leakExternalPrefix['ip']:
                    logger.error("IP missing in leakExternalPrefixes of VRF {}: {} (line {})".format(vrf, leakExternalPrefix, prefix_line))
                    return False
                ip = leakExternalPrefix['ip']
                version = 4
                prefixlen = 32
                try:
                    version = ipaddress.ip_network(ip, strict=True).version
                    prefixlen = ipaddress.ip_network(ip, strict=True).prefixlen
                except ValueError as ve:
                    logger.error("IP {} in leakExternalPrefixes of VRF {} is not a valid IP address or network or has host bits set: {} (line {})".format(ip, vrf, ve, prefix_line))
                    return False
                if 'leakTo' not in leakExternalPrefix or not isinstance(leakExternalPrefix['leakTo'], list) or len(leakExternalPrefix['leakTo']) == 0:
                    logger.error("leakTo missing or invalid in leakExternalPrefixes of VRF {}: {}. It should be a non-empty list of VRF DNs. (line {})".format(vrf, leakExternalPrefix, prefix_line))
                    return False
                if 'le' in leakExternalPrefix:
                    le = leakExternalPrefix['le']
                    if not isinstance(le, int):
                        logger.error("le in leakExternalPrefixes of VRF {} must be an integer: {} le {} (line {})".format(vrf, ip, le, prefix_line))
                        return False
                    if version == 4 and (le <= prefixlen or le > 32):
                        logger.error("le in leakExternalPrefixes of VRF {} must be between prefixlen (greater than) and 32 (lower or equal) for IPv4: {} le {} (line {})".format(vrf, ip, le, prefix_line))
                        return False
                    if version == 6 and (le <= prefixlen or le > 128):
                        logger.error("le in leakExternalPrefixes of VRF {} must be between prefixlen (greater than) and 128 (lower or equal) for IPv6: {} le {} (line {})".format(vrf, ip, le, prefix_line))
                        return False
                if 'ge' in leakExternalPrefix:
                    ge = leakExternalPrefix['ge']
                    if not isinstance(ge, int):
                        logger.error("ge in leakExternalPrefixes of VRF {} must be an integer: {} ge {} (line {})".format(vrf, ip, ge, prefix_line))
                        return False
                    if version == 4 and (ge <= prefixlen or ge > 32):
                        logger.error("ge in leakExternalPrefixes of VRF {} must be between prefixlen (greater than) and 32 (lower or equal) for IPv4: {} ge {} (line {})".format(vrf, ip, ge, prefix_line))
                        return False
                    if version == 6 and (ge <= prefixlen or ge > 128):
                        logger.error("ge in leakExternalPrefixes of VRF {} must be between prefixlen (greater than) and 128 (lower or equal) for IPv6: {} ge {} (line {})".format(vrf, ip, ge, prefix_line))
                        return False
                if 'le' in leakExternalPrefix and 'ge' in leakExternalPrefix:
                    if leakExternalPrefix['le'] < leakExternalPrefix['ge']:
                        logger.error("le value must be greater than or equal to ge value in leakExternalPrefixes of VRF {}: {} ge {} le {} (line {})".format(vrf, ip, leakExternalPrefix['ge'], leakExternalPrefix['le'], prefix_line))
                        return False
    return True

def tcamCapacityCheck(node, showInfo=False):
    logger = logging.getLogger(globalValues['logger'])

    spinner.text = "Checking TCAM capacity"

    nodeInfo = {}
    # Get Node Information
    result = node.methods.ResolveClass('fabricNode').GET()
    for mo in result:
        if mo.fabricSt != 'active': continue
        podId = getPodIdFromDn(mo.dn)
        if podId:
            nodeInfo[mo.id] = {'nodeId': int(mo.id), 'podId': podId,
                               'name':mo.name, 'role': mo.role, 'model': mo.model,
                               'scaleProfile': 'unknown',
                               'tcamUsage': 0, 'tcamCapacity': 0, 'tcamUsagePercent': 0.0, 'vrfCount': 0}

    # Get Node Scale Profile
    result = node.methods.ResolveClass('topoctrlFwdScaleProf').GET()
    for mo in result:
        nodeId = getNodeIdFromDn(mo.dn)
        if nodeId and nodeId in nodeInfo:
            nodeInfo[nodeId]['scaleProfile'] = mo.profType

    # Get TCAM Utilization Summary
    # Formula: TCAM Utilization (%) = ( (polUsageCum − polUsageBase) / polUsageCapCum ) × 100
    result = node.methods.ResolveClass('eqptcapacityPolUsage5min').GET()
    for mo in result:
        nodeId = getNodeIdFromDn(mo.dn)
        if nodeId and nodeId in nodeInfo:
            capacity = int(mo.polUsageCapCum)
            usage = int(mo.polUsageCum) - int(mo.polUsageBase)
            nodeInfo[nodeId]['tcamUsage'] = usage
            nodeInfo[nodeId]['tcamCapacity'] = capacity
            nodeInfo[nodeId]['tcamUsagePercent'] = usage/capacity*100 if capacity > 0 else 0

    if showInfo:
        logger.info("TCAM Capacity Information - This is a {}, the actual capacity may vary:".format(colored("5 minutes average", None, underline=True)))
        for nodeId in sorted(nodeInfo.keys(), key=int):  # sort nodeId numerically
            if nodeInfo[nodeId]['role'] == 'leaf':
                percentText = "{:.2f}%".format(nodeInfo[nodeId]['tcamUsagePercent'])
                if nodeInfo[nodeId]['tcamUsagePercent'] >= 80.0:
                    percentText = colored(percentText, 'red', bold=True)
                elif nodeInfo[nodeId]['tcamUsagePercent'] >= 50.0:
                    percentText = colored(percentText, 'magenta')
                logger.info("Node {} pod {} - TCAM usage on {} ({}) with scale profile {} is {} ({}/{})".
                    format(nodeId,
                        nodeInfo[nodeId]['podId'],
                        nodeInfo[nodeId]['name'],
                        nodeInfo[nodeId]['model'],
                        nodeInfo[nodeId]['scaleProfile'],
                        percentText,
                        nodeInfo[nodeId]['tcamUsage'],
                        nodeInfo[nodeId]['tcamCapacity']))
    return nodeInfo

def capacityCheck(node, fabricDescriptor, esgDataFromYaml, noConfig):
    """
    Helper function to check policy Tcam utilization.
    Conversion function can be run in one of two modes based on capacityCheck output
    1. ESG contracts are installed prior to the selector addition.
    This will ensure minimal traffic loss during migration.
    2. ESG selectors are added prior to the contract cloning for ESG.
    This will conserve policy tcam usage during migration. Some traffic loss will be observed.
    """
    logger = logging.getLogger(globalValues['logger'])

    vrfDeployment = {}
    nodeWarnings = []
    nodeCritical = []
    vrfWithWarnings = set()
    vrfWithCritical = set()
    nodeInfo = tcamCapacityCheck(node, showInfo=True)

    for nodeId, data in nodeInfo.items():
        if data['tcamUsagePercent'] >= 80.0:
            nodeCritical.append(nodeId)
        elif data['tcamUsagePercent'] >= 50.0:
            nodeWarnings.append(nodeId)

    # Get VRF to Node deployment
    result = node.methods.ResolveClass('l3Ctx').GET()
    for mo in result:
        nodeId = getNodeIdFromDn(mo.dn)
        if nodeId and nodeId in nodeInfo:
            nodeInfo[nodeId]['vrfCount'] += 1
            ctxPKey = mo.ctxPKey
            if ctxPKey:
                vrfDeployment.setdefault(ctxPKey, set())
                vrfDeployment[ctxPKey].add(nodeId)
                if nodeId in nodeWarnings:
                    vrfWithWarnings.add(ctxPKey)
                if nodeId in nodeCritical:
                    vrfWithCritical.add(ctxPKey)

    if logger.isEnabledFor(logging.DEBUG):
        for ctxPKey in vrfDeployment:
            logger.debug("VRF %s is deployed on nodes: %s",
                ctxPKey, ",".join(sorted(vrfDeployment[ctxPKey], key=int))
        )

    if nodeCritical:
        logger.critical("VRFs deployed on nodes with critical TCAM usage (>=80%): {}".format(', '.join(sorted(vrfWithCritical))))
        logger.critical("Nodes with critical TCAM usage (>=80%): {}".format(', '.join(sorted(nodeCritical, key=int))))
    if nodeWarnings:
        logger.warning("VRFs deployed on nodes with warning TCAM usage (>=50%): {}".format(', '.join(sorted(vrfWithWarnings))))
        logger.warning("Nodes with warning TCAM usage (>=50%): {}".format(', '.join(sorted(nodeWarnings, key=int))))

    # Check that the VRF conversion list does not include VRFs in the vrfWithCritical list.
    numVrfConversionCritical = 0
    numVrfConversionWarning = 0
    for vrfData in esgDataFromYaml['vrfs']:
        if vrfData['vrf'] in vrfWithCritical:
            logger.critical("Cannot migrate EPGs on VRF {} since the VRF is deployed on a node with with critical TCAM usage (>=80%)".format(vrfData['vrf']))
            numVrfConversionCritical += 1
        elif vrfData['vrf'] in vrfWithWarnings:
            numVrfConversionWarning += 1
    if numVrfConversionCritical > 0:
        if noConfig:
            logger.warning("Continue conversion since --noConfig option is used and no config is pushed to APIC.")
            logger.warning("Conversion will run in a non-optimized mode since VRFs are deployed on nodes with high TCAM usage (usage >= 80%).")
        else:
            logger.critical("Aborting conversion. Please free up some TCAM usage or delete the VRF{} from the conversion YAML file."
                            .format("" if numVrfConversionCritical == 1 else "s"))
            sys.exit(1)
    elif numVrfConversionWarning > 0:
        logger.warning("Conversion will run in a non-optimized mode since VRFs are deployed on nodes with warning TCAM usage (50% <= usage < 80%).")
        logger.warning("This will conserve TCAM space but more traffic loss may be observed during migration.")
        logger.warning("If you want to avoid this, please free up some TCAM space on the nodes or delete the VRFs from the conversion YAML file.")
    else:
        logger.info("All VRFs in the conversion YAML file are deployed on nodes with healthy TCAM usage (<50%).")
        logger.info("Conversion will run in an optimized mode, this will ensure minimal traffic loss during migration.")

    fabricDescriptor['nodeInfo'] = nodeInfo
    fabricDescriptor['nodeWarnings'] = nodeWarnings
    fabricDescriptor['nodeCritical'] = nodeCritical
    fabricDescriptor['vrfWithWarnings'] = vrfWithWarnings
    fabricDescriptor['vrfWithCritical'] = vrfWithCritical
    fabricDescriptor['numVrfConversionWarning'] = numVrfConversionWarning
    fabricDescriptor['numVrfConversionCritical'] = numVrfConversionCritical

def preConversionHealthCheck(node, fabricDescriptor, esgToVrfMap):
    """
    Helper function to check pre-existing faults prior to running conversion.
    In case of catastrophic faults, False is returned, signaling conversion to abort.
    """
    logger = logging.getLogger(globalValues['logger'])

    spinner.text = "Checking Global PC Tag capacity"

    # Global PC Tag check
    globalPcTagCount = 0
    # Formula: total fvEPg with pcTag < 16384 (16k) - fvEPgSelector with no configIssues
    params = {'query-target-filter': 'and(lt(fvEPg.pcTag,"16384"),ne(fvEPg.pcTag,"any"))'}
    globalPcTagCount += len(node.methods.ResolveClass('fvEPg').GET(**params))

    params = {'query-target-filter': 'and(eq(fvEPgSelector.configIssues,%22%22))'}
    globalPcTagCount -= len(node.methods.ResolveClass('fvEPgSelector').GET(**params))

    logger.info("Global PC Tag count in the fabric is {}".format(globalPcTagCount))
    fabricDescriptor['globalPcTagCount'] = globalPcTagCount

    numEsgToConfigure = len(esgToVrfMap)
    logger.info("The number of ESGs to configure is {}".format(numEsgToConfigure))
    if globalPcTagCount + numEsgToConfigure > 10000:
        logger.critical("Not enough Global PC Tags available in the fabric to configure all ESGs")
        logger.critical("Aborting conversion. Please free up some PC Tags or reduce the number of ESGs to configure")
        return False

    return True

def configpushPending(node):
    """
    Helper function to check if there are any pending config pushes.
    Returns number of pending config pushes.
    """
    params = {'query-target-filter': 'eq(configpushTxCont.failedUpdate,"no")'}
    pendingJobs = node.methods.ResolveClass('configpushTxCont').GET(**params)
    if pendingJobs:
        return len(pendingJobs)
    return 0

def listSnapshotCfgJobs(node, snapshotName, type='configexp'):
    """
    Helper function to walk over all configJobs matching input snapshot name.
    Returns completed config jobs, both successful and unsuccessful.
    Returns (snapshotFileName, Status of Job, Oper Details)
    Pending config jobs are skipped and not returned.
    """
    dn = f"uni/backupst/jobs-[uni/fabric/{type}-{snapshotName}]"
    jobCont = node.mit.FromDn(dn).GET(**{'rsp-subtree': 'full'})
    jobSet = set()

    # Job not yet created
    if not jobCont or len(jobCont) == 0:
        return jobSet

    jobContMo = jobCont[0]

    for jobMo in jobContMo.Children:
        if jobMo.operSt not in {'pending', 'running'}:
            jobSet.add((jobMo.fileName, jobMo.operSt, jobMo.details))

    return jobSet

def createCfgSnapshot(node, snapshotName):
    """
    Creates snapshot of configuration.
    Compares configJobs prior to and after creation of new config snapshot.
    Returns status of new config Job once completed.
    """
    logger = logging.getLogger(globalValues['logger'])
    exportCfg = node.mit.polUni()
    preExportConfigJobs = listSnapshotCfgJobs(node, snapshotName)
    exportCfg.fabricInst().configExportP(
                            name=snapshotName,
                            snapshot="yes",
                            adminSt="triggered",
                            descr="Snapshot taken by ESG Migration Assistant tool")
    logger.info("Creating config snapshot job")
    rc = logAndPostHandler(exportCfg, node, outputFile = None, noConfig = False)

    if rc == ReturnCode.SUCCESS:
        logger.info("Snapshot creation job posted successfully")
    elif rc == ReturnCode.USERSKIPPED:
        logger.info("Snapshot creation skipped by user")
        return rc, None
    else:
        logger.error("Snapshot creation failed")
        return rc, None

    def conditionFn():
        postExportConfigJobs = listSnapshotCfgJobs(node, snapshotName)
        exportConfigJobDelta = postExportConfigJobs - preExportConfigJobs
        if not exportConfigJobDelta:
            return None  # not ready yet
        return exportConfigJobDelta.pop()

    result = waitForCondition(
        conditionFn = conditionFn,
        description = f"snapshot {snapshotName} creation (it can take a few minutes)",
        timeout=360,
        ih=InputHandler(),
        checkInterval = 1,
    )

    if result:
        configFile, operSt, operDetails = result
        if operSt != "success":
            logger.error(f"Snapshot creation failed with operSt {operSt}. Reason: {operDetails}")
            return ReturnCode.CONFIG_FAILED, None
        logger.info(f"Snapshot successfully created. Filename is {configFile}")
        return ReturnCode.SUCCESS, configFile

    return ReturnCode.CONFIG_FAILED, None

def restoreCfgSnapshot(node, fileName):
    """
    Creates rollback configuration.
    Compares configJobs prior to and after creation of new config rollback.
    Returns status of new config Job once completed.
    """
    logger = logging.getLogger(globalValues['logger'])
    inportCfg = node.mit.polUni()
    preImportConfigJobs = listSnapshotCfgJobs(node, "default", type='configimp')
    inportCfg.fabricInst().configImportP(
                            name="default",
                            snapshot="true",
                            adminSt="triggered",
                            fileName=fileName,
                            importType="replace",
                            importMode="atomic")
    logger.info("Creating Rollback config job using snapshot file {}".format(fileName))
    rc = logAndPostHandler(inportCfg, node, outputFile = None, noConfig = False)

    if rc == ReturnCode.SUCCESS:
        logger.info("Rollback job posted successfully")
    elif rc == ReturnCode.USERSKIPPED:
        logger.info("Rollback job skipped by user")
        return rc, None
    else:
        logger.error("Rollback job failed")
        return rc, None

    def conditionFn():
        postImportConfigJobs = listSnapshotCfgJobs(node, "default", type='configimp')
        importConfigJobDelta = postImportConfigJobs - preImportConfigJobs
        if not importConfigJobDelta:
            return None  # not ready yet
        return importConfigJobDelta.pop()
    result = waitForCondition(
        conditionFn = conditionFn,
        description = f"Rollback job creation",
        timeout=60,
        ih=InputHandler(),
        checkInterval = 1,
    )

    if result:
        configFile, operSt, operDetails = result
        if operSt != "success":
            logger.error(f"Rollback failed with operSt {operSt}. Reason: {operDetails}")
            return ReturnCode.CONFIG_FAILED, None
        logger.info(f"Rollback completed from snapshot {configFile}")
        return ReturnCode.SUCCESS, configFile

    return ReturnCode.CONFIG_FAILED, None

def parseAciVersion(version):
    """
    Helper function to parse ACI version strings like
    6.1(4) - CCO version numbering
    6.1(3a) - CCO version numbering
    6.1(3.181) - Internal Dev image numbering
    6.1(1.82a) - Internal Dev image numbering
    Returns (major, minor, patch)
    Patch is incremented by 1 for Dev images for compare compatibility with CCO number
    """
    m = re.match(r"(\d+)\.(\d+)\((\d+)(?:\.(\d+))?([a-z]*)\)", version)
    if not m:
        raise ValueError(f"Invalid ACI version format: {version}")
    major, minor, patch, build, suffix = m.groups()

    major = int(major)
    minor = int(minor)
    patch = int(patch)
    build = int(build) if build else 0
    suffix = suffix or ""

    if build != 0:
        patch += 1

    return (major, minor, patch)

def checkApicVersionCompatibility(node, minV=None, maxV=None):
    """
    Checks if all active APICs in the cluster are within input min and max version range.
    Returns True if version is in allowed range.
    """
    logger = logging.getLogger(globalValues['logger'])

    if not minV and not maxV:
        return True

    minVParsed = parseAciVersion(minV) if minV else None
    maxVParsed = parseAciVersion(maxV) if maxV else None
    versionCheckPassed = True
    apicsInfo = []
    for apic in node.methods.ResolveClass('firmwareCtrlrRunning').GET():
        apicsInfo.append({'id': getNodeIdFromDn(apic.dn), 'version': apic.version, 'parseVersion': parseAciVersion(apic.version)})
    for apic in sorted(apicsInfo, key=lambda x: x['id']):
        logger.info(f"APIC {apic['id']} is running version {apic['version']}")

        if minVParsed:
            if apic['parseVersion'] < minVParsed:
                logger.warning(f"APIC {apic['id']} below min version {minV}")
                versionCheckPassed = False

        if maxVParsed:
            if apic['parseVersion'] > maxVParsed:
                logger.warning(f"APIC {apic['id']} above max version {maxV}")
                versionCheckPassed = False

    if versionCheckPassed:
        logger.info("Version check: passed")
    return versionCheckPassed

def generateConversionConfig(node, esgDataForXml, perVrfPreExistingEsgMap, outputFile, noConfig, tcamOptimizedMode, contractConversionDescriptor, configStrategy):
    """
    Conversion function to convert input Yaml file to ACI config.
    If noConfig flag is True, generated config will be output to file and logged.
    If noConfig flag is False, in addition to above, POST is done to apic.
    Phase 1 - Create ESG, add VRF mapping for ESG. Clone EPG contracts, but do not bind to ESG yet.
              For each VRF, add leak internal subnets and external prefixes.
    Phase 2 - If tcamOptimizedMode is True, add EPG & External EPG selectors
              If tcamOptimizedMode is False, add contract mappings to ESG
    Phase 3 - If tcamOptimizedMode if True, add contract mappings to ESG
              If tcamOptimizedMode if False, add EPG & External EPG selectors
    """
    logger = logging.getLogger(globalValues['logger'])
    applyConfig = not noConfig
    migrationAnnotateKey = '__' + TOOL_NAME_STR
    migrationAnnotateVal = 'Cleanup required after migration'
    ndContractAnnotateKey = '__' + ND_NAME_STR + ':contract'
    vrfToSeg = {} # Map of VRF to Segment ID
    esgToPcTag = {} # Map of ESG to PC Tag
    preExistingEsgNewContractMap = {}

    steps = {'vrfs': {'current': 1, 'total': len(esgDataForXml['vrfs'])},
             'contractClones': {'current': 1, 'total': len(esgDataForXml['contractClones'])}}

    try:
        with open(outputFile, "w") as f:
            pass
    except Exception as e:
        logger.error("Failed to open file {} due to {}".format(outputFile, e))
        sys.exit(1)

    def logAndPost(outputElem, step = "", allowYesToAll = True):
        return logAndPostHandler(outputElem, node, outputFile = outputFile, noConfig = noConfig, step = step, allowYesToAll = allowYesToAll)

    def createEsgAndLeakRouteForVrf(vrfData):
        vrfDn = vrfData['vrf']
        esgList = vrfData.get('esgs', [])
        leakInternalSubnets = vrfData.get('leakInternalSubnets', [])
        leakExternalPrefixes = vrfData.get('leakExternalPrefixes', [])
        vrfName = getNameFromDn(vrfDn)
        vrfTennantName = getTenantFromDn(vrfDn)

        perVrfConfig = node.mit.polUni()
        perVrfConfig.fvTenant(vrfTennantName).fvCtx(vrfName)
        mode = "immediate"

        for esg in esgList:
            esgName = esg['name']
            appProfileName = esg['applicationProfile']
            esgPcEnfPref = esg.get('pcEnfPref', 'unenforced')
            esgPrefGrMemb = esg.get('prefGrMemb', 'exclude')
            # Get tenant from first EPG if available since ESG and EPGs must be in the same tenant,
            # else place the ESG in the VRF tenant
            tenantName = getTenantFromDn(esg['epgs'][0]) if esg['epgs'] else getTenantFromDn(vrf['vrf'])

            perVrfConfig.fvTenant(tenantName).fvAp(appProfileName)\
                .fvESg(name = esgName, instrImedcy=mode, pcEnfPref = esgPcEnfPref, prefGrMemb = esgPrefGrMemb)\
                .fvRsScope(tnFvCtxName=vrfName)

        # Create internal subnet leakroutes
        for leakInternalSubnet in leakInternalSubnets:
            for leakVrf in leakInternalSubnet['leakTo']:
                perVrfConfig.fvTenant(vrfTennantName).fvCtx(vrfName).leakRoutes()\
                    .leakInternalSubnet(ip = leakInternalSubnet['ip'], scope = leakInternalSubnet['scope'])\
                    .leakTo(ctxName=getNameFromDn(leakVrf), tenantName=getTenantFromDn(leakVrf), scope="inherit")

        # Create external prefix leakroutes
        for leakExternalPrefix in leakExternalPrefixes:
            extPrefMo = perVrfConfig.fvTenant(vrfTennantName).fvCtx(vrfName).leakRoutes()\
                                    .leakExternalPrefix(ip = leakExternalPrefix['ip'])
            if 'le' in leakExternalPrefix:
                extPrefMo.le = str(leakExternalPrefix['le'])
            if 'ge' in leakExternalPrefix:
                extPrefMo.ge = str(leakExternalPrefix['ge'])
            for leakVrf in leakExternalPrefix['leakTo']:
                extPrefMo.leakTo(ctxName=getNameFromDn(leakVrf), tenantName=getTenantFromDn(leakVrf))

        logger.info("Generated XML config for VRF {} in Tenant {} with new ESGs and route leaks. No contracts and selectors attached yet".format(colored(vrfName), colored(vrfTennantName)))
        vrfRc = logAndPost(perVrfConfig, step = steps['vrfs'])
        if applyConfig and vrfRc == ReturnCode.SUCCESS:
            vrfRc |= fillVrfDictionarySeg(vrfDn)
            for esg in esgList:
                vrfRc |= fillEsgDictionaryPcTag(esg, vrfDn)
        return vrfRc

    def createEsgClonedContracts():
        """
        Nested helper function
        Clones contracts from EPG to ESG.
        """

        def appendContract(contract):
            tenantName = getTenantFromDn(contract.Dn)
            if tenantName not in perTenantConfigToPost:
                perTenantConfigToPost[tenantName] = node.mit.polUni()
                perTenantConfigToPost[tenantName].fvTenant(tenantName)
            uniJson = json.loads(perTenantConfigToPost[tenantName].Json)
            for child in uniJson["polUni"]["children"]:
                tenant = child.get("fvTenant")
                tenant.setdefault("children", [])
                tenant["children"].append(json.loads(contract.Json))
                perTenantConfigToPost[tenantName].Json = json.dumps(uniJson)

        rc = ReturnCode.SUCCESS
        perTenantConfigToPost = {}
        for contact in contractConversionDescriptor.getAll():
            oldContractDn = contact['fromDn']
            newContractMo = contact['mo']
            ndContract = contact['ndContract']

            if not newContractMo:
                logger.error("Missing Cloned Contract for source DN {}".format(oldContractDn))
                rc |= ReturnCode.GETFAILED
                continue

            if ndContract:
                newContractMo.tagAnnotation(key = ndContractAnnotateKey, value = oldContractDn)

            if not inputHandler.isYesToAll() and configStrategy == ConfigStrategy.INTERACTIVE:
                logger.info("Cloning contract subtree {}".format(colored(oldContractDn)))
                rc |= logAndPost(newContractMo, step = steps['contractClones'])
            else:
                appendContract(newContractMo)

        if inputHandler.isYesToAll() or configStrategy == ConfigStrategy.VRF:
            step = {'current': 1, 'total': len(perTenantConfigToPost)}
            for _, config in sorted(perTenantConfigToPost.items()):
                rc |= logAndPost(config, step = step)

        return rc

    def createEsgContractRelations():
        """
        Nested helper function
        Create fvRsProv, fvRsCons and fvRsIntraEpg relationships from ESG to cloned contracts.
        """
        rc = ReturnCode.SUCCESS

        # Create contract relations for ESGs defined in YAML file
        esgConfigs = {}
        for vrfData in sorted(esgDataForXml['vrfs'], key=lambda x: x['vrf']):
            vrfDn = vrfData['vrf']
            esgConfigs.setdefault(vrfDn, {'perEsgConfigs': [], 'vrf': node.mit.polUni()})
            for esg in sorted(vrfData.get('esgs', []), key=lambda x: x['name']):
                esgName = esg['name']
                apName = esg['applicationProfile']
                tenantName = getTenantFromDn(esg['epgs'][0]) if esg['epgs'] else getTenantFromDn(vrfDn)
                esgDn = f"uni/tn-{tenantName}/ap-{apName}/esg-{esgName}"

                perEsgConfig = node.mit.polUni()
                for contract in esg.get('prov', []):
                    for newContract in contractConversionDescriptor.getByProvider(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName) .fvESg(name=esgName)\
                                .fvRsProv(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                for contract in esg.get('cons', []):
                    for newContract in contractConversionDescriptor.getByConsumer(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsCons(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                for contract in esg.get('intraepg', []):
                    for newContract in contractConversionDescriptor.getByIntraEPG(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsIntraEpg(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                for consIf in esg.get('consif', []):
                    for newContract in contractConversionDescriptor.getByConsumerIf(consIf, esgDn):
                        contractIfName = getNameFromDn(newContract['newContractDn'])
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            # Create Contract Interface
                            config.fvTenant(tenantName).vzCPIf(contractIfName).vzRsIf(tDn=newContract['newExportedFromDn'])
                            # Attach Consumed Contract Interface to ESG
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsConsIf(tnVzCPIfName=contractIfName)

                numContracts = len(list(perEsgConfig.Children))
                if numContracts > 0:
                    logText = "Attaching {} contract{} to ESG {} in VRF {}".format(numContracts, "" if numContracts == 1 else "s", colored(esgName), colored(vrfDn))
                    esgConfigs[vrfDn]['perEsgConfigs'].append({'config': perEsgConfig, 'logText': logText})

        # Create contract relations for ESGs that are not defined in YAML file (pre-existing ESGs in scope of conversion)
        for vrfDn in preExistingEsgNewContractMap:
            esgConfigs.setdefault(vrfDn, {'perEsgConfigs': [], 'vrf': node.mit.polUni()})
            for esgDn in preExistingEsgNewContractMap[vrfDn]:
                esgName = getNameFromDn(esgDn)
                apName = getAppProfileFromDn(esgDn)
                tenantName = getTenantFromDn(esgDn)
                perEsgConfig = node.mit.polUni()
                for contract in preExistingEsgNewContractMap[vrfDn][esgDn].get('prov', []):
                    for newContract in contractConversionDescriptor.getByProvider(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName) .fvESg(name=esgName)\
                                .fvRsProv(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                            tagAnnConfig = config.fvTenant(tenantName).fvAp(apName) .fvESg(name=esgName)\
                                .fvRsProv(tnVzBrCPName=getNameFromDn(contract))\
                                .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                            tagAnnConfig.xmlcomment = "tagAnnotation used to mark ESG fvRsProv for ESG migration cleanup"
                for contract in preExistingEsgNewContractMap[vrfDn][esgDn].get('cons', []):
                    for newContract in contractConversionDescriptor.getByConsumer(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsCons(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                            tagAnnConfig = config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsCons(tnVzBrCPName=getNameFromDn(contract))\
                                .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                            tagAnnConfig.xmlcomment = "tagAnnotation used to mark ESG fvRsCons for ESG migration cleanup"
                for contract in preExistingEsgNewContractMap[vrfDn][esgDn].get('consif', []):
                    for newContract in contractConversionDescriptor.getByConsumerIf(contract, esgDn):
                        contractIfName = getNameFromDn(newContract['newContractDn'])
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            # Create Contract Interface
                            config.fvTenant(tenantName).vzCPIf(contractIfName).vzRsIf(tDn=newContract['newExportedFromDn'])
                            tagAnnConfig = config.fvTenant(tenantName).vzCPIf(contractIfName).vzRsIf(tDn=contract)\
                                .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                            tagAnnConfig.xmlcomment = "tagAnnotation used to mark ESG Contract Interface for ESG migration cleanup"
                            # Attach Consumed Contract Interface to ESG
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsConsIf(tnVzCPIfName=contractIfName)
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)

                for contract in preExistingEsgNewContractMap[vrfDn][esgDn].get('epgprov', []):
                    for newContract in contractConversionDescriptor.getByProvider(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName) .fvESg(name=esgName)\
                                .fvRsProv(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                for contract in preExistingEsgNewContractMap[vrfDn][esgDn].get('epgcons', []):
                    for newContract in contractConversionDescriptor.getByConsumer(contract, esgDn):
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsCons(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                for contract in preExistingEsgNewContractMap[vrfDn][esgDn].get('epgconsif', []):
                    for newContract in contractConversionDescriptor.getByConsumerIf(contract, esgDn):
                        contractIfName = getNameFromDn(newContract['newContractDn'])
                        for config in [perEsgConfig, esgConfigs[vrfDn]['vrf']]:
                            # Create Contract Interface
                            config.fvTenant(tenantName).vzCPIf(contractIfName).vzRsIf(tDn=newContract['newExportedFromDn'])
                            # Attach Consumed Contract Interface to ESG
                            config.fvTenant(tenantName).fvAp(apName).fvESg(name=esgName)\
                                .fvRsConsIf(tnVzCPIfName=contractIfName)

                numContracts = len(list(perEsgConfig.Children))
                if numContracts > 0:
                    logText = "Attaching {} contract{} to ESG {} in VRF {}".format(numContracts, "" if numContracts == 1 else "s", colored(esgName), colored(vrfDn))
                    esgConfigs[vrfDn]['perEsgConfigs'].append({'config': perEsgConfig, 'logText': logText})

        # Post contract relations for ESGs. If in interactive mode, post per ESG config one by one.
        # If in VRF or all mode, post per VRF config with all ESGs together.
        step = {'current': 1, 'total': 0}
        for vrfDn in esgConfigs:
            if len(esgConfigs[vrfDn]['perEsgConfigs']) > 0:
                step['total'] += len(esgConfigs[vrfDn]['perEsgConfigs']) if configStrategy == ConfigStrategy.INTERACTIVE else 1

        for vrfDn in esgConfigs:
            somethingToConfigure = len(esgConfigs[vrfDn]['perEsgConfigs']) > 0
            while somethingToConfigure:
                if not inputHandler.isYesToAll() and configStrategy == ConfigStrategy.INTERACTIVE:
                    perEsgConfig = esgConfigs[vrfDn]['perEsgConfigs'].pop(0)
                    logger.info(perEsgConfig['logText'])
                    rc |= logAndPost(perEsgConfig['config'], step = step)
                    somethingToConfigure = len(esgConfigs[vrfDn]['perEsgConfigs']) > 0
                else:
                    for perEsgConfig in esgConfigs[vrfDn]['perEsgConfigs']:
                        logger.info(perEsgConfig['logText'])
                    rc |= logAndPost(esgConfigs[vrfDn]['vrf'], step = step)
                    somethingToConfigure = False

        return rc

    def createEsgSelectors():
        """
        Nested helper function
        Add EPG and External EPG selectors to input ESG, one per iteration
        """
        rc = ReturnCode.SUCCESS

        pcTag = 0
        epg = ""
        esgToNodeId = set()
        def epgSelConditionFn():
            allEpgUpdated = True
            params = {'query-target-filter': 'eq(vlanCktEp.epgDn,"{}")'.format(epg)}
            concreteResult = node.methods.ResolveClass('vlanCktEp').GET(**params)
            if not concreteResult:
                logger.info("EPG {} updated with PC Tag {}, but EPG not present on any node".format(epg, pcTag))
                return True  # Nothing to wait for — consider it "done"

            for mo in concreteResult:
                if int(mo.pcTag) != pcTag:
                    logger.info("EPG {} on node {} has not been yet updated with PC Tag {} (current {})"\
                                .format(mo.epgDn, getNodeIdFromDn(mo.dn), pcTag, mo.pcTag))
                    allEpgUpdated = False
                else:
                    logger.info("EPG {} on node {} has been updated with PC Tag {}".format(mo.epgDn, getNodeIdFromDn(mo.dn), pcTag))
                    esgToNodeId.add(getNodeIdFromDn(mo.dn))
            return allEpgUpdated

        def epgSelOnSuccess(_):
            # Need to clear the EP table for the EPGs assigned to this ESG
            try:
                for nodeId in esgToNodeId:
                    logger.info("Clearing EP table for VRF {} on node {}".format(vrfDn, nodeId))
                spinner.text = "Clearing EP table"
                for nodeId in esgToNodeId:
                    clearCmd = RemoteCommandMo(node, nodeId)
                    clearCmd.moCommand(id="1", cmdtype="vsh", cmd="clear system internal epm endpoint vrf {}:{} remote"
                                    .format(getTenantFromDn(vrfDn), getNameFromDn(vrfDn)))
                    clearCmd.POST()
            except Exception as e:
                logger.error(f"Error clearing EP table: {e}")
            spinner.stop()
            print()

        def extSubSelConditionFn():
            allEpgUpdated = True
            if ipaddress.ip_network(subnet['ip'], strict=False) == ipaddress.ip_network('0.0.0.0/0') or \
                ipaddress.ip_network(subnet['ip'], strict=False) == ipaddress.ip_network('::/0'):
                # These prefixes are split and create two actrlPfxEntry objects, but not on all conditions
                # Keep the logic simple and skip waiting for these prefixes
                return True
            params = {'query-target-filter': 'eq(actrlPfxEntry.addr,"{}")'.format(subnet['ip'])}
            concreteResult = node.methods.ResolveClass('actrlPfxEntry').GET(**params)
            for mo in concreteResult:
                if str(seg) not in mo.dn:
                    continue
                if int(mo.pcTag) != pcTag:
                    logger.info("actrlPfxEntry {} on node {} has not been yet updated with PC Tag {} (current {})"\
                                .format(mo.dn, getNodeIdFromDn(mo.dn), pcTag, mo.pcTag))
                    allEpgUpdated = False
                else:
                    logger.info("actrlPfxEntry {} on node {} has been updated with PC Tag {}".format(mo.dn, getNodeIdFromDn(mo.dn), pcTag))
            return allEpgUpdated

        def extSubSelOnSuccess(_):
            print()

        esgConfigs = {}
        instPSelectorsConfigPatch = node.mit.polUni()
        instPSelectorsDeletePatch = node.mit.polUni()
        for vrfData in sorted(esgDataForXml['vrfs'], key=lambda x: x['vrf']):
            vrfDn = vrfData['vrf']
            esgConfigs.setdefault(vrfDn, {'perEsgConfigs': [], 'vrf': node.mit.polUni()})
            seg = vrfToSeg.get(vrfDn, 0)

            # Collect the per EPG and External Subnet selector configs first
            for esg in sorted(vrfData.get('esgs', []), key=lambda x: x['name']):
                esgName = esg['name']
                apName = esg['applicationProfile']
                tenantName = getTenantFromDn(esg['epgs'][0]) if esg['epgs'] else getTenantFromDn(vrfDn)

                esgDn = f"uni/tn-{tenantName}/ap-{apName}/esg-{esgName}"
                epgs = esg.get('epgs', [])
                externalSubnets = esg.get('externalSubnets', [])

                if epgs and externalSubnets:
                    logger.info("ESG {} has both EPGs and External Subnets defined. Will create separate ESG selectors for EPGs and External Subnets".format(colored(esgName)))
                    for epg in epgs:
                        instPSelectorsConfigPatch.fvTenant(tenantName).fvAp(apName)\
                            .fvESg(name=esgName).fvEPgSelector(matchEpgDn=epg)\
                            .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        instPSelectorsDeletePatch.fvTenant(tenantName).fvAp(apName)\
                            .fvESg(name=esgName).fvEPgSelector(matchEpgDn=epg, status="deleted")

                for epg in sorted(epgs):
                    if not isValidDn(epg, ['uni', 'tn-', 'ap-', 'epg-']):
                        continue
                    perEpgSelectorConfig = node.mit.polUni()
                    for config in [perEpgSelectorConfig, esgConfigs[vrfDn]['vrf']]:
                        tagAnnConfig = config.fvTenant(tenantName).fvAp(apName)\
                                    .fvESg(name=esgName).fvEPgSelector(matchEpgDn=epg)\
                                    .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark EPG selectors for ESG migration cleanup"
                    logText = "On ESG {} assign EPG {} via EPG selector".format(colored(esgName), colored(epg))
                    esgConfigs[vrfDn]['perEsgConfigs'].append({'config': perEpgSelectorConfig,
                                      'logText': logText,
                                      'pcTag': esgToPcTag.get(esgDn, 0),
                                      'epg': epg,
                                      'externalSubnets': []})

                if externalSubnets:
                    perExtSubSelectorConfig = node.mit.polUni()
                    for subnet in externalSubnets:
                        for config in [perExtSubSelectorConfig, esgConfigs[vrfDn]['vrf']]:
                            tagAnnConfig = config.fvTenant(tenantName).fvAp(apName)\
                                        .fvESg(name=esgName)\
                                        .fvExternalSubnetSelector(ip=subnet['ip'], shared="yes" if subnet['scope'] == 'public' else "no")\
                                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                            tagAnnConfig.xmlcomment = "tagAnnotation used to mark External Subnet selectors for ESG migration cleanup"

                    logText = "On ESG {} assign External EPG Subnet{} via External Subnet selector".format(colored(esgName), 's' if len(externalSubnets) > 1 else '')
                    esgConfigs[vrfDn]['perEsgConfigs'].append({'config': perExtSubSelectorConfig,
                                      'logText': logText,
                                      'pcTag': esgToPcTag.get(esgDn, 0),
                                      'epg': None,
                                      'externalSubnets': externalSubnets})

        # Post Temporary External EPG selector config to minimize the traffic impact
        if len(list(instPSelectorsConfigPatch.Children)):
            instPSelectorsConfigPatch.POST()

        # Post EPG and External Subnet selector configs for ESGs. If in interactive mode,
        # post per ESG config one by one.
        # If in VRF or all mode, post per VRF config with all ESGs together.
        step = {'current': 1, 'total': 0}
        for vrfDn in esgConfigs:
            if len(esgConfigs[vrfDn]['perEsgConfigs']) > 0:
                step['total'] += len(esgConfigs[vrfDn]['perEsgConfigs']) if configStrategy == ConfigStrategy.INTERACTIVE else 1


        for vrfDn in esgConfigs:
            somethingToConfigure = len(esgConfigs[vrfDn]['perEsgConfigs']) > 0
            while somethingToConfigure:
                if not inputHandler.isYesToAll() and configStrategy == ConfigStrategy.INTERACTIVE:
                    perEpgConfig = esgConfigs[vrfDn]['perEsgConfigs'].pop(0)
                    pcTag = perEpgConfig['pcTag']
                    epg = perEpgConfig['epg']
                    externalSubnets = perEpgConfig['externalSubnets']
                    logger.info(perEpgConfig['logText'])
                    selRc = logAndPost(perEpgConfig['config'], step = step)

                    if epg:
                        if applyConfig and pcTag and selRc == ReturnCode.SUCCESS:
                            esgToNodeId = set()
                            result = waitForCondition(
                                conditionFn = epgSelConditionFn,
                                description = "EPG {} to be updated with PC Tag {} on all nodes".format(epg, pcTag),
                                timeout = CONFIG_TIMEOUT,
                                ih = InputHandler(),
                                onSuccess = epgSelOnSuccess)
                            if not result:
                                selRc |= ReturnCode.CONFIG_TIMEOUT
                    else:
                        if applyConfig and pcTag and seg and selRc == ReturnCode.SUCCESS:
                            for subnet in externalSubnets:
                                result = waitForCondition(
                                    conditionFn = extSubSelConditionFn,
                                    description = "actrlPfxEntry for {} to be updated with PC Tag {} on all nodes".format(subnet['ip'], pcTag),
                                    timeout = CONFIG_TIMEOUT,
                                    ih = InputHandler(),
                                    onSuccess = extSubSelOnSuccess)
                                if not result:
                                    selRc |= ReturnCode.CONFIG_TIMEOUT
                    somethingToConfigure = len(esgConfigs[vrfDn]['perEsgConfigs']) > 0
                    rc |= selRc
                else:
                    for perEpgConfig in esgConfigs[vrfDn]['perEsgConfigs']:
                        logger.info(perEpgConfig['logText'])
                    allRc = logAndPost(esgConfigs[vrfDn]['vrf'], step = step)
                    if applyConfig and allRc == ReturnCode.SUCCESS:
                        esgToNodeId = set()
                        for perEpgConfig in esgConfigs[vrfDn]['perEsgConfigs']:
                            pcTag = perEpgConfig['pcTag']
                            epg = perEpgConfig['epg']
                            externalSubnets = perEpgConfig['externalSubnets']
                            if epg:
                                if pcTag:
                                    result = waitForCondition(
                                        conditionFn = epgSelConditionFn,
                                        description = "EPG {} to be updated with PC Tag {} on all nodes".format(epg, pcTag),
                                        timeout = CONFIG_TIMEOUT,
                                        ih = InputHandler())
                                    if not result:
                                        allRc |= ReturnCode.CONFIG_TIMEOUT
                            else:
                                if pcTag and seg:
                                    for subnet in externalSubnets:
                                        result = waitForCondition(
                                            conditionFn = extSubSelConditionFn,
                                            description = "actrlPfxEntry for {} to be updated with PC Tag {} on all nodes".format(subnet['ip'], pcTag),
                                            timeout = CONFIG_TIMEOUT,
                                            ih = InputHandler())
                                        if not result:
                                            allRc |= ReturnCode.CONFIG_TIMEOUT
                        epgSelOnSuccess(None)
                    somethingToConfigure = False # Exit while loop since all processed at once
                    rc |= allRc

        # Post Delete of External EPG selector config used to minimize the traffic impact
        if len(list(instPSelectorsDeletePatch.Children)):
            instPSelectorsDeletePatch.POST()
        return rc

    def createEsgPbrCtx():
        """
        Nested helper function
        Clone PBR Logical Device Context Subtree and set contract attributes to newly cloned ESG contract
        """
        rc = ReturnCode.SUCCESS
        configToPost = []
        vnsLDevCtxMos = node.methods.ResolveClass('vnsLDevCtx').GET()
        for vnsLDevCtxMo in vnsLDevCtxMos:
            pbrCtxTenant = getTenantFromDn(vnsLDevCtxMo.dn)
            pbrCtrctName = vnsLDevCtxMo.ctrctNameOrLbl
            graphNameOrLbl = vnsLDevCtxMo.graphNameOrLbl
            nodeNameOrLbl = vnsLDevCtxMo.nodeNameOrLbl
            matchCtrctDn = f"uni/tn-{pbrCtxTenant}/brc-{pbrCtrctName}"
            for newContract in contractConversionDescriptor.getByAny(matchCtrctDn):
                esgContractDn = newContract['newContractDn']
                esgContractName = getNameFromDn(esgContractDn)
                targetDn = f"uni/tn-{pbrCtxTenant}/ldevCtx-c-{esgContractName}-g-{graphNameOrLbl}-n-{nodeNameOrLbl}"
                overrideProps = {"ctrctNameOrLbl": esgContractName}
                newPbrCtxSubtree = cloneNodeSubtree(node, vnsLDevCtxMo.dn, targetDn, overrideProps)
                if not newPbrCtxSubtree:
                    logger.error("Could not clone {} to {}".format(vnsLDevCtxMo.dn, targetDn))
                    continue
                configToPost.append((vnsLDevCtxMo.dn, newPbrCtxSubtree))
        step = {'current': 1, 'total': len(configToPost)}
        for dn, config in configToPost:
            logger.info("Posting cloned PBR Logical Device Context subtree {}".format(colored(dn)))
            rc |= logAndPost(config, step = step)
        return rc

    def calculatePreExistingEsgContractRelations():
        for vrf in perVrfPreExistingEsgMap:
            for esgDn in perVrfPreExistingEsgMap[vrf]:
                sourceSubtree = node.mit.FromDn(esgDn).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
                if not sourceSubtree or len(sourceSubtree) == 0:
                    logger.error(f"Unable to retreive information related to pre-existing ESG {esgDn}")
                    continue
                esgMo = sourceSubtree[0]
                if esgMo.shutdown == "yes":
                    logger.info(f"Pre-existing ESG {esgDn} is shutdown, skipping contract relation extraction")
                    continue
                for child in esgMo.Children:
                    if child.ClassName == "fvRsProv":
                        contractDn = child.tDn
                        if contractDn:
                            if contractConversionDescriptor.getByProvider(contractDn, esgMo.dn):
                                preExistingEsgNewContractMap.setdefault(vrf, {})\
                                    .setdefault(esgDn, {}).setdefault('prov', set()).add(contractDn)
                    elif child.ClassName == "fvRsCons":
                        contractDn = child.tDn
                        if contractDn:
                            if contractConversionDescriptor.getByConsumer(contractDn, esgMo.dn):
                                preExistingEsgNewContractMap.setdefault(vrf, {})\
                                    .setdefault(esgDn, {}).setdefault('cons', set()).add(contractDn)
                    elif child.ClassName == "fvRsConsIf":
                        contractIfDn = child.tDn
                        if contractIfDn:
                            if contractConversionDescriptor.getByConsumerIf(contractIfDn, esgMo.dn):
                                preExistingEsgNewContractMap.setdefault(vrf, {})\
                                    .setdefault(esgDn, {}).setdefault('consif', set()).add(contractIfDn)

                    elif child.ClassName == "fvEPgSelector":
                        epgSourceSubtree = node.mit.FromDn(child.matchEpgDn).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
                        if not epgSourceSubtree or len(epgSourceSubtree) == 0:
                            logger.error(f"Unable to retreive information related to pre-existing ESG {esgDn}")
                            continue
                        epgMo = epgSourceSubtree[0]
                        for child in epgMo.Children:
                            if child.ClassName == "fvRsProv":
                                contractDn = child.tDn
                                if contractDn:
                                    if contractConversionDescriptor.getByProvider(contractDn, epgMo.dn):
                                        preExistingEsgNewContractMap.setdefault(vrf, {})\
                                            .setdefault(esgDn, {}).setdefault('epgprov', set()).add(contractDn)
                            elif child.ClassName == "fvRsCons":
                                contractDn = child.tDn
                                if contractDn:
                                    if contractConversionDescriptor.getByConsumer(contractDn, epgMo.dn):
                                        preExistingEsgNewContractMap.setdefault(vrf, {})\
                                            .setdefault(esgDn, {}).setdefault('epgcons', set()).add(contractDn)
                            elif child.ClassName == "fvRsConsIf":
                                contractIfDn = child.tDn
                                if contractIfDn:
                                    if contractConversionDescriptor.getByConsumerIf(contractIfDn, epgMo.dn):
                                        preExistingEsgNewContractMap.setdefault(vrf, {})\
                                            .setdefault(esgDn, {}).setdefault('epgconsif', set()).add(contractIfDn)

    def createEsgInbContractRelations():
        """
        Nested helper function
        Connect mgmtInB objects with cloned ESG contracts
        """
        rc = ReturnCode.SUCCESS
        inbMos = node.methods.ResolveClass('mgmtInB').GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
        configToPost = []

        for inbMo in inbMos:
            tenantName = getTenantFromDn(inbMo.dn)
            mgmtPName = getMgmtPFromDn(inbMo.dn)
            inbName = getNameFromDn(inbMo.dn)
            perContractConfig = node.mit.polUni()
            numContracts = 0
            for child in inbMo.Children:
                if child.ClassName == "fvRsProv":
                    contractDn = child.tDn
                    if not contractDn:
                        logger.debug("Relation {} {} under {} missing target Dn, skipping contract relation".format(child.ClassName, child.dn, inbMo.dn))
                        continue
                    for newContract in contractConversionDescriptor.getByProvider(contractDn, inbMo.dn):
                        perContractConfig.fvTenant(tenantName).mgmtMgmtP(mgmtPName)\
                                .mgmtInB(inbName).fvRsProv(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                        tagAnnConfig = perContractConfig.fvTenant(tenantName)\
                                        .mgmtMgmtP(mgmtPName).mgmtInB(inbName)\
                                        .fvRsProv(tnVzBrCPName=getNameFromDn(contractDn))\
                                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark InB fvRsProv for ESG migration cleanup"
                        numContracts += 1
                elif child.ClassName == "fvRsCons":
                    contractDn = child.tDn
                    if not contractDn:
                        logger.debug("Relation {} {} under {} missing target Dn, skipping contract relation".format(child.ClassName, child.dn, inbMo.dn))
                        continue
                    for newContract in contractConversionDescriptor.getByConsumer(contractDn, inbMo.dn):
                        perContractConfig.fvTenant(tenantName).mgmtMgmtP(mgmtPName)\
                                .mgmtInB(inbName).fvRsCons(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                        tagAnnConfig = perContractConfig.fvTenant(tenantName)\
                                        .mgmtMgmtP(mgmtPName).mgmtInB(inbName)\
                                        .fvRsCons(tnVzBrCPName=getNameFromDn(contractDn))\
                                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark InB fvRsCons for ESG migration cleanup"
                        numContracts += 1
                elif child.ClassName == "fvRsConsIf":
                    contractIfDn = child.tDn
                    if not contractIfDn:
                        logger.debug("Relation {} {} under {} missing target Dn, skipping contract relation".format(child.ClassName, child.dn, inbMo.dn))
                        continue
                    for newContract in contractConversionDescriptor.getByConsumerIf(contractIfDn, inbMo.dn):
                        contractIfName = getNameFromDn(newContract['newContractDn'])
                        # Create contract interface
                        perContractConfig.fvTenant(tenantName).vzCPIf(contractIfName).vzRsIf(tDn=newContract['newExportedFromDn'])
                        # Attach Consumed Contract Interface to Inband EPG
                        perContractConfig.fvTenant(tenantName).mgmtMgmtP(mgmtPName)\
                                .mgmtInB(inbName).fvRsConsIf(tnVzCPIfName=contractIfName)
                        tagAnnConfig = perContractConfig.fvTenant(tenantName)\
                                        .mgmtMgmtP(mgmtPName).mgmtInB(inbName)\
                                        .fvRsConsIf(tnVzCPIfName=getNameFromDn(contractIfDn))\
                                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark InB fvRsConsIf for ESG migration cleanup"
                        numContracts += 1
            if numContracts > 0:
                configToPost.append((inbMo.dn, perContractConfig))

        step = {'current': 1, 'total': len(configToPost)}
        for dn, config in configToPost:
            logger.info("Attaching {} contract{} to inband EPG {}".format(numContracts, "" if numContracts == 1 else "s", colored(dn)))
            rc |= logAndPost(config, step = step)

        return rc

    def createEsgVzAnyContractRelations():
        """
        Nested helper function
        Connect vzAny objects with cloned ESG contracts
        """
        rc = ReturnCode.SUCCESS
        vzAnyMos = node.methods.ResolveClass('vzAny').GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
        configToPost = []

        for vzAnyMo in vzAnyMos:
            tenantName = getTenantFromDn(vzAnyMo.dn)
            vrfName = getNameFromDn(vzAnyMo.dn)
            perContractConfig = node.mit.polUni()
            numContracts = 0
            for child in vzAnyMo.Children:
                if child.ClassName == "vzRsAnyToProv":
                    contractDn = child.tDn
                    if not contractDn:
                        logger.info("Relation {} {} under {} missing target Dn, skipping contract relation".format(child.ClassName, child.dn, vzAnyMo.dn))
                        continue
                    for newContract in contractConversionDescriptor.getByProvider(contractDn, vzAnyMo.dn):
                        perContractConfig.fvTenant(tenantName).fvCtx(vrfName)\
                                .vzAny().vzRsAnyToProv(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                        tagAnnConfig = perContractConfig.fvTenant(tenantName)\
                                        .fvCtx(vrfName).vzAny()\
                                        .vzRsAnyToProv(tnVzBrCPName=getNameFromDn(contractDn))\
                                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark vzAny vzRsAnyToProv for ESG migration cleanup"
                        numContracts += 1
                elif child.ClassName == "vzRsAnyToCons":
                    contractDn = child.tDn
                    if not contractDn:
                        logger.info("Relation {} {} under {} missing target Dn, skipping contract relation".format(child.ClassName, child.dn, vzAnyMo.dn))
                        continue
                    for newContract in contractConversionDescriptor.getByConsumer(contractDn, vzAnyMo.dn):
                        perContractConfig.fvTenant(tenantName).fvCtx(vrfName)\
                                .vzAny().vzRsAnyToCons(tnVzBrCPName=getNameFromDn(newContract['newContractDn']))
                        tagAnnConfig = perContractConfig.fvTenant(tenantName)\
                                        .fvCtx(vrfName).vzAny()\
                                        .vzRsAnyToCons(tnVzBrCPName=getNameFromDn(contractDn))\
                                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark vzAny vzRsAnyToCons for ESG migration cleanup"
                        numContracts += 1
                elif child.ClassName == "vzRsAnyToConsIf":
                    contractIfDn = child.tDn
                    if not contractIfDn:
                        logger.info("Relation {} {} under {} missing target Dn, skipping contract relation".format(child.ClassName, child.dn, vzAnyMo.dn))
                        continue
                    for newContract in contractConversionDescriptor.getByConsumerIf(contractIfDn, vzAnyMo.dn):
                        contractIfName = getNameFromDn(newContract['newContractDn'])
                        # Create contract interface
                        perContractConfig.fvTenant(tenantName).vzCPIf(contractIfName).vzRsIf(tDn=newContract['newExportedFromDn'])
                        # Attach Consumed Contract Interface to Inband EPG
                        perContractConfig.fvTenant(tenantName).fvCtx(vrfName)\
                                    .vzAny().vzRsAnyToConsIf(tnVzCPIfName=contractIfName)
                        tagAnnConfig = perContractConfig.fvTenant(tenantName)\
                                            .fvCtx(vrfName).vzAny()\
                                            .vzRsAnyToConsIf(tnVzCPIfName=getNameFromDn(contractIfDn))\
                                            .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                        tagAnnConfig.xmlcomment = "tagAnnotation used to mark vzAny vzRsAnyToConsIf for ESG migration cleanup"
                        numContracts += 1

            if numContracts > 0:
                # Add tag to vzAny for faster lookup during cleanup
                perContractConfig.fvTenant(tenantName).fvCtx(vrfName).vzAny()\
                        .tagAnnotation(key=migrationAnnotateKey, value=migrationAnnotateVal)
                configToPost.append((vzAnyMo.dn, perContractConfig))

        step = {'current': 1, 'total': len(configToPost)}
        for dn, config in configToPost:
            logger.info("Attaching vzAny {} to new ESG contracts.".format(colored(dn)))
            rc |= logAndPost(config, step = step)

        return rc

    def fillVrfDictionarySeg(vrf):
        """
        Nested helper function
        Fills the vrfToSeg dictionary.
        """
        def conditionFn():
            results = node.mit.FromDn(vrf).GET()
            if results and len(results) > 0 and results[0].seg != "any":
                return int(results[0].seg)
            return None

        def onSuccess(segId):
            vrfToSeg[vrf] = segId
            logger.debug("VRF {} has been assigned Segment ID {}".format(colored(vrf), colored(segId)))

        def onFailure():
            vrfToSeg[vrf] = 0

        segId = waitForCondition(
            conditionFn = conditionFn,
            description = "VRF {} to be assigned a Segment ID".format(colored(vrf)),
            timeout = CONFIG_TIMEOUT,
            ih = InputHandler(),
            onSuccess = onSuccess,
            onFailure = onFailure)

        return ReturnCode.SUCCESS if segId else ReturnCode.CONFIG_TIMEOUT

    def fillEsgDictionaryPcTag(esgData, vrf):
        """
        Nested helper function
        Fills the esgToPcTag dictionary with the PC Tag assigned to the ESG after creation.
        """
        tenantName = getTenantFromDn(esgData['epgs'][0]) if esgData['epgs'] else getTenantFromDn(vrf)
        appProfileName = esgData['applicationProfile']
        esgName = esgData['name']
        esgDn = f"uni/tn-{tenantName}/ap-{appProfileName}/esg-{esgName}"

        def conditionFn():
            results = node.mit.FromDn(esgDn).GET()
            if results and len(results) > 0 and results[0].pcTag != "any":
                return int(results[0].pcTag)
            return None

        def onSuccess(pcTag):
            esgToPcTag[esgDn] = pcTag
            logger.debug("ESG {} has been assigned PC Tag {}".format(colored(esgName), colored(pcTag)))

        def onFailure():
            esgToPcTag[esgDn] = 0

        pcTag = waitForCondition(
            conditionFn = conditionFn,
            description = "ESG {} on tenant {} to be assigned a PC Tag".format(colored(esgName), colored(tenantName)),
            timeout = CONFIG_TIMEOUT,
            ih = InputHandler(),
            onSuccess = onSuccess,
            onFailure = onFailure)

        return ReturnCode.SUCCESS if pcTag else ReturnCode.CONFIG_TIMEOUT

    #
    # Phase 1
    #

    calculatePreExistingEsgContractRelations()

    returnCode = ReturnCode.SUCCESS
    logger.info(colored("----------------------------------------------------", bold=True))
    logger.info(colored("Configuration phase 1: ESGs and Leak Routes Creation", bold=True))
    logger.info(colored("                       Contracts Clone", bold=True))
    logger.info(colored("----------------------------------------------------", bold=True))
    for vrf in sorted(esgDataForXml['vrfs'], key=lambda x: x['vrf']):
        returnCode |= createEsgAndLeakRouteForVrf(vrf)

    if returnCode not in [ReturnCode.SUCCESS, ReturnCode.USERSKIPPED]:
        logger.error("Configuration phase 1: ESGs and Leak Routes Creation did not complete successfully. Please check the logs. Return code: {}".format(returnCode))
        sys.exit(1)

    inputHandler.reset()

    returnCode |= createEsgClonedContracts()
    if returnCode not in [ReturnCode.SUCCESS, ReturnCode.USERSKIPPED]:
        logger.error("Configuration phase 1: Contracts Clone did not complete successfully. Please check the logs. Return code: {}".format(returnCode))
        sys.exit(1)

    inputHandler.reset()

    #
    # Phase 2
    #
    logger.info(colored("----------------------------------------------------------", bold=True))
    logger.info(colored("Configuration phase 2: {} Installation".format("Selectors" if tcamOptimizedMode else "Contract"), bold=True))
    logger.info(colored("Optimized mode: {}".format("YES" if tcamOptimizedMode else "NO"), bold=True))
    logger.info(colored("----------------------------------------------------------", bold=True))

    if tcamOptimizedMode:
        returnCode |= createEsgSelectors()
        inputHandler.reset()
    else:
        returnCode |= createEsgContractRelations()
        inputHandler.reset()

        # Attach inband EPGs to the new ESG contracts
        returnCode |= createEsgInbContractRelations()
        inputHandler.reset()

        # Attach vzAny to the new ESG contracts
        returnCode |= createEsgVzAnyContractRelations()
        inputHandler.reset()

        # Clone PBR contexts and attach to the new ESG Contracts
        returnCode |= createEsgPbrCtx()
        inputHandler.reset()

    if applyConfig:
        tcamCapacityCheck(node, showInfo=True)

    #
    # Phase 3
    #
    logger.info(colored("----------------------------------------------------------", bold=True))
    logger.info(colored("Configuration phase 3: {} Installation".format("Contract" if tcamOptimizedMode else "Selectors"), bold=True))
    logger.info(colored("Optimized mode: {}".format("YES" if tcamOptimizedMode else "NO"), bold=True))
    logger.info(colored("----------------------------------------------------------", bold=True))

    if tcamOptimizedMode:
        returnCode |= createEsgContractRelations()
        inputHandler.reset()

        # Attach inband EPGs to the new ESG contracts
        returnCode |= createEsgInbContractRelations()
        inputHandler.reset()

        # Attach vzAny to the new ESG contracts
        returnCode |= createEsgVzAnyContractRelations()
        inputHandler.reset()

        # Clone PBR contexts and attach to the new ESG Contracts
        returnCode |= createEsgPbrCtx()
        inputHandler.reset()
    else:
        returnCode |= createEsgSelectors()
        inputHandler.reset()

    if applyConfig:
        tcamCapacityCheck(node, showInfo=True)

    logger.info(colored("----------------------------", bold=True))
    logger.info(colored("END of EPG to ESG conversion", bold=True))
    logger.info(colored("----------------------------\n", bold=True))
    if returnCode == ReturnCode.SUCCESS:
        logger.info("ESG conversion completed successfully.")
    elif returnCode == ReturnCode.USERSKIPPED:
        logger.warning("ESG conversion completed with some user skipped operations.")
    else:
        logger.error("ESG conversion completed with errors. Please check the logs. Return code: {}".format(returnCode))


#########################################################
# CLEANUP PHASE
#########################################################
def generateCleanupConfig(node, outputFile, noConfig, configStrategy):

    logger = logging.getLogger(globalValues['logger'])
    migrationAnnotateKey = '__' + TOOL_NAME_STR
    migrationAnnotateVal = 'Cleanup required after migration'
    returnCode = ReturnCode.SUCCESS

    def logAndPost(outputElem, step = None, allowYesToAll = True):
        return logAndPostHandler(outputElem, node, outputFile = outputFile, noConfig = noConfig, step = step, allowYesToAll = allowYesToAll)

    def findClassInstancesWithTag(className, tagKey, tagVal, skipConfigIssues):
        """
        Find all instances of input className which match input tagKey + tagVal.
        Returns list of matching MO objects
        """
        matchingMos = []
        mos = node.methods.ResolveClass(className).GET(**{'rsp-subtree': 'children', 'rsp-subtree-class': 'tagAnnotation'})

        for mo in mos:
            if skipConfigIssues and getattr(mo, "configIssues", None):
                continue

            for child in mo.Children:
                if child.ClassName == "tagAnnotation" and child.key == tagKey and child.value == tagVal:
                    matchingMos.append(mo)
                    break

        return matchingMos

    try:
        with open(outputFile, "w") as f:
            pass
    except Exception as e:
        logger.error("Failed to open file {} due to {}".format(outputFile, e))
        sys.exit(1)

    cleanupEPgs = {}
    cleanupContracts = {}
    cleanupProvContractToEpgTenantMap = {}
    cleanupExternalSubnets = {}
    instPToSubnetMap = {}
    instPToExtSubnetSelMap = {}
    globalConfigToPost = node.mit.polUni()
    perVrfConfigToPost = {}
    cleanupSequence = []

    spinner.text = "Analyze configuration"

    epgSelectors = findClassInstancesWithTag('fvEPgSelector', migrationAnnotateKey, migrationAnnotateVal, skipConfigIssues=True)
    for epgSelector in epgSelectors:
        cleanupEPgs[epgSelector.matchEpgDn] = {"epgSelector": epgSelector.dn, "vrfDn": epgSelector.matchScope}

    externalSubnets = findClassInstancesWithTag('fvExternalSubnetSelector', migrationAnnotateKey, migrationAnnotateVal, skipConfigIssues=True)
    for externalSubnet in externalSubnets:
        cleanupExternalSubnets.setdefault(externalSubnet.matchScope, set())
        cleanupExternalSubnets[externalSubnet.matchScope].add((ipaddress.ip_network(externalSubnet.ip, strict=False), externalSubnet.dn))

    if cleanupExternalSubnets:
        # Get all the existing External EPGs and their subnets if there are any external subnet selectors to clean up
        for extEpgMo in node.methods.ResolveClass('fvRtdEpPInfoHolder').GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'}):
            vrfDn = extEpgMo.ctxDefDn.removeprefix("uni/ctx-[").removesuffix("]")
            if vrfDn not in cleanupExternalSubnets: continue
            instPDn = extEpgMo.epgPKey
            instPToSubnetMap[instPDn] = set()
            instPToExtSubnetSelMap[instPDn] = set()
            for subnetMo in extEpgMo.Children:
                if subnetMo.ClassName == 'l3extSubnetDef':
                    ip = ipaddress.ip_network(subnetMo.ip, strict=False)
                    for extSubnetSelIp, extSubnetSelDn in cleanupExternalSubnets[vrfDn]:
                        if ip == extSubnetSelIp:
                            # Exact match, mark for cleanup
                            instPToSubnetMap[instPDn].add(subnetMo.ip)
                            instPToExtSubnetSelMap[instPDn].add(extSubnetSelDn)
                            if instPDn not in cleanupEPgs:
                                cleanupEPgs[instPDn] = {"epgSelector": None, "vrfDn": vrfDn}

    lenCleanupEPgs = len(cleanupEPgs)
    logger.debug("Found {} potential EPG{} to clean up".format(lenCleanupEPgs, '' if lenCleanupEPgs == 1 else 's'))

    spinner.text = "Analyze configuration"

    for epgDn in sorted(cleanupEPgs):
        epgData = cleanupEPgs[epgDn]
        vrfDn = epgData["vrfDn"]
        if not vrfDn:
            logger.error(f"Unable to determine VRF for EPG with Dn {epgDn}. Skipping cleanup of this EPG.")
            continue
        else:
            perVrfConfigToPost.setdefault(vrfDn, node.mit.polUni())
        perEpgConfig = node.mit.polUni()
        epgTenantName = getTenantFromDn(epgDn)
        epgApName = getAppProfileFromDn(epgDn)
        epgL3OutName = getL3OutFromDn(epgDn)
        epgName = getNameFromDn(epgDn)

        sourceSubtree = node.mit.FromDn(epgDn).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
        if not sourceSubtree or len(sourceSubtree) == 0:
            logger.error(f"There is an Selector configured for EPG {epgDn}, but the EPG does not exist. Skipping cleanup of this EPG.")
            continue

        epgSelectorDn = epgData["epgSelector"]
        if epgSelectorDn:
            esgTenantName = getTenantFromDn(epgSelectorDn)
            esgApName = getAppProfileFromDn(epgSelectorDn)
            esgName = epgSelectorDn.split('/')[3].removeprefix("esg-")  # fvESg is always the 4th segment in the Dn
            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                config.fvTenant(esgTenantName).fvAp(esgApName).fvESg(name=esgName).fvEPgSelector(matchEpgDn=epgDn).tagAnnotation(key=migrationAnnotateKey, status='deleted')

        epgMo = sourceSubtree[0]
        if epgMo.ClassName == 'fvAEPg':
            bdDn = None
            # Find associated BD if epgClass is fvAEPg
            for epgChildren in epgMo.Children:
                if epgChildren.ClassName == 'fvRsBd':
                    bdDn = epgChildren.tDn
                    logger.debug("EPG {} is associated to BD {}".format(epgDn, bdDn))
                    break

            for epgChildren in epgMo.Children:
                if epgChildren.ClassName == 'fvRsProv':
                    for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                        config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvRsProv(tnVzBrCPName=epgChildren.tnVzBrCPName, status='deleted')
                    cleanupProvContractToEpgTenantMap[epgChildren.tDn] = epgTenantName
                    cleanupContracts.setdefault(epgChildren.tDn, set())
                    cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsProv'))
                elif epgChildren.ClassName == 'fvRsCons':
                    for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                        config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvRsCons(tnVzBrCPName=epgChildren.tnVzBrCPName, status='deleted')
                    cleanupContracts.setdefault(epgChildren.tDn, set())
                    cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsCons'))
                elif epgChildren.ClassName == 'fvRsIntraEpg':
                    for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                        config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvRsIntraEpg(tnVzBrCPName=epgChildren.tnVzBrCPName, status='deleted')
                    cleanupContracts.setdefault(epgChildren.tDn, set())
                    cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsIntraEpg'))
                elif epgChildren.ClassName == 'fvRsConsIf':
                    for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                        config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvRsConsIf(tnVzCPIfName=epgChildren.tnVzCPIfName, status='deleted')
                    cleanupContracts.setdefault(epgChildren.tDn, set())
                    cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsConsIf'))
                elif epgChildren.ClassName == 'fvRsSecInherited':
                    for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                        config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvRsSecInherited(tDn=epgChildren.tDn, status='deleted')
                elif epgChildren.ClassName == 'fvSubnet':
                    scopeFlags = [flag.strip() for flag in epgChildren.scope.split(",")]
                    if "shared" in scopeFlags:
                        bdSubnetDn = bdDn + "/subnet-[{}]".format(epgChildren.ip)
                        bdSubnetSubtree = node.mit.FromDn(bdSubnetDn).GET()

                        # Check if BD subnet is of special type (NLB, Anycast, Reachability)
                        reason = "it does not exist in BD"
                        for subnetChild in epgChildren.Children:
                            if subnetChild.ClassName in ['fvEpNlb', 'fvEpAnycast', 'fvEpReachability']:
                                reason = "it rappresent a{} {} endpoint"\
                                    .format("n" if subnetChild.ClassName in ['fvEpNlb', 'fvEpAnycast'] else "",\
                                            subnetChild.ClassName.replace('fvEp', ''))
                                bdSubnetSubtree = None
                                break

                        # If BD subnet does not exist or EPG Subnet is a special type (NLB, Anycast, Reachability)
                        # then just remove shared scope instead of deleting the subnet
                        if not bdSubnetSubtree or len(bdSubnetSubtree) == 0:
                            scopeFlags.remove("shared")
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                subnet = config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvSubnet(ip=epgChildren.ip, scope=",".join(scopeFlags))
                                subnet.xmlcomment = "Subnet not deleted since {}. Remove shared scope".format(reason)
                        else:
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(epgTenantName).fvAp(epgApName).fvAEPg(name=epgName).fvSubnet(ip=epgChildren.ip, status='deleted')
        elif epgMo.ClassName == 'l3extInstP':
            if epgDn in instPToExtSubnetSelMap:
                for extSubnetSelDn in instPToExtSubnetSelMap[epgDn]:
                    esgTenantName = getTenantFromDn(extSubnetSelDn)
                    esgApName = getAppProfileFromDn(extSubnetSelDn)
                    esgName = extSubnetSelDn.split('/')[3].removeprefix("esg-")  # fvESg is always the 4th segment in the Dn
                    ip = extSubnetSelDn.split('extsubselector-[')[1].split(']')[0]
                    for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                        config.fvTenant(esgTenantName).fvAp(esgApName).fvESg(name=esgName).fvExternalSubnetSelector(ip=ip).tagAnnotation(key=migrationAnnotateKey, status='deleted')
            allSecuritySubnetHandled = True
            for epgChildren in epgMo.Children:
                if epgChildren.ClassName == 'l3extSubnet':
                    scopeFlags = [flag.strip() for flag in epgChildren.scope.split(",")]
                    if epgChildren.ip in instPToSubnetMap[epgDn]:
                        scope = [flag for flag in scopeFlags if flag not in ['import-security', 'shared-security', 'shared-rtctrl']]
                        if len(scope) == 0:
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(epgTenantName).l3extOut(name=epgL3OutName).l3extInstP(name=epgName).l3extSubnet(ip=epgChildren.ip, status='deleted')
                        elif scope != scopeFlags:
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                subnet = config.fvTenant(epgTenantName).l3extOut(name=epgL3OutName)\
                                                .l3extInstP(name=epgName).l3extSubnet(ip=epgChildren.ip, scope=",".join(scope))
                                subnet.xmlcomment = "Subnet not deleted since other flags are present. Remove security and route leak flags"
                    else:
                        if 'shared-security' in scopeFlags or 'import-security' in scopeFlags:
                            allSecuritySubnetHandled = False
            if allSecuritySubnetHandled:
                for epgChildren in epgMo.Children:
                    if epgChildren.ClassName == 'fvRsProv':
                        for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                            config.fvTenant(epgTenantName).l3extOut(epgL3OutName).l3extInstP(name=epgName).fvRsProv(tnVzBrCPName=epgChildren.tnVzBrCPName, status='deleted')
                        cleanupProvContractToEpgTenantMap[epgChildren.tDn] = epgTenantName
                        cleanupContracts.setdefault(epgChildren.tDn, set())
                        cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsProv'))
                    elif epgChildren.ClassName == 'fvRsCons':
                        for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                            config.fvTenant(epgTenantName).l3extOut(epgL3OutName).l3extInstP(name=epgName).fvRsCons(tnVzBrCPName=epgChildren.tnVzBrCPName, status='deleted')
                        cleanupContracts.setdefault(epgChildren.tDn, set())
                        cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsCons'))
                    elif epgChildren.ClassName == 'fvRsIntraEpg':
                        for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                            config.fvTenant(epgTenantName).l3extOut(epgL3OutName).l3extInstP(name=epgName).fvRsIntraEpg(tnVzBrCPName=epgChildren.tnVzBrCPName, status='deleted')
                        cleanupContracts.setdefault(epgChildren.tDn, set())
                        cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsIntraEpg'))
                    elif epgChildren.ClassName == 'fvRsConsIf':
                        for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                            config.fvTenant(epgTenantName).l3extOut(epgL3OutName).l3extInstP(name=epgName).fvRsConsIf(tnVzCPIfName=epgChildren.tnVzCPIfName, status='deleted')
                        cleanupContracts.setdefault(epgChildren.tDn, set())
                        cleanupContracts[epgChildren.tDn].add(buildReverseRelation(epgDn, epgChildren.tDn, 'fvRsConsIf'))
        else:
            continue

        if configStrategy == ConfigStrategy.INTERACTIVE and len(list(perEpgConfig.Children)):
            cleanupSequence.append({'text': "Cleaning up security on {} {}".format(epgDnToStr(epgDn), colored(epgDn)), 'config': perEpgConfig})

    # Cleanup contract relations to InB epgs which have tags to be deleted
    inbMos = node.methods.ResolveClass('mgmtInB').GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
    for inbMo in inbMos:
        eppDn = 'uni/epp/inb-[{}]'.format(inbMo.dn)
        eppRequest = node.mit.FromDn(eppDn).GET()
        if not eppRequest or len(eppRequest) == 0:
            logger.error(f"Inband EPG {inbMo.dn} does not have an EPP.")
            continue
        vrfDn = eppRequest[0].ctxDefDn.removeprefix("uni/ctx-[").removesuffix("]")
        perVrfConfigToPost.setdefault(vrfDn, node.mit.polUni())

        tenantName = getTenantFromDn(inbMo.dn)
        mgmtPName = getMgmtPFromDn(inbMo.dn)
        inbName = getNameFromDn(inbMo.dn)
        perEpgConfig = node.mit.polUni()
        for child in inbMo.Children:
            if child.ClassName in ("fvRsProv", "fvRsCons", "fvRsConsIf"):
                for grandchild in child.Children:
                    if grandchild.ClassName == "tagAnnotation" \
                        and grandchild.key == migrationAnnotateKey \
                        and grandchild.value == migrationAnnotateVal:
                        if child.ClassName == "fvRsProv":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).mgmtMgmtP(mgmtPName).mgmtInB(inbName).fvRsProv(tnVzBrCPName=child.tnVzBrCPName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set())
                            cleanupContracts[child.tDn].add(buildReverseRelation(inbMo.dn, child.tDn, 'fvRsProv'))
                        elif child.ClassName == "fvRsCons":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).mgmtMgmtP(mgmtPName).mgmtInB(inbName).fvRsCons(tnVzBrCPName=child.tnVzBrCPName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set())
                            cleanupContracts[child.tDn].add(buildReverseRelation(inbMo.dn, child.tDn, 'fvRsCons'))
                        elif child.ClassName == "fvRsConsIf":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).mgmtMgmtP(mgmtPName).mgmtInB(inbName).fvRsConsIf(tnVzCPIfName=child.tnVzCPIfName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set())
                            cleanupContracts[child.tDn].add(buildReverseRelation(inbMo.dn, child.tDn, 'fvRsConsIf'))
                        break

        if configStrategy == ConfigStrategy.INTERACTIVE and len(list(perEpgConfig.Children)):
            cleanupSequence.append({'text': "Cleaning up security on {} {}".format(epgDnToStr(inbMo.dn), colored(inbMo.dn)), 'config': perEpgConfig})

    # Cleanup contract relations for pre-esisting fvESg which have tags to be deleted
    fvESgMos = findClassInstancesWithTag('fvESg', migrationAnnotateKey, migrationAnnotateVal, skipConfigIssues=True)
    for fvESgMo in fvESgMos:
        esgDn = fvESgMo.dn
        fvESgSubtree = node.mit.FromDn(esgDn).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
        if not fvESgSubtree or len(fvESgSubtree) == 0:
            continue
        for child in fvESgSubtree[0].Children:
            if child.ClassName == 'fvRsScope':
                vrfDn = child.tDn
                break
        if not vrfDn:
            logger.error(f"ESG {esgDn} does not have an associated VRF. Skipping cleanup of this ESG.")
            continue

        esgName = getNameFromDn(esgDn)
        apName = getAppProfileFromDn(esgDn)
        tenantName = getTenantFromDn(esgDn)
        perVrfConfigToPost.setdefault(vrfDn, node.mit.polUni())
        perEpgConfig = node.mit.polUni()
        # Cleanup fvESg Tag Annotation
        for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
            config.fvTenant(tenantName).fvAp(apName).fvESg(esgName).tagAnnotation(key=migrationAnnotateKey, status="deleted")
        for child in fvESgSubtree[0].Children:
            if child.ClassName in ("fvRsProv", "fvRsCons", "fvRsConsIf"):
                for grandchild in child.Children:
                    if grandchild.ClassName == "tagAnnotation" \
                        and grandchild.key == migrationAnnotateKey \
                        and grandchild.value == migrationAnnotateVal:
                        if child.ClassName == "fvRsProv":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).fvAp(apName).fvESg(esgName).fvRsProv(tnVzBrCPName=child.tnVzBrCPName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set()).add(buildReverseRelation(esgDn, child.tDn, 'fvRsProv'))
                        elif child.ClassName == "fvRsCons":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).fvAp(apName).fvESg(esgName).fvRsCons(tnVzBrCPName=child.tnVzBrCPName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set()).add(buildReverseRelation(esgDn, child.tDn, 'fvRsCons'))
                        elif child.ClassName == "fvRsConsIf":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).fvAp(apName).fvESg(esgName).fvRsConsIf(tnVzCPIfName=child.tnVzCPIfName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set()).add(buildReverseRelation(esgDn, child.tDn, 'fvRsConsIf'))
                        break

        if configStrategy == ConfigStrategy.INTERACTIVE and len(list(perEpgConfig.Children)):
            cleanupSequence.append({'text': "Cleaning up security on {} {}".format(epgDnToStr(esgDn), colored(esgDn)), 'config': perEpgConfig})

    # Cleanup contract relations to vzAny which have tags to be deleted
    vzAnyMos = findClassInstancesWithTag('vzAny', migrationAnnotateKey, migrationAnnotateVal, skipConfigIssues=True)
    for vzAnyMo in vzAnyMos:
        tenantName = getTenantFromDn(vzAnyMo.dn)
        vrfName = getNameFromDn(vzAnyMo.dn)
        vrfDn = vzAnyMo.dn.removesuffix('/any')
        perVrfConfigToPost.setdefault(vrfDn, node.mit.polUni())
        perEpgConfig = node.mit.polUni()
        # Cleanup vzAny Tag Annotation
        for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
            config.fvTenant(tenantName).fvCtx(vrfName).vzAny().tagAnnotation(key=migrationAnnotateKey, status="deleted")
        vzAnySubtree = node.mit.FromDn(vzAnyMo.dn).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})
        if not vzAnySubtree or len(vzAnySubtree) == 0:
            continue
        for child in vzAnySubtree[0].Children:
            if child.ClassName in ("vzRsAnyToProv", "vzRsAnyToCons", "vzRsAnyToConsIf"):
                for grandchild in child.Children:
                    if grandchild.ClassName == "tagAnnotation" \
                        and grandchild.key == migrationAnnotateKey \
                        and grandchild.value == migrationAnnotateVal:
                        if child.ClassName == "vzRsAnyToProv":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).fvCtx(vrfName).vzAny().vzRsAnyToProv(tnVzBrCPName=child.tnVzBrCPName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set())
                            cleanupContracts[child.tDn].add(buildReverseRelation(vzAnyMo.dn, child.tDn, 'vzRsAnyToProv'))
                        elif child.ClassName == "vzRsAnyToCons":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).fvCtx(vrfName).vzAny().vzRsAnyToCons(tnVzBrCPName=child.tnVzBrCPName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set())
                            cleanupContracts[child.tDn].add(buildReverseRelation(vzAnyMo.dn, child.tDn, 'vzRsAnyToCons'))
                        elif child.ClassName == "vzRsAnyToConsIf":
                            for config in [perEpgConfig, perVrfConfigToPost[vrfDn], globalConfigToPost]:
                                config.fvTenant(tenantName).fvCtx(vrfName).vzAny().vzRsAnyToConsIf(tnVzCPIfName=child.tnVzCPIfName, status='deleted')
                            cleanupContracts.setdefault(child.tDn, set())
                            cleanupContracts[child.tDn].add(buildReverseRelation(vzAnyMo.dn, child.tDn, 'vzRsAnyToConsIf'))
                        break

        if configStrategy == ConfigStrategy.INTERACTIVE and len(list(perEpgConfig.Children)):
            cleanupSequence.append({'text': "Cleaning up security on {} {}".format(epgDnToStr(vzAnyMo.dn), colored(vzAnyMo.dn)), 'config': perEpgConfig})

    if configStrategy == ConfigStrategy.VRF:
        for vrfDn, perVrfConfig in sorted(perVrfConfigToPost.items()):
            if list(perVrfConfig.Children):
                cleanupSequence.append({'text': "Cleaning up security on VRF {} {}"
                                        .format(colored(getNameFromDn(vrfDn)), colored(vrfDn)), 'config': perVrfConfig})
    elif configStrategy == ConfigStrategy.GLOBAL:
        if len(list(globalConfigToPost.Children)):
            cleanupSequence.append({'text': "Cleaning up security globally", 'config': globalConfigToPost})

    logger.info(colored("------------------------------------------------", bold=True))
    logger.info(colored("EPG/External EPG/vzAny/Inband EPG cleanup config", bold=True))
    logger.info(colored("------------------------------------------------", bold=True))

    step = {'current': 1, 'total': len(cleanupSequence)}
    if step['total'] == 0:
        logger.info("No EPGs, vzAny or Inband EPGs to clean up")
    for cleanup in cleanupSequence:
        logger.info(cleanup['text'])
        returnCode |= logAndPost(cleanup['config'], step=step)

    logger.info(colored("------------------------------------------------", bold=True))
    logger.info(colored("END of EPG/External EPG/vzAny/Inband EPG cleanup", bold=True))
    logger.info(colored("------------------------------------------------\n", bold=True))

    inputHandler.reset()

    spinner.text = "Collecting contracts for cleanup"
    # Cleanup contracts from previous phase which no longer have any contract associations
    cleanupSequence = []
    globalConfigToPost = node.mit.polUni()
    perTenantConfigToPost = {}
    cleanupContracts.pop('', None)
    deletedProvContracts = defaultdict(set) # EPG Tenant to Deleted Provider Contract Set
    contractRelClasses = ['vzRtCons', 'vzRtProv', 'vzRtIntraEpg', 'vzRtConsIf', 'vzRtAnyToCons', 'vzRtAnyToProv', 'vzRtAnyToConsIf']
    for contract, deletedRtRelations in sorted(cleanupContracts.items()):
        perContractConfig = node.mit.polUni()
        contractCleanup = True
        tenant = getTenantFromDn(contract)
        perTenantConfigToPost.setdefault(tenant, node.mit.polUni())
        contractName = getNameFromDn(contract)
        sourceSubtree = node.mit.FromDn(contract).GET(**{'rsp-subtree': 'full', 'rsp-prop-include': 'all'})

        if not sourceSubtree or len(sourceSubtree) == 0:
            logger.error(f"Error in retrieving and cleaning up contract {contract} on {tenant}. Skipping cleanup of this contract.")
            spinner.text = "Collecting contracts for cleanup"
            continue
        for childMo in sourceSubtree[0].Children:
            if childMo.ClassName in contractRelClasses:
                if childMo.Dn not in deletedRtRelations:
                    contractCleanup = False
                    logger.debug("Contract {} still has RT relations. Skipping cleanup of this contract.".format(contract))
                    break

        if contractCleanup:
            if "/brc-" in contract:
                for config in [perContractConfig, perTenantConfigToPost[tenant], globalConfigToPost]:
                    config.fvTenant(tenant).vzBrCP(name=contractName, status='deleted')
            elif "/cif-" in contract:
                for config in [perContractConfig, perTenantConfigToPost[tenant], globalConfigToPost]:
                    config.fvTenant(tenant).vzCPIf(name=contractName, status='deleted')
            if contract in cleanupProvContractToEpgTenantMap:
                deletedProvContracts[cleanupProvContractToEpgTenantMap[contract]].add(contractName)

            if configStrategy == ConfigStrategy.INTERACTIVE and len(list(perContractConfig.Children)):
                cleanupSequence.append({'text': "Cleaning up contract {} on tenant {}"
                                        .format(colored(contractName), colored(tenant)), 'config': perContractConfig})

    if configStrategy == ConfigStrategy.VRF:
        for tenant, perTenantCfg in perTenantConfigToPost.items():
            if len(list(perTenantCfg.Children)):
                cleanupSequence.append({'text': "Cleaning up contracts on tenant {}".format(colored(tenant)), 'config': perTenantCfg})
    elif configStrategy == ConfigStrategy.GLOBAL:
        if len(list(globalConfigToPost.Children)):
            cleanupSequence.append({'text': "Cleaning up contracts globally", 'config': globalConfigToPost})

    logger.info(colored("-----------------------", bold=True))
    logger.info(colored("Contract cleanup config", bold=True))
    logger.info(colored("-----------------------", bold=True))

    step = {'current': 1, 'total': len(cleanupSequence)}
    if step['total'] == 0:
        logger.info("No contracts to clean up")
    for cleanup in cleanupSequence:
        logger.info(cleanup['text'])
        returnCode |= logAndPost(cleanup['config'], step=step)

    logger.info(colored("-----------------------", bold=True))
    logger.info(colored("END of Contract cleanup", bold=True))
    logger.info(colored("-----------------------\n", bold=True))

    inputHandler.reset()

    # Cleanup PBR Logical Device Context Objects corresponding to cleanedup contracts
    cleanupSequence = []
    globalConfigToPost = node.mit.polUni()
    perTenantConfigToPost = {}
    vnsLDevCtxMos = node.methods.ResolveClass('vnsLDevCtx').GET()
    for vnsLDevCtxMo in vnsLDevCtxMos:
        perContractConfig = node.mit.polUni()
        vnsTenant = getTenantFromDn(vnsLDevCtxMo.Dn)
        perTenantConfigToPost.setdefault(vnsTenant, node.mit.polUni())
        # Provider EP and PBR Logical Device Context should be in same tenant
        if vnsLDevCtxMo.ctrctNameOrLbl in deletedProvContracts[vnsTenant]:
            for config in [perContractConfig, perTenantConfigToPost[vnsTenant], globalConfigToPost]:
                config.fvTenant(vnsTenant).vnsLDevCtx(ctrctNameOrLbl=vnsLDevCtxMo.ctrctNameOrLbl,
                                                      graphNameOrLbl=vnsLDevCtxMo.graphNameOrLbl,
                                                      nodeNameOrLbl=vnsLDevCtxMo.nodeNameOrLbl,
                                                      status='deleted')

            if configStrategy == ConfigStrategy.INTERACTIVE and len(list(perContractConfig.Children)):
                cleanupSequence.append({'text': "Cleaning up PBR Logical Device Context for contract {} on tenant {}"
                                        .format(colored(vnsLDevCtxMo.ctrctNameOrLbl), colored(vnsTenant)), 'config': perContractConfig})

    if configStrategy == ConfigStrategy.VRF:
        for tenant, perTenantCfg in perTenantConfigToPost.items():
            if len(list(perTenantCfg.Children)):
                cleanupSequence.append({'text': "Cleaning up PBR Logical Device Context on tenant {}".format(colored(tenant)), 'config': perTenantCfg})
    elif configStrategy == ConfigStrategy.GLOBAL:
        if len(list(globalConfigToPost.Children)):
            cleanupSequence.append({'text': "Cleaning up PBR Logical Device Context globally", 'config': globalConfigToPost})

    logger.info(colored("-----------------------------------------", bold=True))
    logger.info(colored("PBR Logical Device Context cleanup config", bold=True))
    logger.info(colored("-----------------------------------------", bold=True))

    step = {'current': 1, 'total': len(cleanupSequence)}
    if step['total'] == 0:
        logger.info("No PBR Logical Device Context to clean up")
    for cleanup in cleanupSequence:
        logger.info(cleanup['text'])
        returnCode |= logAndPost(cleanup['config'], step=step)

    logger.info(colored("-----------------------------------------", bold=True))
    logger.info(colored("END of PBR Logical Device Context cleanup", bold=True))
    logger.info(colored("-----------------------------------------\n", bold=True))

    if returnCode == ReturnCode.SUCCESS:
        logger.info("Cleanup completed successfully.")
    elif returnCode == ReturnCode.USERSKIPPED:
        logger.warning("Cleanup completed with some user skipped operations.")
    else:
        logger.error("Cleanup completed with errors. Please check the logs. Return code: {}".format(returnCode))


def dryRunFuncHandle(args):
    logger = logging.getLogger(globalValues['logger'])

    logger.info(colored("-----------------------", bold=True))
    logger.info(colored("Dryrun phase", bold=True))
    logger.info(colored("-----------------------", bold=True))
    logger.info("""
During the Dryrun phase, all EPGs in the system are analyzed and grouped into ESGs based on
their contract layout.
The result of this analysis is a YAML file, which can later be used during the migration phase.

The Dryrun can be executed in two modes:
  - one-to-one: each EPG is assigned to its own ESG.
  - optimized: EPGs with identical contract layout are grouped into the same ESG.

The optimized mode analisys reduces the number of ESGs created, it reduces the final TCAM
utilization and it will allow communication between the grouped EPGs.
If communication between the grouped EPGs is not desired and existing contracts and security
layout must be preserved, the one-to-one mode is the recommended approach.

The Dryrun can be performed using a configuration snapshot provided in JSON or XML format,
a tar.gz archive containing the snapshot, a DBXML file (internal only), or by connecting
directly to the APIC.
When connecting to the APIC, a configuration snapshot is automatically created and used for
the analysis.

To avoid naming conflicts, a prefix and or suffix can be applied to the cloned contract names.
""")

    mit = None

    if args.mode == 'optimized':
        logger.info("""
The choosen Dryrun mode is "optimized" where Application EPGs/External EPGs with identical
contract layout are grouped into the same ESG.
This mode mode reduces the number of ESGs created and it reduces the TCAM utilization, but
it may {} between the grouped EPGs.
""".format(colored("allow unintended communication", color=None, bold=True, underline=True)))

    userInput = inputHandler.getInput("Do you want to continue (Y-Yes, Q-Quit): ", ['y', 'q'])
    if userInput == "q":
        sys.exit(0)

    if args.fromApic or args.apic:
        node = apicLoginGetNodeAndVersionCheck(args)

    if args.dbxml:
        if not os.path.exists(args.acimeta):
            logger.error("Unable to find {}. An ACIMeta file is needed when using the --dbxml option. Please specify a valid file via --acimeta <ACIMeta file>".format(args.acimeta))
            sys.exit(1)
        if not os.path.exists(args.dbxml):
            logger.error("File {} not found. Please provide a valid --dbxml <DB to analyze> file".format(args.dbxml))
            sys.exit(1)
        else:
            logging.info(f"DBXML file found: {args.dbxml}")
            mit = dbXmlToMit(args.dbxml, args)
    elif args.json:
        if not os.path.exists(args.acimeta):
            logger.error("Unable to find {}. An ACIMeta file is needed when using the --json option. Please specify a valid file via --acimeta <ACIMeta file>".format(args.acimeta))
            sys.exit(1)
        if not os.path.exists(args.json):
            logger.error("File {} not found. Please provide a valid --json <DB to analyze> file".format(args.json))
            sys.exit(1)
        else:
            logging.info(f"JSON file found: {args.json}")
            mit = jsonToMit(args.json, args)
    elif args.xml:
        if not os.path.exists(args.acimeta):
            logger.error("Unable to find {}. An ACIMeta file is needed when using the --xml option. Please specify a valid file via --acimeta <ACIMeta file>".format(args.acimeta))
            sys.exit(1)
        if not os.path.exists(args.xml):
            logger.error("File {} not found. Please provide a valid --xml <DB to analyze> file".format(args.xml))
            sys.exit(1)
        else:
            logging.info(f"XML File found: {args.xml}")
            mit = xmlToMit(args.xml, args)
    elif args.targz:
        if not os.path.exists(args.acimeta):
            logger.error("Unable to find {}. An ACIMeta file is needed when using the --targz option. Please specify a valid file via --acimeta <ACIMeta file>".format(args.acimeta))
            sys.exit(1)
        if not os.path.exists(args.targz):
            logger.error("File {} not found. Please provide a valid --targz <DB to analyze> file".format(args.targz))
            sys.exit(1)
        else:
            logging.info(f"TARGZ File found: {args.targz}")
            mit = snapshotToMitLocal(args.targz, "", args)
    elif args.fromApic or args.apic:
        rc, snapshotStr = createCfgSnapshot(node, TOOL_NAME_STR + "_Dryrun_Config")
        if rc == ReturnCode.USERSKIPPED:
            logger.warning("A configuration snapshot file is required to proceed with dryrun. Either specify a file via the --json, --xml, --targz, or --dbxml option or allow the creation of a snapshot. Aborting dryrun")
            sys.exit(1)
        elif rc != ReturnCode.SUCCESS:
            logger.error("Config snapshot creation failed, aborting dryrun")
            sys.exit(1)
        else:
            if snapshotStr:
                if args.fromApic:
                    mit = snapshotToMitLocal(snapshotStr, "/data2/snapshots/", args)
                else:
                    mit = snapshotToMit(snapshotStr, "/data2/snapshots/", args)
            else:
                logger.error("Empty snapshot received from APIC, aborting dryrun")
                sys.exit(1)

    vrfdns = [item for item in args.vrfdns.split(',')] if args.vrfdns else []
    tenantdns = [item for item in args.tenantdns.split(',')] if args.tenantdns else []
    ndCompliant = '--disableNdMode' not in sys.argv
    showStats = '--showStats' in sys.argv

    relationFramework(mit)
    generateDryrunConfig(mit, args.mode, ndCompliant, args.outYaml, args.prefix, args.suffix, vrfdns, tenantdns, showStats)

def dryRunValidate(args, parser):
    if not args.fromApic:
        if args.apic and (args.json or args.xml or args.dbxml or args.targz):
            parser.error("--apic cannot be used together with --json, --xml, --targz, or --dbxml.")
            sys.exit(2)
        elif not args.apic and not (args.json or args.xml or args.dbxml or args.targz):
            parser.error("one of --json, --xml, --targz, --dbxml, or --apic must be provided.")
            sys.exit(2)

        if args.apic:
            if not args.username or not args.password:
                parser.error("when using --apic, both --username and --password must be provided.")
                sys.exit(2)
        else:
            if args.username or args.password:
                parser.error("--username and --password can only be used with --apic.")
                sys.exit(2)

    validName = re.compile(r'[^a-zA-Z0-9_.:-]')

    if validName.search(args.prefix):
        parser.error("prefix '{}' contains invalid characters. Only alphanumeric characters, underscores (_), hyphens (-), periods (.), colons (:) are allowed.".format(args.prefix))
        sys.exit(2)

    if validName.search(args.suffix):
        parser.error("suffix '{}' contains invalid characters. Only alphanumeric characters, underscores (_), hyphens (-), periods (.), colons (:) are allowed.".format(args.suffix))
        sys.exit(2)

    vrfDns = args.vrfdns.split(',') if args.vrfdns else []
    tenantDns = args.tenantdns.split(',') if args.tenantdns else []

    for vrfdn in vrfDns:
        if not isValidDn(vrfdn, ['uni', 'tn-', 'ctx-']):
            parser.error("Invalid VRF DN {}. The correct VRF DN syntax is 'uni/tn-<tenant_name>/ctx-<vrf_name>'".format(vrfdn))
            sys.exit(1)

    for tenantdn in tenantDns:
        if not isValidDn(tenantdn, ['uni', 'tn-']):
            parser.error("Invalid Tenant DN {}. The correct Tenant DN syntax is 'uni/tn-<tenant_name>'".format(tenantdn))
            sys.exit(1)

    overlaps = []
    for vrf in vrfDns:
        for tenant in tenantDns:
            if vrf.startswith(tenant):
                overlaps.append((tenant, vrf))
    if overlaps:
        text = "Ambiguous input: VRF DNs should not belong to any of the selected Tenant DNs."
        text += "\nBoth --tenantdns and --vrfdns filters can be used together. When both are provided, the filters are combined using AND logic (not OR logic)."
        for tenant, vrf in overlaps:
            text += f"\n  - VRF {vrf} is inside tenant {tenant}"
        parser.error(text)
        sys.exit(1)

def dryRunParseDefine(childParser, **kwargs):
    dryRunParser = childParser.add_parser('dryrun',
                                          help='Dry-Run phase mode',
                                          aliases=kwargs.get('aliases', None))
    # Ensure we get only one of XML, JSON or DBXML inputs. Also ensures one of these arguments are provided.
    dryRunParserInGroup = dryRunParser.add_mutually_exclusive_group()
    dryRunParserInGroup.add_argument('--json',
                                     help='Configuration snapshot JSON file',
                                     default=None)
    dryRunParserInGroup.add_argument('--xml',
                                     help='Configuration snapshot XML file',
                                     default=None)
    dryRunParserInGroup.add_argument('--targz',
                                     help='Configuration snapshot TAR.GZ file',
                                     default=None)
    dryRunParserInGroup.add_argument('--dbxml',
                                     help='ifc_policydist.db.xml file coming from DB conversion phase [INTERNAL ONLY USE]',
                                     default=None)

    dryRunParser.add_argument('--disableNdMode',
                              help='Disable Nexus Dashboard compatibility mode.',
                              action='store_true')

    if '--fromApic' not in sys.argv:
        dryRunParser.add_argument('--apic',
                                help='APIC IP address or hostname to connect to')
        dryRunParser.add_argument('--username', help='Username for APIC')
        dryRunParser.add_argument('--password', help='Password for APIC')

    dryRunParser.add_argument('--mode',
                              help='Select the mode of analysis: optimized (default) or one-to-one',
                              choices=['optimized', 'one-to-one'],
                              default='optimized')
    dryRunParser.add_argument('--tenantdns',
                              help='Filter the analysis to all VRFs within the specified Tenants. Provide a comma-separated list of Tenant DNs (no spaces). Example: uni/tn-T1,uni/tn-T2. '
                                    'May be combined with --vrfdns; both filters apply using AND logic.',
                              type=str,
                              default="")
    dryRunParser.add_argument('--vrfdns',
                              help='Filter the analysis to the specified VRFs. Provide a comma-separated list of VRF DNs (no spaces). Example: uni/tn-T1/ctx-ctx1,uni/tn-T2/ctx-ctx2. '
                                    'May be combined with --tenantdns; both filters apply using AND logic.',
                              type=str,
                              default="")
    dryRunParser.add_argument('--outYaml',
                              help='YAML file in which we report the execution plan',
                              default="epg_to_esg_groups.yaml")
    dryRunParser.add_argument('--prefix',
                               help='Prefix to add to cloned names (default: empty). Example: contract name is "web" and prefix is "e", cloned contract will be named "e_web"',
                               type=str,
                               default="")
    dryRunParser.add_argument('--suffix',
                               help='Suffix to add to cloned names (default: e). Example: contract name is "web" and suffix is "e", cloned contract will be named "web_e"',
                               type=str,
                               default="e")
    dryRunParser.add_argument('--showStats',
                              help='Show statistics about the Fabric Config.',
                              action='store_true')

    dryRunParser.set_defaults(handle=dryRunFuncHandle)
    dryRunParser.set_defaults(validate=lambda args: dryRunValidate(args, dryRunParser))

def conversionFuncHandle(args):
    logger = logging.getLogger(globalValues['logger'])

    logger.info(colored("------------------------", bold=True))
    logger.info(colored("Conversion phase", bold=True))
    logger.info(colored("------------------------", bold=True))
    logger.info("""
During the conversion phase, the YAML execution plan generated during the dry run is processed and
converted into ACI configuration. The user is prompted to review and confirm the proposed changes
before they are applied.

By default, the configuration is pushed directly to the APIC. When the --noConfig flag is specified,
the configuration is not applied and is instead logged and saved to an output file.

The conversion can be executed either by connecting remotely to the APIC using provided credentials
or by running the tool directly on the APIC.

Two conversion configuration strategies are supported:
  - Interactive (default): EPGs and External EPGs are migrated one at a time.
  - VRF-based: all EPGs and External EPGs within the same VRF are migrated in a single transaction.

The generated configuration can be saved in XML or JSON format using the --outputFile option.
""")

    class LineNumberLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
        mapping['__line__'] = node.start_mark.line + 1  # 0-based → 1-based
        return mapping

    LineNumberLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping
    )

    # Open and read the YAML file
    if not os.path.exists(args.inYaml):
        logger.error(f"Input YAML file not found: {args.inYaml}")
        sys.exit(1)

    esgDataFromYaml = []
    contractConversionDescriptor = ContractConversionDescriptor()

    try:
        logger.info(f"Loading YAML file {args.inYaml}")
        with open(args.inYaml, 'r') as yaml_in:
            esgDataFromYaml = yaml.load(yaml_in, Loader=LineNumberLoader)
        if not esgDataFromYaml:
            raise ValueError("YAML file is empty")
        logger.info(f"Successfully read YAML file {args.inYaml}")
    except Exception as e:
        logger.error(f"Error reading YAML file {args.inYaml}: {e}")
        sys.exit(1)

    esgToVrfMap = {}
    perVrfPreExistingEsgMap = {}
    if not validateInputYamlData(esgDataFromYaml, esgToVrfMap):
        sys.exit(1)

    # Conversion on APIC with script execution on APIC
    node = apicLoginGetNodeAndVersionCheck(args)

    fabricDescriptor = {'nodeInfo': {},
                        'globalPcTagCount': 0,
                        'nodeWarnings': [], 'nodeCritical': [],
                        'vrfWithWarnings': set(), 'vrfWithCritical': set(),
                        'numVrfConversionWarning': 0,
                        'numVrfConversionCritical': 0
    }

    # Check current policy tcam utilization to determine installation mode
    capacityCheck(node, fabricDescriptor, esgDataFromYaml, args.noConfig)
    tcamOptimizedMode = True if fabricDescriptor['numVrfConversionCritical'] or fabricDescriptor['numVrfConversionWarning'] else False

    # Validate existing ESG to VRF mapping
    if validateESgToVrf(node, esgToVrfMap, perVrfPreExistingEsgMap) != ReturnCode.SUCCESS:
        logger.error("ESG to VRF mapping validation failed, aborting conversion")
        sys.exit(1)

    # Pre conversion health checks:
    # - Global PC Tag capacity
    if not preConversionHealthCheck(node, fabricDescriptor, esgToVrfMap):
        sys.exit(1)

    transactions = configpushPending(node)
    if transactions:
        logger.error("There {} {} pending transaction{}. Please wait for completion before running conversion phase."
                    .format("are" if transactions > 1 else "is", transactions, "s" if transactions > 1 else ""))
        sys.exit(1)

    # Create config snapshot before doing conversion
    if not args.noConfig:
        rc, snapshotStr = createCfgSnapshot(node, TOOL_NAME_STR + "_Preconversion_Config")
        if rc not in [ReturnCode.SUCCESS, ReturnCode.USERSKIPPED]:
            logger.error("Config snapshot creation failed, aborting conversion")
            sys.exit(1)

    # Validate and create clones of contracts. Post & binding to ESG will be done later
    if validateAndCloneContracts(node, esgDataFromYaml, contractConversionDescriptor) != ReturnCode.SUCCESS:
        logger.error("Contract validation failed, aborting conversion")
        sys.exit(1)

    try:
        generateConversionConfig(node, esgDataFromYaml, perVrfPreExistingEsgMap, args.outputFile, args.noConfig, \
                                tcamOptimizedMode, contractConversionDescriptor, ConfigStrategy(args.configStrategy))
    except KeyboardInterrupt:
        print("\n\n")
        logger.info("ESGMigrationAssistant conversion interrupted by user")
        if not args.noConfig:
            if snapshotStr:
                restoreCfgSnapshot(node, snapshotStr)
            else:
                logger.info("If needed, please use APIC rollback feature to restore the configuration to a previous state")
        sys.exit(1)


def conversionValidate(args, parser):
    if not args.fromApic:
        if args.apic:
            if not args.username or not args.password:
                parser.error("when using --apic, both --username and --password must be provided.")
                sys.exit(2)
        else:
            if args.username or args.password:
                parser.error("--username and --password can only be used with --apic.")
                sys.exit(2)

    if args.outputFile:
        if not (args.outputFile.endswith('.xml') or args.outputFile.endswith('.json')):
            parser.error("--outputFile must have either .xml or .json extension to save in respective format.")
            sys.exit(2)

def conversionParseDefine(childParser, **kwargs):
    conversionParser = childParser.add_parser('conversion',
                                              help='Conversion phase mode',
                                              aliases=kwargs.get('aliases', None))
    conversionParser.add_argument('--inYaml',
                                  help='YAML file in which we report the execution plan',
                                  default=None,
                                  required=True)

    apicCredentialsReqd = ('--fromApic' not in sys.argv)

    if '--fromApic' not in sys.argv:
        conversionParser.add_argument('--apic',
                                    help='APIC IP address or hostname to connect to',
                                    required=apicCredentialsReqd)
        conversionParser.add_argument('--username', help='Username for APIC')
        conversionParser.add_argument('--password', help='Password for APIC')

    conversionParser.add_argument('--noConfig',
                                  help='Proposed configuration is not applied to APIC',
                                  action='store_true',
                                  default=False)
    conversionParser.add_argument('--configStrategy',
                                  help='Select the configuration strategy mode: in interactive mode (default) EPGs/External EPGs are migrated one by one, in vrf mode all EPGs/External EPGs assigned to a single VRF are migrated in a single transaction',
                                  choices=[ConfigStrategy.INTERACTIVE.value, ConfigStrategy.VRF.value],
                                  default=ConfigStrategy.INTERACTIVE.value)
    conversionParser.add_argument('--outputFile',
                                  help='Output file for generated configuration (default: output.xml). Use .xml or .json extension to save in respective format',
                                  default="output.xml")
    conversionParser.set_defaults(handle=conversionFuncHandle)
    conversionParser.set_defaults(validate=lambda args: conversionValidate(args, conversionParser))


def cleanupFuncHandle(args):
    """
    List of items to cleanup
    1. EPG contracts + subtrees which have been cloned
    2. EPG subnets
    3. PBR - vnsLDevCtx + subtrees which have been cloned
    """
    logger = logging.getLogger(globalValues['logger'])

    logger.info(colored("-------------------------", bold=True))
    logger.info(colored("EPG cleanup phase", bold=True))
    logger.info(colored("-------------------------", bold=True))
    logger.info("""
During the cleanup phase, all selectors marked with a tagAnnotation during migration are analyzed.
These selectors may reference Application EPGs, External EPGs, vzAny objects, or the inband EPG.

For Application EPGs, all contract associations (fvRsProv, fvRsCons, fvRsIntraEpg, fvRsConsIf) and
shared services subnets (fvSubnet) are removed.
For External EPGs, all contract associations and external subnets (l3extSubnet) are removed.

After contract associations are removed, any contracts that are no longer referenced are deleted.
Associated vzAny, inband EPG, PBR Logical Device Context objects are also cleaned up.

The cleanup phase can be executed by connecting to the APIC using provided credentials.
By default, the configuration is pushed directly to the APIC. When the --noConfig flag is specified,
the configuration is not applied and is instead logged and saved to an output file.

Three cleanup configuration strategies are supported:
  - Interactive (default): EPGs and External EPGs are cleaned up individually.
  - VRF-based: all EPGs and External EPGs within the same VRF are cleaned up in a single transaction.
  - Global: all EPGs and External EPGs are cleaned up in a single transaction. This mode is not
    recommended unless used together with --noConfig.

The generated configuration can be saved in XML or JSON format using the --outputFile option.
""")

    if args.fromApic or args.apic:
        node = apicLoginGetNodeAndVersionCheck(args)
    else:
        logger.error("Cleanup phase must be run either from APIC or connected to APIC")
        sys.exit(1)

    transactions = configpushPending(node)
    if transactions:
        logger.error("There {} {} pending transaction{}. Please wait for completion before running cleanup phase."
                    .format("are" if transactions > 1 else "is", transactions, "s" if transactions > 1 else ""))
        sys.exit(1)

    # Create config snapshot before doing cleanup
    if not args.noConfig:
        rc, snapshotStr = createCfgSnapshot(node, TOOL_NAME_STR + "_Precleanup_Config")
        if rc not in [ReturnCode.SUCCESS, ReturnCode.USERSKIPPED]:
            logger.error("Config snapshot creation failed, aborting cleanup")
            sys.exit(1)

    try:
        generateCleanupConfig(node, args.outputFile, args.noConfig, ConfigStrategy(args.configStrategy))
    except KeyboardInterrupt:
        print("\n\n")
        logger.info("ESGMigrationAssistant cleanup interrupted by user")
        if not args.noConfig:
            if snapshotStr:
                restoreCfgSnapshot(node, snapshotStr)
            else:
                logger.info("If needed, please use APIC rollback feature to restore the configuration to a previous state")
        sys.exit(1)


def cleanupValidate(args, parser):
    if not args.fromApic:
        if args.apic:
            if not args.username or not args.password:
                parser.error("when using --apic, both --username and --password must be provided.")
                sys.exit(2)
        else:
            if args.username or args.password:
                parser.error("--username and --password can only be used with --apic.")
                sys.exit(2)
    if args.outputFile:
        if not (args.outputFile.endswith('.xml') or args.outputFile.endswith('.json')):
            parser.error("--outputFile must have either .xml or .json extension to save in respective format.")
            sys.exit(2)

def cleanupParseDefine(childParser, **kwargs):
    cleanupParser = childParser.add_parser('cleanup',
                                           help='Cleanup phase mode',
                                           aliases=kwargs.get('aliases', None))

    if '--fromApic' not in sys.argv:
        cleanupParser.add_argument('--apic',
                                help='APIC IP address or hostname to connect to',
                                required='--fromApic' not in sys.argv)
        cleanupParser.add_argument('--username', help='Username for APIC')
        cleanupParser.add_argument('--password', help='Password for APIC')

    cleanupParser.add_argument('--noConfig',
                                help='Proposed configuration is not applied to APIC',
                                action='store_true',
                                default=False)

    cleanupParser.add_argument('--configStrategy',
                               help='Select the configuration strategy mode: in interactive mode (default) EPGs/External EPGs are cleaned up one by one, in vrf mode all EPGs/External EPGs assigned to a single VRF are cleaned up in a single transaction, in global mode (not recommended unless noConfig option is used) all EPGs/External EPGs are cleaned up in a single transaction',
                               choices=[ConfigStrategy.INTERACTIVE.value, ConfigStrategy.VRF.value, ConfigStrategy.GLOBAL.value],
                               default=ConfigStrategy.INTERACTIVE.value)
    cleanupParser.add_argument('--outputFile',
                               help='Output file for generated configuration (default: output.xml). Use .xml or .json extension to save in respective format.',
                               default="output.xml")
    cleanupParser.set_defaults(handle=cleanupFuncHandle)
    cleanupParser.set_defaults(validate=lambda args: cleanupValidate(args, cleanupParser))

def defaultFuncHandle(args):
    print("No command invoked")


def xmlpost(self, message, *args, **kwargs):
    if self.isEnabledFor(XMLPOST_LEVEL_NUM):
        message = '\n' + (highlight(message, XmlLexer(), TerminalFormatter()))
        message = re.sub(r"\"deleted\"", f"{BOLD_RED}\"deleted\"{RESET}", message)
        self._log(XMLPOST_LEVEL_NUM, message, args, **kwargs)

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.CRITICAL: BOLD_RED,
        logging.ERROR: RED,
        logging.WARNING: YELLOW,
        logging.INFO: BLUE,
        XMLPOST_LEVEL_NUM: BOLD_MAGENTA,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        # Only colorize the levelname prefix
        record.levelname = f"{color}{record.levelname}:{RESET}"
        return super().format(record)

class SpinnerStopHandler(logging.Handler):
    def emit(self, record):
        spinner.stop()

def main():
    # Setup parser
    parser = argparse.ArgumentParser("ESGMigrationAssistant")
    parser.set_defaults(handle=defaultFuncHandle)

    # Section of arguments common to every submode
    parser.add_argument('--acimeta',
                        help='acimeta Location',
                        default="aci-meta.json")
    parser.add_argument('--fromApic',
                        help='Running it from APIC, by default we assume is being launched outside',
                        action='store_true')
    parser.add_argument('--logToFile',
                        help='File to log to',
                        default='ESGMigrationAssistant.log')
    parser.add_argument('--logLevel',
                        help='Level for logging info',
                        default='INFO',
                        choices=logging._nameToLevel.keys())
    parser.add_argument('--pdb',
                        help='In case of issues invoke pdb',
                        action="store_true",
                        default=False)

    subparsers = parser.add_subparsers(help='sub-command help')

    parserDefines = [
        # Dry-Run phase mode
        dryRunParseDefine,
        # Conversion phase mode
        conversionParseDefine,
        # Cleanup phase mode
        cleanupParseDefine
    ]

    # First lets collect all the commands info and the we register in order
    for parserDefine in parserDefines:
        stub = ParserStub(parserDefine)
        parserDefine(stub)
    # At this point the several ParserStub should have collected the
    # associtation "cmd" -> parserDefine function, so now we can register
    # with the real subparser in an ordered way
    visitedAliases = set()
    for cmd in sorted(globalValues['parserCommands'].keys()):
        aliasesFromCmd = []
        i = len(cmd)
        while i > MINCMDALIASLEN:
            subcmd = cmd[:i]
            if subcmd not in visitedAliases:
                aliasesFromCmd.append(subcmd)
                visitedAliases.add(subcmd)
            subcmd = subcmd.lower()
            if subcmd not in visitedAliases:
                aliasesFromCmd.append(subcmd)
                visitedAliases.add(subcmd)
            i = i - 1
        globalValues['parserCommands'][cmd](subparsers, aliases=aliasesFromCmd)

    args = parser.parse_args()

    if hasattr(args, "validate"):
        args.validate(args)

    # Configure root logging
    log_level = logging._nameToLevel[args.logLevel.upper()]
    globalValues['logger'] = "ESGMigrationAssistant"
    logger = logging.getLogger(globalValues['logger'])
    logger.handlers.clear()
    logger.setLevel(log_level)
    logger.propagate = False
    logging.addLevelName(XMLPOST_LEVEL_NUM, "XML POST")
    logging.Logger.xmlpost = xmlpost

    handler = SpinnerStopHandler()
    logger.addHandler(handler)

    # Configure console logging
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColorFormatter("%(levelname)s %(message)s"))
    logger.addHandler(console_handler)

    # Configure file logging
    if args.logToFile:
        file_handler = logging.FileHandler(args.logToFile, mode="w")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)

    logging.debug("Logging initialized.")
    logging.debug("Parsed arguments: {}".format(args))

    # PDB
    if args.pdb:
        pdb.set_trace()

    global inputHandler
    inputHandler = InputHandler()
    res = args.handle(args)
    if res is None:
        res = 0
    return res


if __name__ == "__main__":
    try:
        res = main()
        sys.exit(res)
    except KeyboardInterrupt:
        print("\n\nESGMigrationAssistant interrupted by user")
        spinner.stop()
        sys.exit(1)
