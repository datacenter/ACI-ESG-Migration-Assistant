import sys
from collections import defaultdict
import re
import json
import pdb
import functools
import logging
import pyaci
from xml import etree
import pytz
import threading
import itertools
import time

class RemoteCommandMo(pyaci.core.Mo):
    """
    Class that can be used in pyaci to send a command list to a switch, here is a sample code on how to use it:

    node = pyaci.core.Node("hostname_or_ip", aciMetaFilePath="/path/.aci-meta/aci-meta.json")
    node.methods.Login("admin", "password").POST()
    remCmdList = RemoteCommandMo(node, 101)
    remCmdList.moCommand(id="1", cmdtype="vsh", cmd="clear system internal epm endpoint remote all")
    print(remCmdList.Xml)
    remCmdList.POST()
    """
    def __init__(self, api, nodeId):
        super(RemoteCommandMo, self).__init__(api, "moCmdList", api._aciClassMetas)
        self._properties['nodeid'] = str(nodeId)

    def _isTopRoot(self):
        return self._className == 'moCmdList'

    @property
    def _relativeUrl(self):
        if self._className == 'moCmdList':
            return 'remotecommand'
        else:
            return self.Rn


# Helper function to extract name from a DN (e.g., "tn-TenantA" -> "TenantA")
@functools.cache
def getNameFromDn(dn_string):
    parts = dn_string.split('/')
    for part in reversed(parts):
        if '-' in part:
            return part.split('-', 1)[1]
    return dn_string

@functools.cache
def getMgmtPFromDn(dn_string):
    parts = dn_string.split('/')
    for part in parts:
        if part.startswith('mgmtp-'):
            return part[6:]
    return None

@functools.cache
def getTenantFromDn(dn):
    """
    Extracts the tenant name from a distinguished name (DN).
    The DN is expected to be in the format:
    "uni/tn-<tenant_name>/..."
    """
    parts = dn.split('/')
    for part in parts:
        if part.startswith('tn-'):
            return part[3:]  # Return the tenant name without 'tn-'
    return None  # Return None if no tenant found

@functools.cache
def getAppProfileFromDn(dn):
    """
    Extracts the application profile name from a distinguished name (DN).
    The DN is expected to be in the format:
    ".../ap-<appProfileName>/..."
    """
    parts = dn.split('/')
    for part in parts:
        if part.startswith('ap-'):
            return part[3:]  # Return the tenant name without 'ap-'
    return None  # Return None if no AP found

@functools.cache
def getL3OutFromDn(dn):
    """
    Extracts the L3Out name from a distinguished name (DN).
    The DN is expected to be in the format:
    ".../out-<l3OutName>/..."
    """
    parts = dn.split('/')
    for part in parts:
        if part.startswith('out-'):
            return part[4:]  # Return the tenant name without 'out-'
    return None  # Return None if no L3Out found

@functools.cache
def getNodeIdFromDn(dn):
    """
    Extracts the nodeId name from a distinguished name (DN).
    The DN is expected to be in the format:
    ".../node-<nodeId>/..."
    """
    match = re.search(r"/node-(\d+)", dn)
    if match:
        return match.group(1)
    return None  # Return None if no nodeId found

@functools.cache
def getPodIdFromDn(dn):
    """
    Extracts the podId name from a distinguished name (DN).
    The DN is expected to be in the format:
    ".../pod-<podId>/..."
    """
    match = re.search(r"/pod-(\d+)", dn)
    if match:
        return match.group(1)
    return None  # Return None if no podId found

def isValidDn(dn, rnList):
    """
    Validates if the given DN matches the expected RN list structure.
    Example usage:
    dn = "uni/tn-foo/ap-ap1/epg-e1"
    rnList = ["uni", "tn-", "ap-", "epg-"]
    isValidDn(dn, rnList) -> True
    """
    segments = []
    parts = dn.split("/")
    for part in parts:
        if '-' not in part:
            segments.append(part)
        else:
            match = re.match(r"^([^-]+)-[^/]+$", part)
            if not match:
                return False
            segments.append(match.group(1) + '-')
    if segments != rnList:
        return False
    return True

def getNewContractDn(newName, contractDn):
    """
    Given a contract DN and a new name, generate a new contract DN
    by replacing the contract name in the DN with the new name.
    Example:
    contractDn = "uni/tn-foo/brc-oldName"
    newName = "newName"
    getNewContractDn(newName, contractDn) -> "uni/tn-foo/brc-newName"
    """
    return (contractDn.rsplit('/', 1))[0] + '/brc-' + newName

def getNewContractIfDn(newName, contractIfDn):
    """
    Given a contract DN and a new name, generate a new contract DN
    by replacing the contract name in the DN with the new name.
    Example:
    contractIfDn = "uni/tn-foo/cif-oldName"
    newName = "newName"
    getNewContractIfDn(newName, contractIfDn) -> "uni/tn-foo/cif-newName"
    """
    return (contractIfDn.rsplit('/', 1))[0] + '/cif-' + newName

def getRelationDescription():
    relationDesc = {
        'fvRsBd': {'targetClass': 'fvBD', 'namingProperty': 'tnFvBDName', 'rtClass': 'fvRtBd', 'rnFormat': 'rtbd-'},
        'fvRsCtx': {'targetClass': 'fvCtx', 'namingProperty': 'tnFvCtxName', 'rtClass': 'fvRtCtx', 'rnFormat': 'rtctx-'},
        'fvRsScope': {'targetClass': 'fvCtx', 'namingProperty': 'tnFvCtxName', 'rtClass': 'fvRtScope', 'rnFormat': 'rtscope-'},
        'l3extRsEctx': {'targetClass': 'fvCtx', 'namingProperty': 'tnFvCtxName', 'rtClass': 'fvRtEctx', 'rnFormat': 'rtl3extEctx-'},
        'fvRsProv': {'targetClass': 'vzBrCP', 'namingProperty': 'tnVzBrCPName', 'rtClass': 'vzRtProv', 'rnFormat': 'rtfvProv-'},
        'fvRsCons': {'targetClass': 'vzBrCP', 'namingProperty': 'tnVzBrCPName', 'rtClass': 'vzRtCons', 'rnFormat': 'rtfvCons-'},
        'fvRsIntraEpg': {'targetClass': 'vzBrCP', 'namingProperty': 'tnVzBrCPName', 'rtClass': 'vzRtIntraEpg', 'rnFormat': 'rtfvIntraEpg-'},
        'fvRsConsIf': {'targetClass': 'vzCPIf', 'namingProperty': 'tnVzCPIfName', 'rtClass': 'vzRtConsIf', 'rnFormat': 'rtfvConsIf-'},
        'vzRsIf': {'targetClass': 'vzBrCP', 'rtClass': 'vzRtIf', 'rnFormat': 'rtif-'},
        'vzRsAnyToProv': {'targetClass': 'vzBrCP', 'namingProperty': 'tnVzBrCPName', 'rtClass': 'vzRtAnyToProv', 'rnFormat': 'rtanyToProv-'},
        'vzRsAnyToCons': {'targetClass': 'vzBrCP', 'namingProperty': 'tnVzBrCPName', 'rtClass': 'vzRtAnyToCons', 'rnFormat': 'rtanyToCons-'},
        'vzRsAnyToConsIf' : {'targetClass': 'vzCPIf', 'namingProperty': 'tnVzCPIfName', 'rtClass': 'vzRtAnyToConsIf', 'rnFormat': 'rtanyToConsIf-'},
        'mgmtRsMgmtBD': {'targetClass': 'fvBD', 'namingProperty': 'tnFvBDName', 'rtClass': 'fvRtMgmtBD', 'rnFormat': 'rtmgmtMgmtBD-'},
        'vzRsSubjFiltAtt': {'targetClass': 'vzFilter', 'namingProperty': 'tnVzFilterName', 'rtClass': 'vzRtSubjFiltAtt', 'rnFormat': 'rtsubjFiltAtt-'},
    }
    return relationDesc

def makeDn(classID, tenantName, name):
    """
    Helper function to create a DN given a tenant name and a name
    """
    if classID == "vzBrCP":
        return "uni/tn-{}/brc-{}".format(tenantName, name)
    elif classID == "vzCPIf":
        return "uni/tn-{}/cif-{}".format(tenantName, name)
    elif classID == "fvBD":
        return "uni/tn-{}/BD-{}".format(tenantName, name)
    elif classID == "fvCtx":
        return "uni/tn-{}/ctx-{}".format(tenantName, name)
    elif classID == "vzFilter":
        return "uni/tn-{}/flt-{}".format(tenantName, name)
    else:
        reportAFailure("Unsupported classID: {}".format(classID))

def tzAware(dt):
    """
    Check if a time object is tz aware or no
    """
    return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None


def makeTzAware(dt):
    """
    Make a timestamp TZ aware assuming UTC
    """
    if not tzAware(dt):
        return dt.replace(tzinfo=pytz.utc)
    return dt


def tree():
    """
    Define a tree like structure
    """
    return defaultdict(tree)


globalValues = tree()

def catchException(fn):
    """
    A decorator that wraps the passed in function and logs
    exceptions should one occur
    """
    @functools.wraps(fn)
    def wrapperFn(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if globalValues['usepdb']:
                pdb.post_mortem()
            logger = logging.getLogger(globalValues['logger'])
            logger.error("Error while executing function:{} with args:{} kargs:{}".format(fn, args, kwargs))
            logger.exception(e)
    return wrapperFn


def reportAFailure(msg):
    if globalValues['usepdb']:
        pdb.post_mortem()
    else:
        raise Exception(msg)


def setupPdb(args):
    """
    Routine to setup the PDB as normally used in scripts
    """
    globalValues['usepdb'] = args.pdb


@functools.cache
def parseDnStr(dnStr, returnList=False):
    '''
    Routine that will split a dn formatted string for example:
    uni/tn-foo/ap-ap1/epg-e1/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/1]]
    in a dictionary with:
    {
    'uni': ''
    'tn': 'foo'
    'ap': 'ap1'
    'epg': 'e1'
    'rspathAtt': '[topology/pod-1/paths-101/pathep-[eth1/1]]'
    }
    if the same routine is executed again on:
    'topology/pod-1/paths-101/pathep-[eth1/1]'
    that would yield:
    {
    'topology': ''
    'pod': '1'
    'paths': '101'
    'pathep': '[eth1/1]'
    }
    if returnList parameter is TRUE instead of a dictionary a list of
    the dn parts will be returned
    '''

    def matches(line):
        '''
        Matches the top level pairs of [] so for example in a string
        like:
        '[foo]/[[baz]]'
        will return the position of:
        [ {'start': 1, 'end': 4},
          {'start': 7, end: '12'} ]
        this because will match the content of '[foo]' that is 'foo'
        and the content of '[[baz]]' which is '[baz]' ignoring any
        level of nesting below. The list returned will be in such a
        way that will start from the lower positions
        '''
        stack = []
        retList = []
        import re
        for m in re.finditer(r'[\[\]]', line):
            pos = m.start()
            if line[pos-1] == '\\':
                continue
            c = line[pos]
            if c == '[':
                stack.append(pos+1)
            elif c == ']':
                if len(stack) > 0:
                    prevpos = stack.pop()
                    # Report the top level pairs
                    if len(stack) == 0:
                        retItem = {}
                        retItem['start'] = prevpos
                        retItem['end'] = pos
                        retList.append(retItem)
                else:
                    errStr = "extraneous closing quote at pos {}: '{}'"
                    raise ValueError(errStr.format(pos, line[pos:]))
        if len(stack) > 0:
            for pos in stack:
                errStr = "expecting closing quote to match open quote at: '{}'"
                raise ValueError(errStr.format(line[pos-1:]))
        return retList

    res = {}
    resList = []
    if dnStr is None:
        return res
    # Make sure it's a string
    dnStr = str(dnStr)
    topLevelMatches = matches(dnStr)
    dnStrStrippedList = []
    piecesToReinsert = {}
    prevEnd = 0
    for match in topLevelMatches:
        currStart = match['start']
        currEnd = match['end']
        dnStrStrippedList.append(dnStr[prevEnd:currStart])
        bookmark = 'start{}'.format(currStart)
        # Now add a bookmark so we can readd what we are trimming off
        dnStrStrippedList.append('{')
        dnStrStrippedList.append(bookmark)
        dnStrStrippedList.append('}')
        piecesToReinsert[bookmark] = dnStr[currStart:currEnd]
        prevEnd = currEnd
    # Attach the rest of the string
    dnStrStrippedList.append(dnStr[prevEnd:])
    dnStrStripped = ''.join(dnStrStrippedList)
    # Split the string yanked of the inner [] content because that
    # string would contain '/' which would cause wrong parsing of the
    # level
    rnList = dnStrStripped.split('/')
    for rn in rnList:
        resList.append(rn.format(**piecesToReinsert))
        # Split only the first - if present
        rnKeyVal = rn.split('-', 1)
        # Now lets compile the result where we can have just a key or
        # a key/value in both the cases there could be a marker like
        # [{start<X>}] that need to be refilled with the pieces we
        # yanked before the split
        if len(rnKeyVal) == 1:
            res[rnKeyVal[0].format(**piecesToReinsert)] = ''
        if len(rnKeyVal) == 2:
            res[rnKeyVal[0].format(**piecesToReinsert)] = rnKeyVal[1].format(
                **piecesToReinsert)
        # In other cases, we silently ignore it, field is malformed
    if returnList:
        return resList
    else:
        return res


def chomp(x):
    if x.endswith("\r\n"):
        return x[:-2]
    if x.endswith("\n") or x.endswith("\r"):
        return x[:-1]
    return x


class Mo(object):
    def __init__(self, mit, dn, className, propertiesDict):
        self._mit = mit
        self._dn = dn
        self._className = className
        self._properties = dict(propertiesDict)
        self._aciClassMeta = self._mit._aciClassMetas[self._className]

    def __eq__(self, other):
        """Check if 2 MOs are the same"""
        if isinstance(other, Mo):
            if self._dn != other._dn:
                return False
            if self._className != other._className:
                return False
            if self._properties != other._properties:
                return False
        else:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        resParts = []
        resParts.append("{}({})".format(self._dn, self._className))
        for prop in sorted(self._properties):
            resParts.append("{}:{}".format(prop,
                                           self._properties.get(prop, '<NONE>')))
        return ','.join(resParts)

    def deltaStr(self, other, skipProps=[]):
        """
        Return the delta in the properties
        """
        resParts = []
        if self._dn != other._dn:
            return "This Dn: {} Other Dn: {}".format(self._dn, other._dn)
        if self._className != other._className:
            return "This Class: {} Other Class: {}".format(self._className, other._className)
        allProps = set()
        allProps.update(self._properties)
        allProps.update(other._properties)
        for prop in sorted(allProps):
            if prop in skipProps:
                continue
            selfProp = self._properties.get(prop, '<NONE>')
            otherProp = other._properties.get(prop, '<NONE>')
            if selfProp == otherProp:
                continue
            resParts.append("({}):F[{}]:T[{}]".format(prop,
                                                      selfProp,
                                                      otherProp))
        if resParts:
            return "Mismatched Props: {}".format(','.join(resParts))

    @property
    def ClassName(self):
        return self._className

    @property
    def Dn(self):
        return self._dn

    @property
    def Parent(self):
        dnParts = parseDnStr(self._dn, returnList=True)
        if len(dnParts) == 1:
            # Return topRoot
            return self._mit.lookupByDn("")
        parentDn = "/".join(dnParts[0:-1])
        return self._mit.lookupByDn(parentDn)

    def getParentByClass(self, className):
        parentMo = self.Parent
        while parentMo.Dn != "":
            if parentMo.ClassName == className:
                return parentMo
            parentMo = parentMo.Parent
        return None

    @property
    def Children(self):
        dnParts = parseDnStr(self._dn, returnList=True)
        currLevel = self._mit._tree
        if not self.isTopRoot:
            for dnPart in dnParts:
                currLevel = currLevel[dnPart]
        res = []
        for rn, value in currLevel.items():
            if rn == '__mo__':
                # This is the MO itself we want the children
                continue
            mo = value.get('__mo__', None)
            if mo is None:
                continue
            # Nobody can contain topRoot
            if mo.isTopRoot:
                continue
            res.append(mo)
        return res

    @property
    def isTopRoot(self):
        return (self.Dn == "" and self.ClassName == "topRoot")

    @property
    def Status(self):
        return self._properties['status']

    def getProp(self, propName):
        if self._aciClassMeta['properties'].get(propName, None) is None:
            reportAFailure("No property named: {} in MO of class: {}".format(propName,
                                                                             self.ClassName))
        return self._properties.get(propName, None)

    def setProp(self, propName, propValue):
        if self._aciClassMeta['properties'].get(propName, None) is None:
            reportAFailure("No property named: {} in MO of class: {}".format(propName,
                                                                             self.ClassName))
        if propName in ['dn', 'rn'] or propName in self._aciClassMeta['identifiedBy']:
            reportAFailure("Cannot change naming property {} in MO of class: {}".format(propName,
                                                                                        self.ClassName))
        if propName in ['tDn']:
            self._properties[propName] = propValue

        return self._properties.get(propName, None)

    @property
    def PropertyNames(self):
        return sorted(self._properties.keys())

    @property
    def NonEmptyPropertyNames(self):
        return sorted([k for k, v in self._properties.items()
                       if v is not None])

    @property
    def IsConfigurable(self):
        return self._mit._aciClassMeta[self._className]['isConfigurable']

    def IsConfigurableProperty(self, name):
        return (name in self._aciClassMeta['properties'] and
                self._aciClassMeta['properties'][name]['isConfigurable'])

    @property
    def Json(self):
        return json.dumps(self._dataDict(),
                          sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def Xml(self):
        def element(mo):
            result = etree.ElementTree.Element(mo._className)

            for key, value in mo._properties.items():
                if value is not None:
                    result.set(key, value)

            for child in mo.Children:
                result.append(element(child))

            return result

        root = element(self)
        etree.ElementTree.indent(root)
        return etree.ElementTree.tostring(root, encoding="unicode")

    def _dataDict(self):
        data = {}
        objectData = {}
        data[self._className] = objectData

        attributes = {
            k: v
            for k, v in self._properties.items()
            if v is not None
        }
        if attributes:
            objectData['attributes'] = attributes

        if self._children:
            objectData['children'] = []

        for child in self.Children:
            objectData['children'].append(child._dataDict())

        return data


class Mit(object):
    def __init__(self, aciMetaFilePath):
        if aciMetaFilePath is not None:
            with open(aciMetaFilePath, 'rb') as f:
                logger = logging.getLogger(globalValues['logger'])
                logger.debug('Loading meta information from %s',
                             aciMetaFilePath)
                aciMetaContents = json.load(f)
                self._aciClassMetas = aciMetaContents['classes']
        else:
            reportAFailure('ACI meta was not specified !')
        self._aciClassDB = defaultdict(defaultdict)
        # aciDnDB is the DB of all the MO keyed by their DN
        self._aciDnDB = dict()
        self._tree = tree()
        # Add the topRoot
        self.addMo("", "topRoot", {})

    def lookupByDn(self, dn):
        return self._aciDnDB.get(dn, None)

    def lookupByClass(self, className):
        mos = self._aciClassDB.get(className, None)
        if mos is not None:
            return mos.items()
        return None

    @property
    def Xml(self):
        return self.TopRoot.Xml

    @property
    def Json(self):
        return self.TopRoot.Json

    @property
    def TopRoot(self):
        return self.lookupByDn("")

    def addMo(self, dn, className, propertiesDict):
        mo = self.lookupByDn(dn)
        if mo is None:
            # Check if the parents are all present
            mo = Mo(self, dn, className, propertiesDict)
            self._aciDnDB[dn] = mo
            self._aciClassDB[className][dn] = mo
            dnParts = parseDnStr(dn, returnList=True)
            currLevel = self._tree
            for dnPart in dnParts:
                currLevel = currLevel[dnPart]
            currLevel["__mo__"] = mo
        return mo


class ParserStub(object):
    """
    Class used to collect the command names registered, so we can do some manipulation
    """
    def __init__(self, fn):
        if globalValues.get('parserCommands', None) is None:
            globalValues['parserCommands'] = {}
        self._fn = fn

    def add_parser(self, cmd, **kwargs):
        globalValues['parserCommands'][cmd] = self._fn
        return ParserStub(self._fn)

    def set_defaults(self, *args, **kwargs):
        pass

    def add_argument(self, *args, **kwargs):
        pass

    def add_mutually_exclusive_group(self, *args, **kwargs):
        return ParserStub(self._fn)


class Spinner:
    def __init__(self, text="Processing"):
        self._text = text
        self._maxLen = len(text)
        self._running = False
        self._thread = None

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, newText):
        self._text = newText
        self._maxLen = len(newText) if len(newText) > self._maxLen else self._maxLen
        # Restart spinner every time text is set
        self.start()

    def start(self):
        if self._running:
            self.stop()
        self._running = True
        self._thread = threading.Thread(target=self._spin)
        self._thread.start()

    def _spin(self):
        for char in itertools.cycle("|/-\\"):
            if not self._running:
                break
            sys.stdout.write(f"\r{self._text} {char}")
            sys.stdout.flush()
            time.sleep(0.2)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join()
        sys.stdout.write("\r" + " " * (self._maxLen + 2) + "\r")
        sys.stdout.flush()

spinner = Spinner()


if __name__ == "__main__":
    print("{} can only be included".format(__file__))
    sys.exit(-1)
