# ABSTRACT
This is the repository for a tool whose goal is to take an existing
ACI deployment using EPG (for networking and security meaning) and to
automate the process of moving the security portion from the EPG to
the ESG construct.

# PACKAGING
The tool is developed using python, as such there is no build needed,
just a packaging required. The tool is supposed to be launched
directly from the APIC SSH console itself, but in reality can be
launched by any place where python 3.12 mint installation is present
and there is out-of-band connectivity to one of the APICs controlling
the fabric.

In order to package the tool with dependencies just run from the
current directory the command:

```./zipTool```

the expected outcome is to generate a zip file under directory:

```./dist/ESGMigrationAssistant-<version>.zip```

This zip file it's supposed to be copied in the directory
/data/techsupport of an APIC (if the preferred method of running
directly from APIC is used). 

# EXECUTION
The user once on APIC can then follow these steps:

1. ```cd /data/techsupport```
2. ```unzip ESGMigrationAssistant-<version>.zip```
3. ```cd ESGMigrationAssistant-<version>```
4. ```./ESGMigrationAssistant <parameters>```

# ESGMigrationAssistant

The migration is implemented in three parts

1. Dryrun analyze the user config and group similar EPGs into ESGs. The analysis is outputted to a YAML file. Script usage is as follows -
```
./ESGMigrationAssistant dryrun --help
usage: ESGMigrationAssistant dryrun [-h] [--json JSON | --xml XML | --targz TARGZ | --dbxml DBXML] [--disableNdMode] [--apic APIC]
                                    [--username USERNAME] [--password PASSWORD] [--mode {optimized,one-to-one}]
                                    [--tenantdns TENANTDNS] [--vrfdns VRFDNS] [--outYaml OUTYAML] [--prefix PREFIX] [--suffix SUFFIX]

options:
  -h, --help            show this help message and exit
  --json JSON           Configuration snapshot JSON file
  --xml XML             Configuration snapshot XML file
  --targz TARGZ         Configuration snapshot TAR.GZ file
  --dbxml DBXML         ifc_policydist.db.xml file coming from DB conversion phase [INTERNAL ONLY USE]
  --disableNdMode       Disable Nexus Dashboard compatibility mode.
  --apic APIC           APIC IP address or hostname to connect to
  --username USERNAME   Username for APIC
  --password PASSWORD   Password for APIC
  --mode {optimized,one-to-one}
                        Select the mode of analysis: optimized (default) or one-to-one
  --tenantdns TENANTDNS
                        Filter analysis to all the VRFs configured inside to the specified Tenants. Use comma separated Tenant DNs without spaces. Example: uni/tn-T1,uni/tn-T2
  --vrfdns VRFDNS       Filter analysis to a subset of VRFs. Use comma separated VRF DNs without spaces. Example: uni/tn-T1/ctx-ctx1,uni/tn-T2/ctx-ctx2
  --outYaml OUTYAML     YAML file in which we report the execution plan
  --prefix PREFIX       Prefix to add to cloned names (default: empty). Example: contract name is "web" and prefix is "e", cloned contract will be named "e_web"
  --suffix SUFFIX       Suffix to add to cloned names (default: e). Example: contract name is "web" and suffix is "e", cloned contract will be named "web_e"
```

2. Conversion uses the YAML file (it can be edited by the user) and generate the migration configuration
```
./ESGMigrationAssistant conversion --help
usage: ESGMigrationAssistant conversion [-h] --inYaml INYAML --apic APIC [--username USERNAME] [--password PASSWORD] [--noConfig]
                                        [--configStrategy {interactive,vrf}] [--outputFile OUTPUTFILE]

options:
  -h, --help            show this help message and exit
  --inYaml INYAML       YAML file in which we report the execution plan
  --apic APIC           APIC IP address or hostname to connect to
  --username USERNAME   Username for APIC
  --password PASSWORD   Password for APIC
  --noConfig            Proposed configuration is not applied to APIC
  --configStrategy {interactive,vrf}
                        Select the configuration strategy mode: in interactive mode (default) EPGs/External EPGs are migrated one by one, in vrf
                        mode all EPGs/External EPGs assigned to a single VRF are migrated in a single transaction
  --outputFile OUTPUTFILE
                        Output file for generated configuration (default: output.xml). Use .xml or .json extension to save in respective format
```

3. Cleanup phase
```
./ESGMigrationAssistant cleanup --help
usage: ESGMigrationAssistant cleanup [-h] --apic APIC [--username USERNAME] [--password PASSWORD] [--noConfig]
                                     [--configStrategy {interactive,vrf,global}] [--outputFile OUTPUTFILE]

options:
  -h, --help            show this help message and exit
  --apic APIC           APIC IP address or hostname to connect to
  --username USERNAME   Username for APIC
  --password PASSWORD   Password for APIC
  --noConfig            Proposed configuration is not applied to APIC
  --configStrategy {interactive,vrf,global}
                        Select the configuration strategy mode: in interactive mode (default) EPGs/External EPGs are cleaned up one by one, in vrf
                        mode all EPGs/External EPGs assigned to a single VRF are cleaned up in a single transaction, in global mode (not
                        recommended unless noConfig option is used) all EPGs/External EPGs are cleaned up in a single transaction
  --outputFile OUTPUTFILE
                        Output file for generated configuration (default: output.xml). Use .xml or .json extension to save in respective format.
```