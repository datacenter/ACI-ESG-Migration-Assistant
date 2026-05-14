# ABSTRACT
This is the repository for a tool whose goal is to take an existing
ACI deployment using EPG (for networking and security meaning) and to
automate the process of moving the security portion from the EPG to
the ESG construct.

# EXECUTION OPTIONS

## Option 1: Run from the APIC CLI

On your machine (copy the zip file to your APIC):
1. ```git clone git@github.com:datacenter/ACI-ESG-Migration-Assistant.git```
2. ```cd ACI-ESG-Migration-Assistant```
3. ```scp ESGMigrationAssistant-<version>.zip admin@<your-APIC-IP>:/data/techsupport```

Then, on your APIC:
1. ```cd /data/techsupport```
2. ```unzip ESGMigrationAssistant-<version>.zip```
3. ```cd ESGMigrationAssistant-<version>```
4. ```./ESGMigrationAssistant <parameters>```

> [!TIP]
> On APIC version 6.2(2)+, you do not need to follow these procedures unless the pre-packaged one is outdated because ESG Migration Assistant is pre-packaged under `/data/esgmigration/`.

## Option 2: Run from your machine

1. ```git clone git@github.com:datacenter/ACI-ESG-Migration-Assistant.git```
2. ```cd ACI-ESG-Migration-Assistant```
3. ```./zipTool```
4. ```cd build/ESGMigrationAssistant-<version>```
5. ```./ESGMigrationAssistant <parameters>```

> [!NOTE]
> Python 3.12+ is required.
> 
> `zipTool` installs the python dependencies into
> `./build/ESGMigrationAssistant-<version>/deps` based on the `requirements.txt`.
>
> It also packages them along with `./src` into `./dist/ESGMigrationAssistant-<version>.zip`
> which may or may not be the same as the pre-packaged zip file in this repository (`./ESGMigrationAssistant-<version>.zip`).
> The libraries used for the dependencies could vary depedning on your machine and its python version.
> The pre-packaged zip file in this repository (`./ESGMigrationAssistant-<version>.zip`) was packaged with python 3.12
> to be copied and ran directly on the APIC CLI.

# ESGMigrationAssistant

The migration is implemented in three parts

1. Dryrun analyze the user config and group similar EPGs into ESGs. The analysis is outputted to a YAML file. Script usage is as follows -
```
./ESGMigrationAssistant dryrun --help
usage: ESGMigrationAssistant dryrun [-h] [--json JSON | --xml XML | --targz TARGZ | --dbxml DBXML] [--disableNdMode]
                                    [--apic APIC] [--username USERNAME] [--password PASSWORD] [--mode {optimized,one-to-one}]
                                    [--tenantdns TENANTDNS] [--vrfdns VRFDNS] [--tenantRegex TENANTREGEX] [--outYaml OUTYAML]
                                    [--prefix PREFIX] [--suffix SUFFIX] [--showStats]

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
                        Filter the analysis to all VRFs within the specified Tenants. Provide a comma-separated list of Tenant DNs (no spaces).
                        Example: uni/tn-T1,uni/tn-T2. May be combined with other filters; all filters apply using UNION logic.
  --vrfdns VRFDNS       Filter the analysis to the specified VRFs. Provide a comma-separated list of VRF DNs (no spaces).
                        Example: uni/tn-T1/ctx-ctx1,uni/tn-T2/ctx-ctx2. May be combined with other filters; all filters apply using UNION logic.
  --tenantRegex TENANTREGEX
                        Filter by tenant name. Provide a comma-separated list of names or regex (no spaces). Wrap the tenantRegex with quotes.
                        Example: "T1,T2,Prod.*,Test[0-9]+". May be combined with other filters; all filters apply using UNION logic.
  --outYaml OUTYAML     YAML file in which we report the execution plan
  --prefix PREFIX       Prefix to add to cloned names (default: empty). Example: contract name is "web" and prefix is "e", cloned contract will be named "e_web"
  --suffix SUFFIX       Suffix to add to cloned names (default: e). Example: contract name is "web" and suffix is "e", cloned contract will be named "web_e"
  --showStats           Show statistics about the Fabric Config.
```

2. Conversion uses the YAML file (it can be edited by the user) and generate the migration configuration
```
./ESGMigrationAssistant conversion --help
usage: ESGMigrationAssistant conversion [-h] --inYaml INYAML --apic APIC [--username USERNAME] [--password PASSWORD] 
                                        [--noConfig] [--configStrategy {interactive,vrf}] [--outputFile OUTPUTFILE]

options:
  -h, --help            show this help message and exit
  --inYaml INYAML       YAML file in which we report the execution plan
  --apic APIC           APIC IP address or hostname to connect to
  --username USERNAME   Username for APIC
  --password PASSWORD   Password for APIC
  --noConfig            Proposed configuration is not applied to APIC
  --configStrategy {interactive,vrf}
                        Select the configuration strategy mode: in interactive mode (default) EPGs/External EPGs are migrated one by one, in vrf mode all EPGs/External EPGs assigned to a single VRF are migrated in a single transaction
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
                        Select the configuration strategy mode: in interactive mode (default) EPGs/External EPGs are cleaned up one by one, in vrf mode all EPGs/External EPGs assigned to a single VRF are cleaned up in a single transaction, in global mode (not recommended unless noConfig option is used) all EPGs/External EPGs are cleaned up in a single transaction
  --outputFile OUTPUTFILE
                        Output file for generated configuration (default: output.xml). Use .xml or .json extension to save in respective format.
```