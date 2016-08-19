#!/urs/bin/env python
import acitoolkit.acitoolkit as ACI



# Create the Tenant
tenant = ACI.Tenant('AF_Prog_Test')
print tenant.get_json()
print "\n"

# Create the Application Profile
app = ACI.AppProfile('ASA', tenant)

# Create the EPG
epg = ACI.EPG('WEB_FARM', app)
epg2 = ACI.EPG('USERS', app)


# Create a Contract for Users and Web_Farm

# Create a Context and BridgeDomain
context = ACI.Context('INTERNAL', tenant)

print context.get_json()
print "\n"

bd1 = ACI.BridgeDomain('WEB_Inside', tenant)
bd1.add_context(context)
bd2 = ACI.BridgeDomain('USER_Inside', tenant)
bd2.add_context(context)

# Place the EPG in the BD
epg.add_bd(bd1)
epg2.add_bd(bd2)

#Create Contract
contract = ACI.Contract('WEB-to-Users', tenant)

						 
# Assign Contracts to EPG

epg.provide(contract)
epg2.consume(contract)
						
# Declare 2 physical interfaces
if1 = ACI.Interface('eth', '1', '101', '1', '15')
#print if1.get_json()

if2 = ACI.Interface('eth', '1', '101', '1', '16')
#print if2.get_json()

# Create VLAN 5 on the physical interfaces
vlan_on_if1 = ACI.L2Interface('vlan2005_on_if1', 'vlan', '2005')
vlan_on_if1.attach(if1)

vlan_on_if2 = ACI.L2Interface('vlan2006_on_if2', 'vlan', '2006')
vlan_on_if2.attach(if2)

# Attach the EPG to the VLANs
epg.attach(vlan_on_if1)
epg2.attach(vlan_on_if2)

# Get the APIC login credentials
description = 'acitoolkit tutorial application'
creds = ACI.Credentials('apic', description)
creds.add_argument('--delete', action='store_true',
                   help='Delete the configuration from the APIC')
args = creds.get()

# Delete the configuration if desired
if args.delete:
    tenant.mark_as_deleted()

# Login to APIC and push the config
session = ACI.Session(args.url, args.login, args.password)
session.login()
resp = tenant.push_to_apic(session)

if resp.ok:
    print 'Success'

# Print what was sent
print 'Pushed the following JSON to the APIC'
#print 'URL:', tenant.get_url()
#print 'JSON:', tenant.get_json()
