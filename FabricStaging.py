#!/usr/bin/env python
#!C:\Python27\python

import cobra.model.cdp as cdpIfPol
import cobra.model.lldp as lldpIfPol
import cobra.model.mcp as mcpIfPol
import requests
import time
import cobra.model.snmp as SNMP
import cobra.model.datetime as DateTime
import cobra.model.fabric as Fabric
from random import random
from clint.textui import progress
from cobra.mit.access import MoDirectory
from cobra.mit.request import ConfigRequest, DnQuery, LoginSession
from cobra.model.fabric import ProtPol, ExplicitGEp, RsVpcInstPol, NodePEp, Inst, HIfPol
from cobra.model.aaa import UserEp, TacacsPlusEp, TacacsPlusProvider, RsSecProvToEpg, TacacsPlusProviderGroup, ProviderRef, RadiusProvider, RadiusEp, RadiusProviderGroup, User, UserDomain, UserRole
from cobra.model.fv import AEPg, Ap, BD, Ctx, RsBd, RsCtx, RsDomAtt, RsPathAtt, Subnet, Tenant
from cobra.model.fvns import VlanInstP, EncapBlk
from cobra.model.infra import AccBndlGrp, AccPortGrp, AccPortP, AttEntityP, FuncP, HPortS, Infra, LeafS, NodeBlk, NodeP, PortBlk, RsAccBaseGrp, RsAccPortP, RsAttEntP
from cobra.model.infra import RsCdpIfPol, RsDomP, RsHIfPol, RsL2IfPol, RsLacpPol, RsLldpIfPol, RsMcpIfPol, RsMonIfInfraPol, RsVlanNs
from cobra.model.lacp import LagPol
from cobra.model.phys import DomP
from cobra.model.pol import Uni
from cobra.model.vmm import CtrlrP, DomP, ProvP, RsAcc, UsrAccP
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from cobra.internal.codec.xmlcodec import toXMLStr

# ------------  KEEP THIS ------------ #
def apic_login(host, user, password):
	apicUrl = 'https://%s' % (host)
	moDir = MoDirectory(LoginSession(apicUrl, user, password))
	moDir.login()
	return moDir
# ------------  KEEP THIS ------------ #
def cfg_commit(moDir,object):
	Cfg = ConfigRequest()
	Cfg.addMo(object)
	moDir.commit(Cfg)
# ------------  EASY BUILD ------------ #
def local_user(host,user,password):

	moDir = apic_login(host, user, password)

	polUni = Uni('')
	aaaUserEp = UserEp(polUni)
	
	#Variable Section - Customize as needed#
	Username='presidio'
	Password='Pr3s1d10!'
	FName=''
	LName=''
	ActStatus='active'
	#--------------------------------------#

	aaaUser = User(aaaUserEp,
					expires=u'no',
					firstName=FName,
					descr=u'',
					lastName=LName,
					clearPwdHistory=u'no',
					accountStatus=ActStatus,
					phone=u'',
					pwdLifeTime=u'no-password-expire',
					expiration=u'never',
					ownerTag=u'',
					email=u'',
					name=Username,
					pwd=Password)
	
	aaaUserDomain = UserDomain(aaaUser,
								ownerKey=u'',
								name=u'all',
								descr=u'',
								ownerTag=u'')

	aaaUserRole = UserRole(aaaUserDomain, 
							privType=u'writePriv', 
							name=u'presidio')
							
	cfg_commit(moDir,aaaUserEp)
# ------------  EASY BUILD ------------ #
def tacacs_build(host, user, password):
	#Login to Fabric
	print ("Logging Into Fabric")
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	aaaUserEp = UserEp(polUni)
	aaaTacacsPlusEp = TacacsPlusEp(aaaUserEp)
	
	print ("Creating TACACS Provider")
	aaaTacacsPlusProvider = TacacsPlusProvider(aaaTacacsPlusEp,
												retries=u'1',
												name=u'COBRA-TACACS',
												timeout=u'5',
												key='Pr3s1d10!',
												authProtocol=u'pap',
												port=u'49')
												
	print ("Assigning TACACS Server to oob-default")
	aaaRsSecProvToEpg = RsSecProvToEpg(aaaTacacsPlusProvider, tDn=u'uni/tn-mgmt/mgmtp-default/oob-default')
	
	print ("Creating TACACS Group")
	aaaTacacsPlusProviderGroup = TacacsPlusProviderGroup(aaaTacacsPlusEp, name=u'COBRA-GROUP', descr=u'')
	
	print ("Assigning TACACS Providers to Group")
	aaaProviderRef = ProviderRef(aaaTacacsPlusProviderGroup, name=u'COBRA-TACACS', descr=u'', order=u'1')
	
	print ("Commiting Configuration")
	#Commit AAA Configuration
	cfg_commit(moDir,aaaTacacsPlusEp)
# ------------  EASY BUILD ------------ #
def radius_build(host, user, password):
	#Login to Fabric
	print ("Logging Into Fabric")
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	aaaUserEp = UserEp(polUni)
	aaaRadiusEp = RadiusEp(aaaUserEp)
	
	#Variables for Radius Config
	RSName='COBRA-RADIUS'
	RSGName='COBRA-RADIUS-GROUP'
	RSkey='Pr3s1d10!'
	RSauthPort='1812'
	RSProtocol='pap'

	#Create Radius Server
	print ("	Creating Radius Server Provider {"+RSName+"}")
	aaaRadiusProvider = RadiusProvider(aaaRadiusEp,
										retries=u'1',
										name=RSName,
										key=RSkey,
										authPort=RSauthPort,
										timeout=u'5',
										authProtocol=RSProtocol)
										
	aaaRsSecProvToEpg = RsSecProvToEpg(aaaRadiusProvider, tDn=u'uni/tn-mgmt/mgmtp-default/oob-default')
	
	print ("	Creating Radius Server Group {"+RSGName+"}")
	#Create Server Group
	aaaRadiusProviderGroup = RadiusProviderGroup(aaaRadiusEp, name=RSGName)
	
	print ("	Assigning Server {"+RSName+"} to Group {"+RSGName+"}")
	# Add Server Provider to Group
	aaaProviderRef = ProviderRef(aaaRadiusProviderGroup, name=RSGName, order=u'1')
	
	cfg_commit(moDir,aaaRadiusEp)	
# ------------  EASY BUILD ------------ #
def date_time_policy(host,user,password):
	print ("Logging Into Fabric")
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	fabricInst = Fabric.Inst(polUni)

	# Create New Data Time Policy
	datetimePol = DateTime.Pol(fabricInst, name=u'COBRA-NTP', adminSt=u'enabled', authSt=u'disabled')
	
	# Create NTP Provider 1 & Assign to OOB Mgmt 
	datetimeNtpProv = DateTime.NtpProv(datetimePol, maxPoll=u'6', keyId=u'0', name=u'north-america.pool.ntp.org', descr=u'', preferred=u'no', minPoll=u'4')
	datetimeRsNtpProvToEpg = DateTime.RsNtpProvToEpg(datetimeNtpProv, tDn=u'uni/tn-mgmt/mgmtp-default/oob-default')
	
	# Create NTP Provider 2 & Addign to OOB Mgmt
	datetimeNtpProv2 = DateTime.NtpProv(datetimePol, maxPoll=u'6', keyId=u'0', name=u'time.nist.gov', descr=u'', preferred=u'no', minPoll=u'4')
	datetimeRsNtpProvToEpg2 = DateTime.RsNtpProvToEpg(datetimeNtpProv2, tDn=u'uni/tn-mgmt/mgmtp-default/oob-default')
	
	# Configure Timezone Format Policy
	datetimeFormat = DateTime.Format(fabricInst, tz=u'n240_America-New_York', name=u'default', showOffset=u'enabled', displayFormat=u'local')
	
	cfg_commit(moDir,fabricInst)
# ------------  EASY BUILD ------------ #
def snmp_policy(host,user,password):
	
	print ("Logging Into Fabric")
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	fabricInst = Fabric.Inst(polUni)
	
	# Create Policy
	print ("	Creating SNMP Policy")
	snmpPol = SNMP.Pol(fabricInst,
						loc=u'',
						ownerKey=u'',
						name=u'Cobra-SNMP',
						descr=u'',
						adminSt=u'enabled',
						contact=u'',
						ownerTag=u'')
	#Create SNMP Client Entry	
	print ("	Creating SNMP Client")
	snmpClientGrpP = SNMP.ClientGrpP(snmpPol,
									name=u'cobra-snmp',
									descr=u'')
	print ("	Assigning SNMP Access to OOB-Default")								
	snmpRsEpg = SNMP.RsEpg(snmpClientGrpP, 
							tDn=u'uni/tn-mgmt/mgmtp-default/oob-default')
	print ("	Creating SNMP Client Access")						
	snmpClientP = SNMP.ClientP(snmpClientGrpP,
								addr=u'192.168.64.50',
								name=u'VPN')
	
	#Create SNMP Community
	print ("	Creating SNMP Community")
	snmpCommunityP = SNMP.CommunityP(snmpPol, name=u'cobra-snmp-policy', descr=u'')
	
	print("		Committing SNMP Configuration")
	cfg_commit(moDir,fabricInst)
# ------------  EASY BUILD ------------ #	
def infra_policy(creds):
	moDir = apic_login(creds[1], creds[2], creds[3])
	
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	# Create Link Level Policies for Fabric
	print ('-- Creating Link Level Policies:')
	print ('	10G Interface')
	fabric10GPol = HIfPol(infraInfra, name=u'10GE-SFP-Cobra', fecMode=u'inherit', autoNeg=u'on', speed=u'10G', linkDebounce=u'100')
	print ('	1G Interface')
	fabric1GPol = HIfPol(infraInfra, name=u'1GE-SFP-Cobra', fecMode=u'inherit', autoNeg=u'on', speed=u'1G', linkDebounce=u'100')
	print ('	FE Interface')
	fabricFEPol = HIfPol(infraInfra, name=u'FE-SFP-Cobra', fecMode=u'inherit', autoNeg=u'on', speed=u'100M', linkDebounce=u'100')
	
	
	# Create CDP Policies for Fabric
	print('--- Creating CDP Policies:')
	print ('	CDP Enabled')
	cdpIfPolEnabled = cdpIfPol.IfPol(infraInfra, name=u'CDP-Enabled-Cobra', adminSt=u'enabled')
	print ('	CDP Disabled')
	cdpIfPolDisabled = cdpIfPol.IfPol(infraInfra, name=u'CDP-Disabled-Cobra', adminSt=u'disabled')
	
	
	# Create LLDP Policies for Fabric
	print ('--- Creating LLDP Policies:')
	print ('	LLDP Enabled')
	lldpIfPolEnabled = lldpIfPol.IfPol(infraInfra, name=u'LLDP-Enabled-Cobra', adminTxSt=u'enabled', adminRxSt=u'enabled')
	print ('	LLDP Disabled')
	lldpIfPolDisabled = lldpIfPol.IfPol(infraInfra, name=u'LLDP-Disabled-Cobra', adminTxSt=u'disabled', adminRxSt=u'disabled')
	
	
	# Create LAG Policies for Fabric
	print('--- Creating LAG Policies:')
	print ('	LACP Active')
	lacpLagPolLACP = LagPol(infraInfra, name=u'LACP-Active-Cobra', minLinks=u'1', ctrl=u'fast-sel-hot-stdby,graceful-conv,susp-individual', maxLinks=u'16', mode=u'active')
	print ('	MAC Pinning')
	lacpLagPolMacPin = LagPol(infraInfra, name=u'MAC-PIN-Cobra', minLinks=u'1', ctrl=u'fast-sel-hot-stdby,graceful-conv,susp-individual', maxLinks=u'16', mode=u'mac-pin')
	
	
	# Create MCP Policies - disable needed?
	print('--- Creating MCP Policies:')
	print ('	MCP Enabled')
	mcpIfPolEnabled = mcpIfPol.IfPol(infraInfra, name=u'MCP-Enabled-Cobra', descr=u'Enable Mis-Cabling Protocol', adminSt=u'enabled')
	print ('	MDP Disabled')
	mcpIfPolDisabled = mcpIfPol.IfPol(infraInfra, name=u'MCP-Disabled-Cobra', descr=u'Disable Mis-Cabling Protocol', adminSt=u'disabled')
	
	cfg_commit(moDir,infraInfra)
	print('[END] Infrastructure Policies \n')
# ------------  EASY BUILD ------------ #
def if_policyG(host, user, password):
	print ('[BEG] Interface Policy Group Creation')
	""""moDir = apic_login(host, user, password)

	polUni = Uni('')
	infraInfra = Infra(polUni)
	infraFuncP = FuncP(infraInfra)"""
	
	ifPG_Name='ASA-Port-Policy-VPC-Cobra'
	lldp_pol='LLDP-Enabled-Cobra'
	cdp_pol='CDP-Enabled-Cobra'
	mcp_pol='MCP-Enabled-Cobra'
	if_pol='1GE-SFP-Cobra'
	lag_pol='LACP-Active-Cobra'
	
	print('--- Creating Policy Group Name: '+ifPG_Name)
	infraAccBndlGrp = AccBndlGrp(infraFuncP, name=ifPG_Name, lagT=u'node')
	
	print ('	Applying LLDP Policy: '+lldp_pol)
	infraRsLldpIfPol = RsLldpIfPol(infraAccBndlGrp, tnLldpIfPolName=lldp_pol)
	
	print ('	Applying CDP Policy: '+cdp_pol)
	infraRsCdpIfPol = RsCdpIfPol(infraAccBndlGrp, tnCdpIfPolName=cdp_pol)
	
	print ('	Applying MCP Policy: '+mcp_pol)
	infraRsMcpIfPol = RsMcpIfPol(infraAccBndlGrp, tnMcpIfPolName=mcp_pol)
	
	print ('	Applying Link Policy: '+if_pol)
	infraRsHIfPol = RsHIfPol(infraAccBndlGrp, tnFabricHIfPolName=if_pol)

	print ('	Applying LAG Policy: '+lag_pol)
	infraRsLacpPol = RsLacpPol(infraAccBndlGrp, tnLacpLagPolName=lag_pol')
	
	cfg_commit(moDir,infraFuncP)
	print ('[END] Interface Policy Group Creation \n')
	return ifPG_Name
	
def vpc_policy(host, user, password):
	print('[BEG] VPC Configuration')
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	fabricInst = Inst(polUni)
	
	print('--- Creating VPC Domain')
	
	VPCdID='20'
	SW1='103'
	SW2='104'
	
	fabricProtPol = ProtPol(fabricInst, pairT=u'explicit', name=u'default')
	fabricExplicitGEp = ExplicitGEp(fabricProtPol, id=VPCdID, name=u'VPC-Cobra-Policy')
	fabricRsVpcInstPol = RsVpcInstPol(fabricExplicitGEp, tnVpcInstPolName=u'default')
	print('--- Assigning LEAF Switches - Node'+SW1+' Node'+SW2+' to Domain ID:'+VPCdID)
	fabricNodePEp = NodePEp(fabricExplicitGEp, id=SW1)
	fabricNodePEp2 = NodePEp(fabricExplicitGEp, id=SW2)
	
	tenantCfg = ConfigRequest()
	tenantCfg.addMo(fabricInst)
	moDir.commit(tenantCfg)
	print('[END] VPC Configuration \n')

def int_profile(host, user, password, port_policy):

	print('[BEG] Port Profile Configuration')
	moDir = apic_login(host, user, password)
	
	# Get Top Level Objects
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	# Variables to keep Ports Consistent  
	intPName='ASA-VPC-INT-PROFILE-Cobra'
	#Port Selector Interface Policy Group
	pSPortP=port_policy
	#Port Selector FEX ID
	pSFexId='101'
	#Port Selector 1
	pS1='15'
	#Port Selector 2
	pS2='16'
	
	# Port Selector Variables #1 - to be used later for other method of input

	pSName='ASA_VPC_Port_Range_'+pS1+'_to_'+pS2+'-Cobra'

	# Port Selector Variables #2 - to be used later for other method of input
	
	print ('--- Creating Port Profile '+intPName)
	infraAccPortP = AccPortP(infraInfra, name=intPName)
	
	print ('	Adding '+pSName+' to Profile: '+intPName)
	infraHPortS = HPortS(infraAccPortP, type=u'range', name=pSName)
	infraRsAccBaseGrp = RsAccBaseGrp(infraHPortS, fexId=pSFexId, tDn=u'uni/infra/funcprof/accbundle-'+pSPortP)
	infraPortBlk = PortBlk(infraHPortS, name=u'block2', fromPort=pS1, fromCard=u'1', toPort=pS1, toCard=u'1')
	infraPortBlk2 = PortBlk(infraHPortS, name=u'block3', fromPort=pS2, fromCard=u'1', toPort=pS2, toCard=u'1')
	
	cfg_commit(moDir,infraInfra)
	print ('[END] Port Profile Configuration \n')
	return intPName

def switch_profile(host, user, password, if_profile):

	print('[BEG] Switch Profile Configuration')
	moDir = apic_login(host, user, password)
	
	# Get Top Level Objects
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	#Create Variables to be used later
	
	sPName='ASA-VPC-1-Cobra'
	swSelName='L103-104-ASA-VPC'
	LFrom='103'
	LTo='104'
	ifProfName=if_profile
	nodeBlkName='somethingsomethingnodeBlk'
	print('--- Creating Switch Profile: '+sPName)
	infraNodeP = NodeP(infraInfra, ownerKey=u'', name=sPName)
	
	print ('	Adding Switch Selector: '+swSelName+' with Nodes :'+LFrom+','+LTo)
	infraLeafS = LeafS(infraNodeP, ownerKey=u'', type=u'range', name=swSelName)
	infraNodeBlk = NodeBlk(infraLeafS, from_=LFrom, name=nodeBlkName, to_=LTo)
	
	print ('	Adding Interface Selector Profile: '+ifProfName)
	infraRsAccPortP = RsAccPortP(infraNodeP, tDn=u'uni/infra/accportprof-'+ifProfName)
	
	# Commit Configuration
	cfg_commit(moDir,infraInfra)
	print ('[END] Switch Profile Configuration \n')

def vlan_pool(host, user, password):
	print('[BEG] VLAN Pool Creation')
	moDir = apic_login(host, user, password)
	
	# Get Top Level Objects
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	vlanPName='ASA-L3-OUT-STATIC-Cobra'
	vlanMode='static'
	vlanTo='vlan-182'
	vlanFrom='vlan-181'
	
	print ('--- Creating VLAN Pool: '+vlanPName)
	fvnsVlanInstP = VlanInstP(infraInfra, name=vlanPName, allocMode=vlanMode)
	print ('	Adding '+vlanMode+' pool from '+vlanFrom+' to '+vlanTo)
	fvnsEncapBlk = EncapBlk(fvnsVlanInstP, to=vlanTo, from_=vlanFrom, allocMode=vlanMode)
	
	cfg_commit(moDir, infraInfra)
	print('[END] VLAN Pool Creation \n')
	return vlanPName

def phys_dom(host, user, password, vlans):
	print ('[BEG] Physical Domain Configuration')
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	
	phyDomName='ASA-UnMan-Cobra'
	
	physDomP = DomP(polUni, name=phyDomName)
	infraRsVlanNs = RsVlanNs(physDomP, tDn=u'uni/infra/vlanns-['+vlans+']-static')
	
	cfg_commit(moDir, physDomP)
	print ('[END] Physical Domain Configuration \n')
	return phyDomName

def AEP_attach(host, user, password, policy, AEP):
	print ('[BEG] Applying '+AEP+' to Interface Policy: '+policy)
	moDir = apic_login(host, user, password)

	polUni = Uni('')
	infraInfra = Infra(polUni)
	infraFuncP = FuncP(infraInfra)
	
	ifPG_Name='ASA-Port-Policy-VPC-Cobra'
	
	infraAccBndlGrp = AccBndlGrp(infraFuncP, name=ifPG_Name, lagT=u'node')
	infraRsAttEntP = RsAttEntP(infraAccBndlGrp, tDn=u'uni/infra/attentp-'+AEP)
	
	cfg_commit(moDir, infraFuncP)
	print('[END] Successful AEP Attach')

def AEP_build(host, user, profile, domain):
	print ('[BEG] Attached Entity Profile Configuration')
	moDir = apic_login(host, user, password)
	
	polUni = Uni('')
	infraInfra = Infra(polUni)
	
	aepName='ASA-L3OUT-Cobra'
	print('--- Creating AEP: '+aepName)
	infraAttEntityP = AttEntityP(infraInfra, name=aepName)
	
	print ('	Associating Domain: '+domain+' to AEP: '+aepName)
	infraRsDomP2 = RsDomP(infraAttEntityP, tDn=u'uni/phys-'+domain+'-1')
	
	cfg_commit(moDir,infraInfra)
	print ('[END] Attached Entity Profile Configuration')
	return aepName

#if __name__ == '__main__':
	""""from argparse import ArgumentParser
	parser = ArgumentParser("Tenant creation script")
	parser.add_argument('-d', '--host', help='APIC host name or IP',
						required=True)
	parser.add_argument('-p', '--password', help='user password',
						required=True)
	parser.add_argument('-u', '--user', help='user name', required=True)
	args = parser.parse_args()"""

#def main(host, user, password):
host = '10.10.2.21'
user = 'admin'
password = 'i6i4Penn'
	
"""local_user(host, user, password)
	
tacacs_build(host, user, password)

radius_build(host, user, password)

date_time_policy(host, user, password)
	
snmp_policy(host, user, password)

infra_policy(host, user, password)

vpc_policy(host, user, password)

if_PG = if_policyG(host, user, password)

if_profile = int_profile(host, user, password, if_PG)

sw_profile = switch_profile(host, user, password, if_profile)

v_pool = vlan_pool(host, user, password)

AssocDomain = phys_dom(host, user, password, v_pool)

aepName = AEP_build(host, user, password, AssocDomain)

AEP_attach(host, user, password, if_PG, aepName)"""
