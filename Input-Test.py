#!/usr/bin/env python

import sys
import json
import getpass
import FabricStaging
import InitialTen
import ACIQuery
import inspect
from cobra.mit.access import MoDirectory
from cobra.mit.session import LoginSession

TnName = ''
host = ''
user = ''
password = ''
loginStatus = 0
menu_select = ''
creds=[]

def get_mo(host, user, password):
	apicUrl = 'https://%s' % (host)
	moDir = MoDirectory(LoginSession(apicUrl, user, password))
	moDir.login()
	return moDir

def cfg_commit(moDir,object):
	tenantCfg = ConfigRequest()
	tenantCfg.addMo(object)
	moDir.commit(tenantCfg)

def login_check():
	print("--- Login ---")
	host = raw_input("Please Enter the Name or IP Address of your APIC: ")
	user = raw_input("Please Enter Your Username: ")
	password = getpass.getpass("Please Enter Your Password: ")
	
	apicUrl = 'https://%s' % (host)
	loginCheck = MoDirectory(LoginSession(apicUrl, user, password))
	loginCheck.login()
	try:
		loginCheck.login()
		var=1
	except Exception:
		print 'Login Error, Please Try Again'
		loginStatus = 1
	else:
		loginStatus = 0
	return loginStatus, host, user, password

def menu_Tree1():
	print("#")*20
	print("[1] Initialize Base Fabric Policies")
	print("[2] Begin Tenant Configuration")
	print("[Q] Quit")
	
	menu_select=raw_input("Please select an option: ")
	return menu_select
	
def Ten_tree(creds):

	print("###################################")
	print("#---   Tenant Configuration    ---#")
	print("################################### \n")
	
	print("#")*20
	print("[1] Create a new Tenant")
	print("[2] Select Existing Tenant")
	print("[Q] Quit")
	
	menu_select=raw_input("Please select an option: ")
	
	if menu_select == '1':
		TnName = raw_input("Please Enter your new Tenant Name:  ")
		InitialTen.BuildTen(creds, TnName)
	elif menu_select == '2':
		ACIQuery.TenList(creds)
	
	
def open_menu():
	
	global menu_select
	global creds

	print("####################################")
	print("#--- Welcome to ACI Quick Build ---#")
	print("#################################### \n")
	
	loginStatus = login_check()
	creds=loginStatus
	loginStatus = loginStatus[0]
	
	
	if loginStatus == 1:
		loginStatus = login_check(host,user,password)
	else:
		menu_select=menu_Tree1()
	if menu_select == '1':
	
		print "\n"+"%" * 38	
		print "Initializing Fabric Interface Policies"
		print "%" * 38 + "\n"
		
		FabricStaging.infra_policy(creds)
		return 1
		
	elif menu_select == '2':
		print "Tenant Configuration"
		Ten_tree(creds)
		return 2
	elif menu_select == 'q' or menu_select == 'Q':
		print "Goodbye! \n \n"
		exit(1)
		

open_menu()