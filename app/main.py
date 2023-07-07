import re
import os
import csv
import time
import smtplib
import logging
import logging.handlers
import syslog
from netmiko import ConnectHandler
from pysnmp.hlapi import *

# GLOBAL VARIABLES
FIREWALL_USERNAME = os.environ.get("FIREWALL_USERNAME")
FIREWALL_PASSWORD = os.environ.get("FIREWALL_PASSWORD")
BACKUP_SERVER_USERNAME = os.environ.get("BACKUP_SERVER_USERNAME")
BACKUP_SERVER_PASSWORD = os.environ.get("BACKUP_SERVER_PASSWORD")
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SNMP_USER = os.environ.get("SNMP_USER")
SNMP_AUTH_KEY = os.environ.get("SNMP_AUTH_KEY")
SNMP_PRIV_KEY = os.environ.get("SNMP_PRIV_KEY")

# GLOBAL GUARDRAILS
if not FIREWALL_USERNAME:
    print("FIREWALL_USERNAME environment variable not set!")
    exit(1)
if not FIREWALL_PASSWORD:
    print("FIREWALL_PASSWORD environment variable not set!")
    exit(1)
if not BACKUP_SERVER_USERNAME:
    print("BACKUP_SERVER_USERNAME environment variable not set!")
    exit(1)
if not BACKUP_SERVER_PASSWORD:
    print("BACKUP_SERVER_PASSWORD environment variable not set!")
    exit(1)
if not SMTP_USERNAME:
    print("SMTP_USERNAME environment variable not set!")
    exit(1)
if not SMTP_PASSWORD:
    print("SMTP_PASSWORD environment variable not set!")
    exit(1)
if not SNMP_USER:
    print("SNMP_USER environment variable not set!")
    exit(1)
if not SNMP_AUTH_KEY:
    print("SNMP_AUTH_KEY environment variable not set!")
    exit(1)
if not SNMP_PRIV_KEY:
    print("SNMP_PRIV_KEY environment variable not set!")
    exit(1)

# INVOKABLE FUNCTIONS
def log(message, LOG_MESSAGES):
    print("LOG:", message)
    LOG_MESSAGES.append(message)
    return LOG_MESSAGES

def connect_firewall(FIREWALL_USERNAME, FIREWALL_PASSWORD, MANAGEMENT_IP, FIREWALL_NAME, LOG_MESSAGES):
    device = {
        'device_type': 'cisco_asa',
        'ip': MANAGEMENT_IP,
        'username': FIREWALL_USERNAME,
        'password': FIREWALL_PASSWORD,
        'secret': FIREWALL_PASSWORD,
    }

    try:
        connection = ConnectHandler(**device)
        connection.enable()
        log(f"Successfully connected to firewall: {FIREWALL_NAME}", LOG_MESSAGES)
        return connection, LOG_MESSAGES
    except Exception as e:
        log(f"Failed to connect to the firewall: {str(e)}", LOG_MESSAGES)
        return LOG_MESSAGES

def changeto_system(connection, FIREWALL_NAME, EXPECTED_PROMPT, LOG_MESSAGES):
    # Switch to the proper context to perform backups
    connection.send_command("changeto system", expect_string=EXPECTED_PROMPT)

    # Local Function Guardrails
    if connection.find_prompt() != EXPECTED_PROMPT:
        log(f"Failed to change to system context. Expected prompt: {EXPECTED_PROMPT}", LOG_MESSAGES)
    else:
        log(f"Successfully switched to firewall context system on: {FIREWALL_NAME}", LOG_MESSAGES)
        
    return LOG_MESSAGES

def get_contexts(connection, FIREWALL_NAME, LOG_MESSAGES):
    # Send command to get printout of contexts
    output = connection.send_command("show context")

    # Divide printout into rows for analysis
    lines = output.splitlines()

    # Define a list to store context names
    CONTEXT_NAMES = []

    # Analyze output line by line
    for line in lines:
        match = re.search(r"^\s*(\S+)\s+", line)
        if match:
            context_name = match.group(1).strip()
            # Regex tested to match the firewall prompt line & printout headers;
            # Attempting to parse that out here and not add to list
            if context_name != FIREWALL_NAME and context_name != "Context Name":
                CONTEXT_NAMES.append(context_name)
                
        log(f"These contexts, {CONTEXT_NAMES}, were detected on firewall, {FIREWALL_NAME}", LOG_MESSAGES)

    return CONTEXT_NAMES, LOG_MESSAGES

def run_backups(connection, CONTEXT_NAMES, BACKUP_SERVER_IP, BACKUP_SERVER_PATH, BACKUP_SERVER_USERNAME, BACKUP_SERVER_PASSWORD, FIREWALL_NAME, LOG_MESSAGES):
    for CONTEXT in CONTEXT_NAMES:
        # Send command to execute backup to server for context
        output = connection.send_command(f"backup /noconfig context {CONTEXT} location scp://{BACKUP_SERVER_USERNAME}:{BACKUP_SERVER_PASSWORD}@{BACKUP_SERVER_IP}/{BACKUP_SERVER_PATH}/")

        # Local Function Guardrails
        if "error" in output.lower() or "failed" in output.lower():
            log(f"Backup for context {CONTEXT} failed on firewall, {FIREWALL_NAME}.", LOG_MESSAGES)
        else:
            log(f"Backup for context {CONTEXT} appears successful on firewall, {FIREWALL_NAME}.", LOG_MESSAGES)
            
    return LOG_MESSAGES

def configure_syslog(SPLUNK_SERVER, SYSLOG_PORT):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Create a handler for sending syslog messages to a remote Splunk server
    syslog_handler = logging.handlers.SysLogHandler(address=(SPLUNK_SERVER, SYSLOG_PORT))
    syslog_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(syslog_handler)

    return logger

def send_snmp_trap(SNMP_SERVER, SNMP_PORT, SNMP_USER, SNMP_AUTH_PROTOCOL, SNMP_AUTH_KEY, SNMP_PRIV_PROTOCOL, SNMP_PRIV_KEY, TRAP_OID, TRAP_VARS):
    auth_protocol = usmHMACSHAAuthProtocol if snmp_auth_protocol == "SHA" else usmHMACMD5AuthProtocol
    priv_protocol = usmAesCfb128Protocol if snmp_priv_protocol == "AES" else usmDESPrivProtocol

    errorIndication, errorStatus, errorIndex, varBinds = next(
        sendEMAIL(
            SnmpEngine(),
            UsmUserData(snmp_user, authKey=snmp_auth_key, authProtocol=auth_protocol,
                        privKey=snmp_priv_key, privProtocol=priv_protocol),
            UdpTransportTarget((SNMP_SERVER, snmp_port)),
            ContextData(),
            'trap',
            EMAILType(ObjectIdentity(TRAP_OID)).addVarBinds(TRAP_VARS)
        )
    )

    if errorIndication:
        syslog.syslog(syslog.LOG_ERR, f"Failed to send SNMP trap: {errorIndication}")
    elif errorStatus:
        syslog.syslog(syslog.LOG_ERR, f"Received SNMP error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1] or '?'}")

def notifications(SMTP_USERNAME, SMTP_PASSWORD, EMAIL_SERVER, EMAIL_SENDER, EMAIL_RECIEVER, SMTP_PORT, SNMP_SERVER, SNMP_PORT, SNMP_USER, SNMP_AUTH_PROTOCOL, SNMP_AUTH_KEY, SNMP_PRIV_PROTOCOL, SNMP_PRIV_KEY, SPLUNK_SERVER, SYSLOG_PORT, FIREWALL_NAME, LOG_MESSAGES):
    logger = configure_syslog(SPLUNK_SERVER,SYSLOG_PORT)

    subject = f"Log Report - {FIREWALL_NAME} - Cisco ASA Multicontext Backups"
    message = "\n".join(LOG_MESSAGES)

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(EMAIL_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)

        # Send the email
        email_content = f"Subject: {subject}\n\n{message}"
        server.sendmail(EMAIL_SENDER, EMAIL_RECIEVER, email_content)

        # Disconnect from the SMTP server
        server.quit()

        logger.info(f"Email notification, {subject}, sent successfully")

    except smtplib.SMTPException as e:
        error_message = f"Email notification, {subject}, has failed: {str(e)}"
        logger.error(error_message)

        # Send SNMP trap for email failure
        TRAP_OID = "1.3.6.1.4.1.12345.1.0"  # OID for the custom trap
        TRAP_VARS = [ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0"), OctetString(FIREWALL_NAME))]  
        send_snmp_trap(SNMP_SERVER, SNMP_PORT, SNMP_USER, SNMP_AUTH_PROTOCOL, SNMP_AUTH_KEY, SNMP_PRIV_PROTOCOL, SNMP_PRIV_KEY, TRAP_OID, TRAP_VARS)

        # Send Syslog Message to Splunk
        logger.error(error_message)

def main():
    while True:
        # Open the inventory file and iterate through the rows
        with open('DEVICE_INVENTORY.csv', 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # Reset LOG_MESSAGES list for each iteration
                LOG_MESSAGES = []
                
                # Map the columns of the row being iterated to variables
                FIREWALL_NAME = row['FIREWALL_NAME']
                MANAGEMENT_IP = row['MANAGEMENT_IP']
                BACKUP_SERVER_IP = row['BACKUP_SERVER_IP']
                BACKUP_SERVER_PATH = row['BACKUP_SERVER_PATH']
                EMAIL_SERVER = row['EMAIL_SERVER']
                EMAIL_SENDER = row['EMAIL_SENDER']
                EMAIL_RECIEVER = row['EMAIL_RECIEVER']
                SNMP_SERVER = row['SNMP_SERVER'] 
                SNMP_AUTH_PROTOCOL = row['SNMP_AUTH_PROTOCOL']
                SNMP_PRIV_PROTOCOL = row['SNMP_PRIV_PROTOCOL']
                SPLUNK_SERVER = row['SPLUNK_SERVER']
                
                
                # Other Variables
                EXPECTED_PROMPT = f"{FIREWALL_NAME}#"
                SMTP_PORT = 587
                SNMP_PORT = 162
                SYSLOG_PORT = 514

                # Connect to the firewall
                connection = connect_firewall(FIREWALL_USERNAME, FIREWALL_PASSWORD, MANAGEMENT_IP, FIREWALL_NAME, LOG_MESSAGES)

                # Changeto System Context
                changeto_system(connection, FIREWALL_NAME, EXPECTED_PROMPT, LOG_MESSAGES)

                # Get a List of Contexts
                CONTEXT_NAMES = get_contexts(connection, FIREWALL_NAME, LOG_MESSAGES)

                # Issue Backup Commands Per Context From System
                run_backups(connection, CONTEXT_NAMES, BACKUP_SERVER_IP, BACKUP_SERVER_PATH, BACKUP_SERVER_USERNAME, BACKUP_SERVER_PASSWORD, FIREWALL_NAME, LOG_MESSAGES)

                # Send notifications
                notifications(SMTP_USERNAME, SMTP_PASSWORD, EMAIL_SERVER, EMAIL_SENDER, EMAIL_RECIEVER, SMTP_PORT, SNMP_SERVER, SNMP_PORT, SNMP_USER, SNMP_AUTH_PROTOCOL, SNMP_AUTH_KEY, SNMP_PRIV_PROTOCOL, SNMP_PRIV_KEY, SPLUNK_SERVER, SYSLOG_PORT, FIREWALL_NAME, LOG_MESSAGES)
                
                # Disconnect from the firewall
                connection.disconnect()  # pylint: disable=no-member


        # Sleep for 8 hours
        time.sleep(8 * 60 * 60)  # 8 hours = 8 * 60 minutes * 60 seconds


# SCRIPT ACTIONS INITIALIZATION
if __name__ == "__main__":
    main()