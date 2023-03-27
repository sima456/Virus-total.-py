"""
    Hashes every resource contained in the prefetch files
    and queries VirusTotal with the hash value.
"""

import json
import os
import subprocess
import hashlib
import vt
import traceback
from windowsprefetch import Prefetch


# checking if OS is a Windows
if os.name is not 'nt':
    exit("This program only works on Windows.")

# setting up prefetch directory
PREFETCH_DIR = os.path.join(os.getenv("windir"), "Prefetch")

VIRUS_TOTAL_API_KEY = None
# Proof of Concept or in case you have a trial limited VT key
PoC_ACTIVE = True


def file_sha256(filepath: str):
    """
    Calculates the SHA256 hash of the specified file
    :param filepath: file to perform sha256
    :return: sha256 value of the file
    """
    with open(filepath, "rb") as f:
        data = f.read()  # read entire file as bytes
        hash = hashlib.sha256(data).hexdigest()
    return hash


def get_volume_info():
    """
    Gets the volume letter and the serial number by using the windows program 'vol'
    (ensuring WIN OS retro compatibility).
    :return:
    """
    output = subprocess.run(['vol'], stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
    letter_output, serial_number_output = output.strip().split('\n')

    letter = letter_output[16]
    sn = serial_number_output[25:]
    sn = sn.replace(sn[4], "")

    return letter, sn


def get_prefetch_files(dir: str):
    """
    Searches for all prefetch files in the specified directory.
    Each encountered file is parsed to windowsprefetch.Prefetch.
    :param dir: directory to check for .pf
    :return: list of windowsprefetch.Prefetch
    """
    prefetch_files = []
    for filename in os.listdir(dir):
        if filename.endswith('.pf'):
            path = os.path.join(dir, filename)
            if os.path.getsize(path) > 0:
                pf = Prefetch(path)
                prefetch_files.append(pf)
    return prefetch_files


def get_prefetch_resources_path(prefetch_list: list, volume_letter: str, volume_sn: str):
    """
    Iterates the prefetch parsed object list, to identify every resource path
    present on each file.
    :param prefetch_list: collection of prefetched parsed objects
    :param volume_letter: default volume letter
    :param volume_sn: default volume serial number
    :return: Paths of the file resources list
    """
    resources = []
    volume_sn = volume_sn.lower()
    for prefetch in prefetch_list:
        if prefetch.volSerialNumber == volume_sn:
            for resource in prefetch.resources:
                path_parts = resource.split('\\')[2:]
                path = f"{volume_letter}:\\" + "\\".join(path_parts)

                if os.path.isfile(path) and path not in resources:
                    resources.append(path)
    return resources


def vt_validate(client: vt.Client, hash: str):
    """
    Uses the VirusTotal Client to validate the provided hash.
    :param client: virus total client
    :param hash: hash
    :return:
    """
    try:
        result = client.get_object(f"/files/{hash}")
        if result.total_votes["malicious"] > 0 or \
                ("malicious" in result.last_analysis_stats and result.last_analysis_stats["malicious"] > 0):
            print(f"Malicious. {result.meaningful_name} {hash} {result.popular_threat_classification}")
            return result
    except vt.APIError as error:
        if "NotFoundError" in error.code:
            pass
        raise

    return None


def vt_validate_files(client: vt.Client, files: list):
    """
    Performs SHA256 hashing on each provided file and validates it on VirusTotal.
    :param client: VirusTotal Client
    :param files: list of files to analyze
    :return:
    """
    vt_results = {}
    it = 0
    for file in files:
        if it == 3 and PoC_ACTIVE:
            break

        hash = file_sha256(file)
        print(f"Querying. {file} - {hash}")
        result = vt_validate(client, hash)
        if result:
            vt_results[hash] = result
        it += 1
    return vt_results


def save_report(report: dict, filename: str = "virus-total-report.json"):
    """
    Saves report to file.
    :param report: dictionary
    :param filename: file name
    :return:
    """
    temp = {}
    for entry in report:
        temp[entry] = report[entry].to_dict()

    with open(filename, 'w') as f:
        json.dump(temp, f)


def greeting():
    greeting = "\nPrefetch File Resources Analyzer\n\n\n" + \
        "If you have Proof Of Concept mode only three prefetch resources are queried.\n" \
        "And one bad dll hash is fed to mock a encountered dangerous resource." + \
        "\n\nFind more at https://github.com/jppdpf/prefetch-vt-analyzer."
    print(greeting)


if __name__ == '__main__':

    greeting()
    print("\n------------------------------\n")

    if not VIRUS_TOTAL_API_KEY:
        print("Please insert a Virus Total API key.\n\n")
        exit()

    # VirusTotal Client
    VT_CLIENT = vt.Client(VIRUS_TOTAL_API_KEY)

    try:

        # volume information
        letter, serial_number = get_volume_info()

        # get prefetch files from directory
        pf_files = get_prefetch_files(PREFETCH_DIR)
        # get prefetch resources paths
        resources_path = get_prefetch_resources_path(pf_files, letter, serial_number)

        report = vt_validate_files(VT_CLIENT, resources_path)

        if PoC_ACTIVE:
            """ for testing purpose lets feed a malicious dll """
            hash_of_malicious_dll = "cf6992dd67403dd92d4111935c789bcb5aefbae2905f172ac11fe476a9d079a6"
            malicious = vt_validate(VT_CLIENT, hash_of_malicious_dll)
            report[hash_of_malicious_dll] = malicious

        print("\n------------------------------\n")
        report_file='virus-total-report.json'
        save_report(report, filename=report_file)
        print(f"See full report at {report_file}\n")

    except Exception:
        print(traceback.format_exc())
    finally:
        VT_CLIENT.close()
