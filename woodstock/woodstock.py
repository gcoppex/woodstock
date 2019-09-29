#!/usr/bin/env python3

import sys
import asyncio
import aiohttp
import os
import base64
from OpenSSL import crypto
from collections import OrderedDict
from construct import Struct, Byte, Enum, Int16ub, Int64ub, Bytes, Int24ub, \
    this, GreedyBytes, GreedyRange, Terminated, Embedded
import hashlib
import datetime
import concurrent
from collections import deque
import argparse
import glob
import json
from datetime import datetime

DEST_FOLDER = "/tmp/ct_logs/"
LOG_SERVER_LIST_URL = "https://www.gstatic.com/ct/log_list/log_list.json"
GET_INFO_API_URL_PATTERN = "http://%s/ct/v1/get-sth"
DOWNLOAD_API_URL_PATTERN = "http://%s/ct/v1/get-entries?start=%d&end=%d"

MAX_RECORDS_PER_OUTPUT_FILE =  2 * 1024
"""
    Parquet file : approx. 0.625 KB / extracted record
    CSV file : approx. 1.6 KB / extracted record
"""

MAX_CONCURRENT_HTTP_REQUESTS_PER_SERVER = 8
MAX_LINES_PER_DATAFRAME =  MAX_RECORDS_PER_OUTPUT_FILE
LOG_FILE = "./log.txt"

OUTPUT_FORMAT = "csv" # other option: "parquet"
CSV_SEPARATOR = "|" # other option: ";" or ","

if sys.version_info < (3, 6,):
    raise Exception("This program requires a python version greater than 3.6.")

MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"      / Int64ub,
    "LogEntryType"   / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"          / GreedyBytes
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

PreCertEntry = Struct(
    "LeafCert" / Certificate,
    Embedded(CertificateChain),
    Terminated
)

class ParallelDownloader:
    """
    Helper class to download CT log server entries: thanks to the `with`
    python syntax, this object provides an asynchronous iterator over the
    retrieved log entries.
    """
    def __init__(self, httpClientSession, server_url, start_offset=0, \
        max_concurrent_requests=16):
        self.httpClientSession = httpClientSession
        self.server_url = server_url
        self.start_offset = start_offset
        self.batch_size = 999999
        self.max_concurrent_requests = max_concurrent_requests

        #self.downloaded_chunks_queue = deque()
        self.promisesQueue = deque()
        self.lock = asyncio.Condition()
        self.closed = False

    async def _query_ct_log_server(self, start_offset):
        """
        Function to retrieve the CT logs entries, given an offset. The batch
        size is a class member, as it is supposed to be constant.
        """
        query_url = "http://" + ("%s/ct/v1/get-entries?start=%d&end=%d" % \
            (self.server_url, start_offset, start_offset + self.batch_size - 1)\
            ).replace("//", "/")

        retry, max_retry, wait_time_millisec = 1, 3, 150
        while retry <= max_retry:
            async with self.httpClientSession.get(query_url) as response:
                try:
                    result = await response.json()
                    if not "entries" in result:
                        return []
                    entries = result['entries']
                    if entries is None:
                        return []
                    for i, entry in enumerate(entries):
                        entry["cert_index"] = start_offset + i
                    return entries
                except Exception as e:
                    import traceback; traceback.print_exc()
                    print("Error while fetching [%s], retry=%d/%d." % \
                        (query_url, retry, max_retry) + "Waiting %dms" % \
                        wait_time_millisec)
                    await asyncio.sleep(wait_time_millisec / 1000.0)
                    retry += 1
                    wait_time_millisec *= 1.5
        return []


    async def __aenter__(self):
        # First query to get the batch size
        raw_certificate_batch = await self._query_ct_log_server(\
            self.start_offset)
        self.batch_size = len(raw_certificate_batch)

        if self.batch_size > 1 :
            async with self.lock:
                # If the server is not down, we prepare the subsequent jobs:
                for _ in range(self.max_concurrent_requests):
                    promise = asyncio.ensure_future(self._query_ct_log_server(
                        self.start_offset))
                    self.start_offset += self.batch_size
                    self.promisesQueue.append(promise)
                    self.lock.notify_all()
        else:
            raise RuntimeError("The CT log server %s " % self.server_url + \
                "is down or has been fully queried. We drop it.")

        return self

    def __aiter__(self):
        return self

    async def __anext__(self):
        async with self.lock:
            while len(self.promisesQueue) == 0 and not self.closed:
                await self.lock.wait()
            if self.closed:
                raise StopAsyncIteration
            #chunk = self.downloaded_chunks_queue.popleft()
            chunkPromise = self.promisesQueue.popleft()

            chunk = await chunkPromise;

            # Once a chunk has been consumed out of the queue, a new fetching
            # job need to be rescheduled:
            promise = asyncio.ensure_future(self._query_ct_log_server(
                self.start_offset))
            self.start_offset += self.batch_size
            self.promisesQueue.append(promise)
            self.lock.notify_all()

            return chunk
    async def __aexit__(self, exc_type, exc, tb):
        async with self.lock:
            self.closed = True
            self.lock.notify_all()

def extract_extensions(certificate):
    """
    This function extracts the extensions of a given certificate.
    """
    extensions = {}
    for x in range(certificate.get_extension_count()):
        extension_name = ""
        try:
            extension_name = certificate.get_extension(x).get_short_name()
            if extension_name == b'UNDEF':
                continue
            extensions[extension_name.decode('latin-1')] = \
                certificate.get_extension(x).__str__()
        except:
            try:
                extensions[extension_name.decode('latin-1')] = "NULL"
            except Exception as e:
                pass
    return extensions

def dump_cert(certificate):
    """
    This function dumps a certificate subject, extension, timestamps and as_der
    fields.
    """
    subject = certificate.get_subject()
    not_before = certificate.get_notBefore().decode()
    not_after = certificate.get_notAfter().decode()
    try:
        not_before = datetime.datetime.strptime(\
            certificate.get_notBefore().decode(), "%Y%m%d%H%M%SZ").timestamp()
        not_after = datetime.datetime.strptime(\
            certificate.get_notAfter().decode(), "%Y%m%d%H%M%SZ").timestamp()
    except:
        # In case of an Exception, the default value is used.
        pass
    return {
        "subject": {
            "aggregated": repr(certificate.get_subject())[18:-2],
            "C": subject.C,
            "ST": subject.ST,
            "L": subject.L,
            "O": subject.O,
            "OU": subject.OU,
            "CN": subject.CN
        },
        "extensions": extract_extensions(certificate),
        "not_before": not_before,
        "not_after": not_after,
        "as_der": base64.b64encode(crypto.dump_certificate(\
            crypto.FILETYPE_ASN1, certificate)).decode('utf-8')
    }

def map_url_to_folder_name(input_string):
    """
    This function filters out non ASCII symbols from input_string
    More precisely, the ranges are:
        - a to z
        - A to Z
        - / and 0 to 9
    """
    return ''.join([i if (
        ord(i) >= 97 and ord(i) <= 122 or \
        ord(i) >= 65 and ord(i) <= 90 or \
        ord(i) >= 47 and ord(i) <= 57 )else '_' \
        for i in input_string])

def get_server_url_list():
    """
    This function queries the LOG_SOUTPUT_FORMATERVER_LIST_URL server to fetch
    the list of available CT log servers.
    """
    import urllib.request, json
    with urllib.request.urlopen(LOG_SERVER_LIST_URL) as url:
        response = json.loads(url.read().decode())
        #return [[x["url"] for x in response["logs"]][0]]
        return [x["url"] for x in response["logs"]]

async def _fetch_raw_certificates(httpClientSession, server_url, \
    start_offset, end_offset):
    """
    Asynchronous "private" function to fetch a precise batch of raw certificates
    with a given specific index range.
    """
    try:
        async with httpClientSession.get(DOWNLOAD_API_URL_PATTERN % \
            (server_url, start_offset, end_offset)) as response:
            entry_list = await response.json()
            print("[%s] Retrieving blocks %d-%d..." % \
                    (server_url, start_offset, end_offset))
            certificates = entry_list['entries']
            for i in range(len(certificates)):
                certificates[i]["cert_index"] = start_offset + i
            return certificates
    except e:
        print("error: ", e)
        return []

def _process_certificate_batch(server_url, raw_certificate_batch):
    """
    This function converts a raw certificate entry (coming from a CT log server)
    into a formatted dict of selected interesting fields.
    """
    output_certs = []
    try:
        for raw_cert in raw_certificate_batch:
            merkle_tree_header = MerkleTreeHeader.parse(base64.b64decode(raw_cert['leaf_input']))
            cert_data = {}
            if merkle_tree_header.LogEntryType == "X509LogEntryType":
                cert_data['type'] = "X509LogEntry"
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, Certificate.parse(merkle_tree_header.Entry).CertData)]
                extra_data = CertificateChain.parse(base64.b64decode(raw_cert['extra_data']))
                for certChain in extra_data.Chain:
                    chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, certChain.CertData))
            else:
                cert_data['type'] = "PreCertEntry"
                extra_data = PreCertEntry.parse(base64.b64decode(raw_cert['extra_data']))
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]
                for certChain in extra_data.Chain:
                    chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, certChain.CertData))

            childs_chain = [dump_cert(x) for x in chain[1:]]
            leaf_certificate = chain[0]
            datetime_format = '%Y%m%d%H%M%S'
            childs_chain_hash = hashlib.sha256("".join([x['as_der'] for x in childs_chain]).encode('ascii')).hexdigest()

            extensions = {}
            for x in range(leaf_certificate.get_extension_count()):
                extension_name = ""
                try:
                    extension_name = leaf_certificate.get_extension(x).get_short_name()
                    if extension_name == b'UNDEF':
                        continue
                    extensions[extension_name.decode('latin-1')] = leaf_certificate.get_extension(x).__str__()
                except:
                    try:
                        extensions[extension_name.decode('latin-1')] = "NULL"
                    except Exception as e:
                        pass
            cert_row_data = {
                "serial_number": str(leaf_certificate.get_serial_number()),
                "version": leaf_certificate.get_version(),
                "has_expired" : leaf_certificate.has_expired(),
                "subject_country":  leaf_certificate.get_subject().C,
                "subject_province": leaf_certificate.get_subject().ST,
                "subject_locality": leaf_certificate.get_subject().L,
                "subject_org_name":leaf_certificate.get_subject().O,
                "subject_org_unit_name": leaf_certificate.get_subject().OU,
                "subject_common_name":leaf_certificate.get_subject().CN,
                "issuer_country": leaf_certificate.get_issuer().C,
                "issuer_province": leaf_certificate.get_issuer().ST,
                "issuer_locality": leaf_certificate.get_issuer().L,
                "issuer_org_name": leaf_certificate.get_issuer().O,
                "issuer_org_unit_name":  leaf_certificate.get_issuer().OU,
                "issuer_common_name":  leaf_certificate.get_issuer().CN,
                "extensions":  json.dumps(extensions),
                "server_url": server_url,
                "cert_index": int(raw_cert['cert_index']),
                "cert_type":  cert_data['type'],
                "signature_algorithm": chain[0].get_signature_algorithm().decode("UTF-8"),
                "key_size":  leaf_certificate.get_pubkey().bits(),
                "timestamp": merkle_tree_header.Timestamp,
                "chain_hash":  childs_chain_hash,
                "not_before":  datetime.strptime(leaf_certificate.get_notBefore().decode('utf8')[:-1],datetime_format),
                "not_after": datetime.strptime(leaf_certificate.get_notAfter().decode('utf8')[:-1],datetime_format)
            }
            file_index = int(raw_cert['cert_index'] // MAX_RECORDS_PER_OUTPUT_FILE)
            output_certs.append(cert_row_data)
    except Exception as e:
        print("Error while writting: ", e)
    return output_certs

async def process_certificate_batch(\
        server_url, raw_certificate_batch, executor):
    """
    Asynchronous function that implicitely spawns python processes (thanks to
    `run_in_executor` of the asyncio module) to process the batch of raw
    certificates.
    """
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(executor, \
            _process_certificate_batch, server_url, raw_certificate_batch)
    except Exception as e:
        print("Unable to process_certificate_batch")
    return result

def _write_certificates(output_filename, entries, extension):
    """
    Function that writes a batch of entries to a file, given its extension
    """
    print("Writing %d certificates ([%d, %d]) to %s file" % \
        (len(entries), entries[0]["cert_index"], entries[-1]["cert_index"], \
        output_filename))
    if extension == "parquet":
        _write_certificates_parquet(output_filename, entries)
    else:
        _write_certificates_csv(output_filename, entries)

def _write_certificates_parquet(output_filename, entries):
    """
    Helper function that writes a batch of entries to a parquet file
    """
    import fastparquet
    import pandas as pd
    df = pd.DataFrame(entries)
    fastparquet.write(output_filename, df, write_index=True,
        row_group_offsets=500000,
        append=os.path.exists(output_filename), compression='SNAPPY')

def _write_certificates_csv(output_filename, entries):
    """
    Helper function that writes a batch of entries to a csv file
    """
    with open(output_filename, 'w', encoding='utf-8') as f:
        for entry in entries:
            f.write(
                CSV_SEPARATOR.join(
                    [
                        str(x).replace(CSV_SEPARATOR,
                        "\\"+CSV_SEPARATOR) for x in
                        [
                            entry["cert_index"],
                            entry["server_url"],
                            entry["serial_number"],
                            entry["subject_org_name"],
                            entry["subject_org_unit_name"],
                            entry["subject_common_name"],
                            entry["subject_country"],
                            entry["subject_province"],
                            entry["subject_locality"],
                            entry["issuer_org_name"],
                            entry["issuer_org_unit_name"],
                            entry["issuer_common_name"],
                            entry["issuer_country"],
                            entry["issuer_province"],
                            entry["issuer_locality"],
                            entry["extensions"],
                            entry["cert_type"],
                            entry["signature_algorithm"],
                            entry["key_size"],
                            entry["timestamp"],
                            entry["chain_hash"],
                            str(entry["not_before"].timestamp()),
                            str(entry["not_after"].timestamp())
                        ]
                    ]
                ) + "\n"
            )
async def write_certificates(output_filename, entries, executor, extension):
    """
    Asynchronous function that implicitely spawns python processes (thanks to
    `run_in_executor` of the asyncio module) to write the batch of raw
    certificates to the disk.
    """
    loop = asyncio.get_event_loop()
    await asyncio.shield(loop.run_in_executor(executor, _write_certificates, \
        output_filename, entries, extension))

async def handle_log_server(httpClientSession, server_url, executor, args):
    """
    Asynchronous function that represent the main logic of the program. Given a
    CT log server url, this function fetches the raw certificates in the current
    green thread, spawns a fetching, processing and writing tasks in the asyncio
    executor.
    """
    if args.output_format == "parquet":
        from fastparquet import ParquetFile

    start_offset = 0
    processed_certificates = []
    server_clean_name = map_url_to_folder_name(server_url)
    output_path = args.output_dir + server_clean_name + "/"

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    try:
        existing_log_files = glob.glob('%s*' % output_path)
        if len(existing_log_files) > 0 :
            latest_file = max(existing_log_files, key=os.path.getctime)
            if args.output_format == "parquet" :
                pf = ParquetFile(latest_file)
                df = pf.to_pandas(['cert_index'])
                start_offset = int(df['cert_index'].max()) + 1
            else:
                with open(latest_file, "r", encoding='utf-8') as f:
                    last_line = f.readlines()[-1]
                    start_offset = int(last_line.split(CSV_SEPARATOR)[0]) + 1
            print("Restarting download for server [%s] at offset = %d." % \
                (server_url, start_offset))
    except Exception as e:
        print("Warning: unable to retrieve the last downloded offset for the" +\
        " server given (%s). Restarting from zero." % server_url)

    try:
        async with ParallelDownloader(httpClientSession, server_url, \
            start_offset, MAX_CONCURRENT_HTTP_REQUESTS_PER_SERVER) as \
            parallelDownloader:
            async for raw_certificate_batch in parallelDownloader:
                processed_certificates_batch = await process_certificate_batch(\
                        server_url, raw_certificate_batch, executor)
                if args.verbose:
                    print("Processed %d certificates for server %s" % \
                    (len(processed_certificates_batch), server_url))
                processed_certificates += processed_certificates_batch
                if len(processed_certificates) >= MAX_RECORDS_PER_OUTPUT_FILE:
                    try:
                        certificate_offset = \
                            processed_certificates[0]["cert_index"]
                        if args.output_format == "parquet" :
                            extension = "parquet"
                        else:
                            extension = "csv"
                        output_filename = output_path + "data-%d.%s" % \
                            (certificate_offset // MAX_RECORDS_PER_OUTPUT_FILE,
                            extension)
                        await write_certificates(output_filename, \
                                processed_certificates, executor, \
                                args.output_format)
                        processed_certificates = []
                    except Exception as e:
                        print("Error:", e)
    except Exception as e:
        print("Error:", e)

async def handle_all_log_servers(server_url_list, executor, args):
    """
    Asynchronous function that handles each CT log server: it enqueues a list of
    awaitable functions, one per CT log server, and give them to asyncio for
    them to be run concurrently (green thread).
    """
    async with aiohttp.ClientSession() as httpClientSession:
        tasks = []
        for server_url in server_url_list:
            task = handle_log_server(httpClientSession, server_url, executor,
                args)
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)


def main():
    
    parser = argparse.ArgumentParser(description='Crawler of Certificate " + \
        "Transparency log servers (CT logs servers).')
    parser.add_argument('-o', dest="output_dir", action="store", \
        default=DEST_FOLDER, help="The path of the output directory " + \
            "(the path will be recursively created")
    parser.add_argument('-f', dest="output_format", action="store", \
        default=OUTPUT_FORMAT, help="The format of the output files")
    parser.add_argument('-v', dest="verbose", action="store", \
        default=False, help="The verbosity of the output (can be True or False)")
    args = parser.parse_args()
    if args.output_dir[-1] != "/":
        args.output_dir += "/"


    if type(args.verbose) != bool:
        if args.verbose.lower() == "true":
            args.verbose = True
        else:
            args.verbose = False


    server_url_list = get_server_url_list()
    print("Parsing the list of server terminated (%d log servers found)" % \
            len(server_url_list))
    loop = asyncio.get_event_loop()
    with concurrent.futures.ProcessPoolExecutor() as executor:
        task = handle_all_log_servers(server_url_list, executor, args)
        loop.run_until_complete(task)
        loop.close()


if __name__ == "__main__":
    main()
