#!/usr/bin/env python3

# check generated report manually
# file=out.csv; t=$(grep -c ",True" "${file}"); f=$(grep -c ",False" "${file}"); echo "$t / ($f + $t)" | bc -l

# results 2021-03-20 (using HEAD and without following redirects)
# 98893 of 416222 HSTS set (19%)
# 88172 of 603387 No response (15%)

# for a minimal execution time tune the following parameters for your setup
# too aggressive numbers will result in many errors (no response from the target)
MAX_CLIENTS = 30 # max parallel connections
TIMEOUT = 100 # connect and request in seconds

LIMIT = 10**7 # limit number of URLs to checks
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '\
        '(KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36'
TEST_ENDPOINT = []
STATUS_SLEEP = 20 # seconds to sleep between status messages
HTTP_METHOD = "GET" # 
# if true check HSTS header in 1st response as well as 2nd response if 1st response is a redirect
FOLLOW_REDIRECT = False

import os
import glob
import csv
import argparse
import time
import numpy as np
from threading import Thread
import datetime
import multiprocessing
import logging
import functools
from socket import herror, gaierror, timeout
#from tornado.log import app_log, gen_log, access_log, LogFormatter
from tornado import (ioloop, gen, process)
from tornado.httputil import HTTPInputError
from tornado.simple_httpclient import (
        SimpleAsyncHTTPClient,
        HTTPStreamClosedError,
        HTTPTimeoutError,
        )
from tornado.httpclient import (
        AsyncHTTPClient,
        HTTPRequest,
        HTTPResponse,
        HTTPError,
        HTTPClientError,
        )

from tornado.netutil import (
    Resolver,
    OverrideResolver,
    _client_ssl_defaults,
    is_valid_ip,
)

def log_filter(record):
    pass

# supress error messages
logging.getLogger('tornado.general').addFilter(log_filter)
logging.getLogger('tornado.application').addFilter(log_filter)
logging.getLogger('tornado.simple_httpclient').addFilter(log_filter)
logging.getLogger('tornado.httpclient').addFilter(log_filter)
logging.getLogger('tornado.httpclient.HTTPClientError').addFilter(log_filter)
logging.getLogger('tornado.httputil').addFilter(log_filter)
logging.getLogger('tornado.simple_httpclient').addFilter(log_filter)
logging.getLogger("requests").addFilter(log_filter)

HTTP_ERRORS = (herror, gaierror, timeout, HTTPTimeoutError, HTTPStreamClosedError, HTTPInputError, HTTPClientError, ConnectionResetError, ConnectionRefusedError, OSError)

NUM_PROCS = multiprocessing.cpu_count()

logging.basicConfig(format='%(message)s', level=logging.INFO)

def time_log(start, limit, id, log_level):
    e = time.time()-start
    if e > limit:
        logging.getLogger().log(log_level, 'Elapsed time {}: {}'.format(id, datetime.timedelta(seconds = e)))


def fetch(http_client, url):
    return http_client.fetch(
        url,
        method=HTTP_METHOD,
        validate_cert=False,
        user_agent=USER_AGENT,
        connect_timeout=TIMEOUT,
        request_timeout=TIMEOUT,
        decompress_response=True,
        follow_redirects=False)

@gen.coroutine
def main(urls, taskID, csv_writer, follow_redirect = True):
    AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient", max_clients=MAX_CLIENTS)
    http_client = AsyncHTTPClient(force_instance=True)

    waiter = gen.WaitIterator(*[fetch(http_client, url) for idx, url in enumerate(urls)])
    waiter_redirect = None
    location = None
    redirects = []

    while not waiter.done():
        line = []
        error = ''
        r = None
        try:
            start = time.time()
            r = yield waiter.next()
            line = [ urls[waiter.current_index] ]
        except HTTPClientError as e:
            r = e.response
            if FOLLOW_REDIRECT and r and r.headers:
                location = r.headers.get('Location') \
                    if follow_redirect \
                    else None
                error = e
        except HTTP_ERRORS as e:
            if hasattr(e, "response"):
                r = e.response
            error = e
        finally:
            line = [ urls[waiter.current_index] ]
            status = "error"
            if r != None: # we have a response
                try:
                    status = False \
                        if None == r.headers.get('strict-transport-security') \
                        else True
                except HTTP_ERRORS as e:
                    error = e
            if status == False and location != None:
                redirects.append(location)
            else:
                line.append(status)
                line.append(error)
                csv_writer.writerow(line)

    iol = ioloop.IOLoop().current()
    iol.stop()
    return redirects


def work(urls, output_filename, taskID, num_hosts):
    with open(output_filename + "_" + str(taskID), 'w') as new_file:
        try:
            iol = ioloop.IOLoop().current()
            csv_writer = csv.writer(new_file)
            redirects = main(urls, taskID, csv_writer)
            iol.start()
            redirects = redirects.result()
            if FOLLOW_REDIRECT and len(redirects) > 0:
                print("Process {:d}: Start processing {} redirects".format(taskID, len(redirects)))
                iol = ioloop.IOLoop().current()
                main(redirects, taskID, csv_writer, follow_redirect = False)
                iol.start()
        except Exception as e:
            print(e)
            pass


# returns number of requests processed so far
def print_status(output_filenames, csv, start, total):
    if (total == 0): return
    count = no_hsts = hsts = errors = 0
    for f in output_filenames:
        with open(f, 'r') as outfile:
            for line in csv.reader(outfile):
                count += 1
                if line[1] == "True":
                    hsts += 1
                elif line[1] == "error":
                    errors += 1
                else:
                    no_hsts += 1
    elapsed = time.time()-start
    ratio = 0
    if (no_hsts + hsts > 0):
        print("elapsed: {}, "\
          "processed: {:d} ({:.0%}), "\
          "errors: {:d} ({:.0%}), "\
          "HSTS ratio: {:.0%}"\
        .format(
            datetime.timedelta(seconds = elapsed),
            count,
            count / total,
            errors,
            errors / count,
            hsts/(no_hsts+hsts),
            ))
    return count


if __name__ == "__main__":
    start = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", help="file to check")
    parser.add_argument("outfile", help="file to write result")
    args = parser.parse_args()

    input_filename = args.infile
    output_filename = args.outfile
    output_filename_glob = output_filename + "_*"

    try:
        num_hosts = 0
        with open(input_filename, 'r') as csv_file:
            urls = TEST_ENDPOINT
            for line in csv.reader(csv_file):
                if num_hosts >= LIMIT: break
                urls.append('https://www.{:s}/'.format(line[1]))
                num_hosts += 1
        a_urls = np.array_split(urls, NUM_PROCS)
        taskID = process.fork_processes(NUM_PROCS+1, max_restarts=0)
        if taskID != NUM_PROCS:
            work(a_urls[taskID], output_filename, taskID, num_hosts)
        else: # last process for status update
            nlines = 0
            while nlines < num_hosts - (STATUS_SLEEP * 200):
                nlines = print_status(glob.glob(output_filename_glob), csv, start, num_hosts)
                time.sleep(STATUS_SLEEP);
    except SystemExit as e: # all forked processes stopped
        try:
            with open(output_filename, 'w') as csv_file:
                csv_writer = csv.writer(csv_file)
                for f in glob.glob(output_filename_glob):
                    with open(f, 'r') as outfile:
                        for line in csv.reader(outfile):
                            csv_writer.writerow(line)
        finally:
            print_status([output_filename], csv, start, num_hosts)
            for f in glob.glob(output_filename_glob): os.remove(f)
