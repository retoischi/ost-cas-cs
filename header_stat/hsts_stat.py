#!/usr/bin/env python3

import argparse
import asyncio
import aiohttp
import glob
import multiprocessing
import os
import uvloop
import csv
import sys
import time
import datetime
import socket

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

TOTAL_TIMEOUT = 10
CONNECT_TIMEOUT = 5
RETRIES = 2
DNS_CACHE_TTL = 900
KEEPALIVE = 15
BATCH_SIZE = 16
FLUSH_INTERVAL = 0.5
POLL_INTERVAL = 2
TMP_DIR = "tmp"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}





async def check(session, idx, domain):
    url = f"https://{domain}/"
    for attempt in range(RETRIES):
        try:
            async with session.get(url, allow_redirects=True, max_redirects=5) as r:
                status = "True" if r.headers.get("Strict-Transport-Security") else "False"
                return idx, url, status
        except Exception:
            if attempt + 1 < RETRIES:
                await asyncio.sleep(0.1 * (2 ** attempt))
                continue
            return idx, url, "error"

def get_resolver():
    try:
        import aiodns
        return aiohttp.AsyncResolver(
            nameservers=["1.1.1.1", "8.8.8.8"]
        )
    except ImportError:
        raise RuntimeError("aiodns ist nicht installiert!")

async def run(infile, outfile, proc_id=0, num_procs=1, concurrency=None):
    domains = []
    total = 0
    with open(infile) as f:
        for i, row in enumerate(csv.reader(f)):
            if len(row) >= 2:
                if num_procs == 1 or (i % num_procs) == proc_id:
                    domains.append((i, row[1]))
                total += 1

    cookie_jar = aiohttp.CookieJar(unsafe=True)
    timeout = aiohttp.ClientTimeout(
        total=TOTAL_TIMEOUT,
        connect=CONNECT_TIMEOUT,
        sock_connect=CONNECT_TIMEOUT,
        sock_read=TOTAL_TIMEOUT,
    )

    resolver = get_resolver()
    procs = int(num_procs) if num_procs else 1
    effective_limit = max(10, concurrency // max(1, procs))
    limit_per_host = 10

    connector_args = dict(
        resolver=resolver,
        limit=effective_limit,
        limit_per_host=limit_per_host,
        ttl_dns_cache=DNS_CACHE_TTL,
        use_dns_cache=True,
        enable_cleanup_closed=True,
        family=socket.AF_INET,
        keepalive_timeout=KEEPALIVE,
    )
    try:
        connector = aiohttp.TCPConnector(**connector_args)
    except TypeError:
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            family=socket.AF_INET,
        )

    done = hsts = no_hsts = errors = 0
    start = time.time()

    # Ensure tmp dir exists
    os.makedirs(TMP_DIR, exist_ok=True)

    out_name = outfile if num_procs == 1 else os.path.join(TMP_DIR, f"{os.path.basename(outfile)}_{proc_id}")
    out_f = open(out_name, "w", newline="")
    csv_writer = csv.writer(out_f)
    write_lock = asyncio.Lock()

    async with aiohttp.ClientSession(
        headers=HEADERS,
        timeout=timeout,
        cookie_jar=cookie_jar,
        connector=connector,
    ) as session:

        queue = asyncio.Queue()
        for i, d in domains:
            queue.put_nowait((i, d))

        last_print = start

        async def worker():
            nonlocal done, hsts, no_hsts, errors, last_print
            buf = []
            last_flush = time.time()

            while True:
                try:
                    idx, domain = await queue.get()
                except asyncio.CancelledError:
                    break

                res = await check(session, idx, domain)

                done += 1
                if res[2] == "True":
                    hsts += 1
                elif res[2] == "False":
                    no_hsts += 1
                else:
                    errors += 1

                buf.append(res)
                now = time.time()

                if len(buf) >= BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL:
                    async with write_lock:
                        for r in buf:
                            csv_writer.writerow(r)
                        out_f.flush()
                    buf.clear()
                    last_flush = now

                if now - last_print >= POLL_INTERVAL:
                    elapsed = int(now - start)
                    speed = done // elapsed if elapsed else 0
                    responding = hsts + no_hsts
                    ratio = hsts / responding if responding else 0

                    sys.stdout.write(
                        f"\relapsed: {datetime.timedelta(seconds=elapsed)}, "
                        f"processed: {done}/{total} ({done/total:.0%}), "
                        f"speed: {speed}/s, "
                        f"errors: {errors} ({errors/done:.0%}), "
                        f"HSTS ratio: {ratio:.0%}\n"
                    )
                    sys.stdout.flush()
                    last_print = now

                queue.task_done()

        workers = [
            asyncio.create_task(worker())
            for _ in range(min(effective_limit, len(domains) or 1))
        ]

        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        print()

    out_f.close()



def _run_child(proc_id, num_procs, infile, outfile, concurrency):
    try:
        os.makedirs(TMP_DIR, exist_ok=True)
    except Exception:
        pass
    logfn = os.path.join(TMP_DIR, f"{os.path.basename(outfile)}_{proc_id}.log")
    sys.stdout = open(logfn, "w")
    sys.stderr = sys.stdout
    asyncio.run(
        run(
            infile,
            outfile,
            proc_id=proc_id,
            num_procs=num_procs,
            concurrency=concurrency,
        )
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("infile")
    parser.add_argument("outfile")
    parser.add_argument("-p", "--procs", type=int, default=300)
    parser.add_argument("-c", "--clients", type=int, default=700)
    args = parser.parse_args()

    if args.procs <= 1:
        asyncio.run(
            run(
                args.infile,
                args.outfile,
                concurrency=args.clients,
            )
        )
        sys.exit(0)


    # Calculate total_hosts for progress reporting
    total_hosts = 0
    with open(args.infile) as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                total_hosts += 1

    procs = []
    for pid in range(args.procs):
        p = multiprocessing.Process(
            target=_run_child,
            args=(pid, args.procs, args.infile, args.outfile, args.clients),
        )
        p.start()
        procs.append(p)

    def print_status(files, start, total):
        count = hsts = no_hsts = errors = 0
        seen = set()

        for fn in files:
            if fn.endswith(".log"):
                continue
            try:
                with open(fn) as f:
                    for row in csv.reader(f):
                        if len(row) < 3:
                            continue
                        idx = row[0]
                        if idx in seen:
                            continue
                        seen.add(idx)
                        count += 1
                        if row[2] == "True":
                            hsts += 1
                        elif row[2] == "False":
                            no_hsts += 1
                        else:
                            errors += 1
            except OSError:
                continue

        elapsed = int(time.time() - start)
        speed = round(count / elapsed) if elapsed else 0

        sys.stdout.write(
            "\relapsed: {}, processed: {:d} ({:.0%}), speed: {:d}/s, errors: {:d} ({:.0%}), HSTS ratio: {:.0%}".format(
                datetime.timedelta(seconds=elapsed),
                count,
                count / total if total else 0,
                speed,
                errors,
                errors / count if count else 0,
                hsts / (hsts + no_hsts) if (hsts + no_hsts) else 0,
            )
        )
        sys.stdout.flush()
        return count

    start = time.time()
    base = os.path.basename(args.outfile)

    while any(p.is_alive() for p in procs):
        files = [f for f in glob.glob(os.path.join(TMP_DIR, base + "_*")) if not f.endswith(".log")]
        print_status(files, start, total_hosts)
        time.sleep(1)

    print()
    files = [f for f in glob.glob(os.path.join(TMP_DIR, base + "_*")) if not f.endswith(".log")]
    print_status(files, start, total_hosts)

    for p in procs:
        p.join()

    # Aggregate shard files from tmp/ into final output
    rows = {}
    for fn in [f for f in glob.glob(os.path.join(TMP_DIR, base + "_*") ) if not f.endswith(".log")]:
        try:
            with open(fn) as f:
                for row in csv.reader(f):
                    if len(row) < 3:
                        continue
                    idx = row[0]
                    if idx not in rows:
                        rows[idx] = row[:3]
        except OSError:
            continue

    # Sort by index
    sorted_rows = sorted(rows.values(), key=lambda r: int(r[0]))

    with open(args.outfile, "w") as out:
        writer = csv.writer(out)
        for r in sorted_rows:
            writer.writerow(r)



    # Clean up shard files
    for fn in [f for f in glob.glob(os.path.join(TMP_DIR, base + "_*") ) if not f.endswith(".log")]:
        try:
            os.remove(fn)
        except OSError:
            pass

