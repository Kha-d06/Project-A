"""Load test for the browser-extension check endpoint (the busiest path).

Run against a private instance started with SENTINEL_RATE_LIMIT_MULTIPLIER=1000:
    python scripts/loadtest.py --base http://localhost:8000 --seconds 20 --concurrency 32

Each simulated browser enrolls once, then checks a mix of addresses: most are
repeats (people revisit sites), some are new. Reports throughput and latency.
"""

import argparse
import asyncio
import random
import statistics
import time

import httpx

DOMAINS = [f"site{n}.example.org" for n in range(400)] + ["malware.example.net", "paypa1-login.example.com"]


async def browser(client: httpx.AsyncClient, base: str, deadline: float, latencies: list[float], errors: list[int]) -> None:
    enrolled = await client.post(f"{base}/api/v1/extension/enroll", json={"browser": "chrome", "version": "load"})
    token = enrolled.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    rng = random.Random()
    while time.monotonic() < deadline:
        # Popular sites dominate browsing, so draw from a skewed distribution.
        domain = DOMAINS[min(int(rng.paretovariate(1.2)) - 1, len(DOMAINS) - 1)] if rng.random() < 0.8 else rng.choice(DOMAINS)
        url = f"https://{domain}/page/{rng.randint(1, 5)}"
        started = time.perf_counter()
        response = await client.post(f"{base}/api/v1/extension/check-url", json={"url": url, "mode": "full"}, headers=headers)
        latencies.append((time.perf_counter() - started) * 1000)
        if response.status_code != 200:
            errors.append(response.status_code)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:8000")
    parser.add_argument("--seconds", type=float, default=20)
    parser.add_argument("--concurrency", type=int, default=32)
    args = parser.parse_args()
    latencies: list[float] = []
    errors: list[int] = []
    deadline = time.monotonic() + args.seconds
    async with httpx.AsyncClient(timeout=30, limits=httpx.Limits(max_connections=args.concurrency * 2)) as client:
        await asyncio.gather(*(browser(client, args.base, deadline, latencies, errors) for _ in range(args.concurrency)))
    latencies.sort()
    count = len(latencies)
    pct = lambda p: latencies[min(count - 1, int(count * p))]  # noqa: E731
    print(f"requests: {count} in {args.seconds:.0f}s = {count / args.seconds:.0f}/s with {args.concurrency} concurrent browsers")
    print(f"latency ms: p50 {pct(0.5):.1f}  p95 {pct(0.95):.1f}  p99 {pct(0.99):.1f}  mean {statistics.mean(latencies):.1f}")
    print(f"errors: {len(errors)} {sorted(set(errors))}")


if __name__ == "__main__":
    asyncio.run(main())
