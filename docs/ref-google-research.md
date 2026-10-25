# Browserless Google web search through Docs research

Validated on 2026-10-25 with ordinary macOS curl and with wafer's core
dependencies. Google's Docs research endpoint returned general web results,
including distinct second pages. It does not require wafer, TLS impersonation,
a browser, a JavaScript runtime, login, or authentication cookies. Existing
`SyncSession` and `AsyncSession` also work without a wafer update.

For implementing this in fetchaller, use the detailed
[developer handoff](google-search-fetchaller-handoff.md) and
[verified document pool](google-search-document-pool.json). The Python examples
below demonstrate compatible clients; wafer is optional for this API.

The endpoint searches the web. The document ID supplies an eligible request
context; it does not restrict results to that document, Google Docs, or Scholar.
Observed results included IKEA product pages, Parks Canada, National Geographic,
Python documentation, and Reddit threads. `site:reddit.com` returned ten Reddit
results on each of two distinct pages.

This is a separate route from the `/search` SearchGuard solver, whose Google
acceptance remains unconfirmed. Equivalence to the ranking and filters of the
normal Google results page has not been established.

## Request and response

POST to:

```text
https://docs.google.com/document/d/{document_id}/explore/search
```

The form field `request` contains a JSON array. Google returns an XSSI prefix
followed by JSON. The first response message holds result records and the next
cursor. Use that returned cursor for pagination; ten- and twenty-result requests
were both tested. Knowledge cards can occupy records, so the number of organic
links may be below the requested count.

These helpers only build the request and decode the response:

```python
import json
from urllib.parse import quote


def google_research_request(document_id, query, *, cursor="CAA=", count=10,
                            language="en"):
    if not 1 <= count <= 20:
        raise ValueError("count must be between 1 and 20")
    payload = [
        "documentsuggest.search.search_request",
        query,
        [count, cursor],
        [language, language],
        1,
    ]
    return {
        "url": (
            "https://docs.google.com/document/d/"
            + quote(document_id, safe="") + "/explore/search"
        ),
        "form": {"request": json.dumps(payload, ensure_ascii=False)},
        "headers": {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
    }


def read_google_research_page(response):
    if response.status_code != 200:
        raise RuntimeError(f"Google research returned HTTP {response.status_code}")
    body = response.text
    if body.startswith(")]}'"):
        body = body.partition("\n")[2]
    data = json.loads(body)
    message = data[0]
    if message[0] != "documentsuggest.search.search_response":
        raise ValueError("Unexpected Google research response")
    results = []
    records = message[1] if len(message) > 1 and message[1] is not None else []
    for record in records:
        item = record[0]
        if (isinstance(item, list) and len(item) >= 3
                and isinstance(item[0], str)
                and item[0].startswith(("https://", "http://"))):
            results.append({"url": item[0], "title": item[1], "snippet": item[2]})
    cursor = message[2] if len(message) > 2 else None
    return results, cursor or None
```

Supply an eligible publicly readable document ID. Three publicly linked
Kubernetes community documents passed ordinary curl searches and pagination;
their IDs, titles, source links, and validation counts are recorded in the
[verified pool](google-search-document-pool.json). Fetchaller should load the
array and implement bounded failover as described in the handoff.

The original tested ID, `1X8Gd2RPfsQdiYVcrUmgk_RpQ7iAl-UQd9vlvpZ8Itvs`,
identifies **10 Ways to Use the Web for Verification**. It was taken from the
reference implementation, not generated randomly. Several Google/Go examples
returned 401, so public visibility alone does not establish search eligibility.
This legacy endpoint and document eligibility remain material dependencies;
this is not the supported Google Custom Search API.

## Synchronous session

```python
from wafer import SyncSession

document_id = "1RvhQAEIrVLHbyNnuaT99-6u9ZUMp7BfkPupT2LAZK7w"
query = "IKEA Canada desk"

with SyncSession(follow_redirects=False, rate_limit=6,
                 max_retries=0, max_rotations=0) as session:
    response = session.post(**google_research_request(document_id, query))
    first_page, cursor = read_google_research_page(response)
    if cursor:
        response = session.post(**google_research_request(
            document_id, query, cursor=cursor))
        second_page, cursor = read_google_research_page(response)
```

## Asynchronous session

```python
from wafer import AsyncSession

async def search_two_pages(document_id, query):
    async with AsyncSession(follow_redirects=False, rate_limit=6,
                            max_retries=0, max_rotations=0) as session:
        response = await session.post(**google_research_request(document_id, query))
        first_page, cursor = read_google_research_page(response)
        second_page = []
        if cursor:
            response = await session.post(**google_research_request(
                document_id, query, cursor=cursor))
            second_page, cursor = read_google_research_page(response)
        return first_page, second_page
```

Both recipes disable redirect following. A redirect or non-200 response is a
failed request; do not follow `/sorry` or an authentication redirect.

The route was discovered through the
[SearXNG discussion](https://github.com/searxng/searxng/issues/6359) and the
[public request implementation](https://github.com/vojkovic/priv/blob/main/src/engines/google_docs.c).
The results and pagination described above were verified directly with wafer.
