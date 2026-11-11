=======
Protego
=======

.. image:: https://img.shields.io/pypi/pyversions/protego.svg
   :target: https://pypi.python.org/pypi/protego
   :alt: Supported Python Versions

.. image:: https://github.com/scrapy/protego/actions/workflows/tests-ubuntu.yml/badge.svg
   :target: https://github.com/scrapy/protego/actions/workflows/tests-ubuntu.yml
   :alt: CI

Protego is a pure-Python ``robots.txt`` parser. It implements the parsing and
URL matching rules of `RFC 9309`_, and additionally supports the
``Crawl-delay``, ``Request-rate``, ``Visit-time`` and ``Host`` extensions.

The parser only reads ``robots.txt`` content. The parts of `RFC 9309`_ that
govern fetching, such as the handling of HTTP status codes and redirects,
caching, and imposing a parsing limit, live in ``RobotsTxtManager``. The
manager performs no network I/O itself: you inject a fetch callback and a
clock, so Protego keeps no network client dependency.

.. _RFC 9309: https://www.rfc-editor.org/rfc/rfc9309.html


Install
=======

To install Protego, simply use pip:

.. code-block:: none

    pip install protego


Usage
=====

.. code-block:: pycon

   >>> from protego import Protego
   >>> robotstxt = """
   ... User-agent: *
   ... Disallow: /
   ... Allow: /about
   ... Allow: /account
   ... Disallow: /account/contact$
   ... Disallow: /account/*/profile
   ... Crawl-delay: 4
   ... Request-rate: 10/1m                 # 10 requests every 1 minute
   ...
   ... Sitemap: http://example.com/sitemap-index.xml
   ... Host: http://example.co.in
   ... """
   >>> rp = Protego.parse(robotstxt)
   >>> rp.can_fetch("http://example.com/profiles", "mybot")
   False
   >>> rp.can_fetch("http://example.com/about", "mybot")
   True
   >>> rp.can_fetch("http://example.com/account", "mybot")
   True
   >>> rp.can_fetch("http://example.com/account/myuser/profile", "mybot")
   False
   >>> rp.can_fetch("http://example.com/account/contact", "mybot")
   False
   >>> rp.crawl_delay("mybot")
   4.0
   >>> rp.request_rate("mybot")
   RequestRate(requests=10, seconds=60, start_time=None, end_time=None)
   >>> list(rp.sitemaps)
   ['http://example.com/sitemap-index.xml']
   >>> rp.preferred_host
   'http://example.co.in'


Using Protego with Requests_:

.. code-block:: pycon

   >>> from protego import Protego
   >>> import requests
   >>> r = requests.get("https://google.com/robots.txt")
   >>> rp = Protego.parse(r.text)
   >>> rp.can_fetch("https://google.com/search", "mybot")
   False
   >>> rp.can_fetch("https://google.com/search/about", "mybot")
   True
   >>> list(rp.sitemaps)
   ['https://www.google.com/sitemap.xml']

.. _Requests: https://3.python-requests.org/


Managing robots.txt with ``RobotsTxtManager``
=============================================

``RobotsTxtManager`` centralizes the fetch-time rules of `RFC 9309`_ so that
callers no longer have to handle 404, 304 and 503 answers each in their own
way. It keeps one state per origin, keyed by scheme, host and effective port,
and gets both HTTP and time from callbacks you inject.

.. code-block:: pycon

   >>> import time
   >>> import requests
   >>> from protego import RobotsFetchRequest, RobotsFetchResult, RobotsTxtManager
   >>>
   >>> def fetcher(request: RobotsFetchRequest) -> RobotsFetchResult:
   ...     headers = {}
   ...     if request.if_none_match:
   ...         headers["If-None-Match"] = request.if_none_match
   ...     if request.if_modified_since:
   ...         headers["If-Modified-Since"] = request.if_modified_since
   ...     response = requests.get(request.url, headers=headers, timeout=10)
   ...     return RobotsFetchResult(
   ...         status=response.status_code,
   ...         final_url=response.url,
   ...         body=response.text,
   ...         etag=response.headers.get("ETag"),
   ...         last_modified=response.headers.get("Last-Modified"),
   ...         retry_after=response.headers.get("Retry-After"),
   ...         location=response.headers.get("Location"),
   ...     )
   >>>
   >>> manager = RobotsTxtManager(fetcher, clock=time.monotonic)
   >>> manager.refresh("https://example.com/")
   <RobotsStatus.FETCHED: 'fetched'>
   >>> manager.can_fetch("https://example.com/private", "mybot")
   False

The status code rules of RFC 9309 section 2.3.1.2 are encoded as explicit
states:

*   ``200`` parses a new policy and stores its ``ETag``/``Last-Modified``
    validators.
*   ``304`` to a conditional request reuses the cached policy.
*   Any other ``4xx`` means the origin has no ``robots.txt`` and is fully
    crawlable.
*   ``429``, ``5xx`` and network failures mark the origin temporarily
    unreachable. A previously cached policy keeps being enforced, flagged as
    stale; with no cached policy the decision is ``unknown``, never a silent
    allow.
*   Redirects (including cross-origin) are followed for at most five hops per
    section 2.3.1.3. The fetched policy always stays attached to the origin
    that initiated the fetch; the final address is reported but never changes
    that origin's identity.

Use ``evaluate`` to inspect the decision instead of acting on a bare boolean:

.. code-block:: pycon

   >>> evaluation = manager.evaluate("https://example.com/private", "mybot")
   >>> evaluation.decision, evaluation.status, evaluation.version, evaluation.stale
   (<RobotsDecision.DISALLOWED: 'disallowed'>, <RobotsStatus.FETCHED: 'fetched'>, <RobotsVersion.FRESH: 'fresh'>, False)

Caching is driven entirely by the injected clock, so advancing a scripted
clock is enough to force revalidation without any real waiting.


Comparison
==========

The following table compares Protego to the most popular ``robots.txt`` parsers
implemented in Python. Performance is the speed difference against Protego, so
a positive value means faster than Protego. It is measured over the
``robots.txt`` of 100 of the most visited websites: the time taken to check the
URLs their homepages link to, and the time taken to parse the files themselves.

.. The table below is generated by benchmarks/compare.py. Regenerate it
   rather than editing it by hand.

   Its feature rows are probe results against the exact releases named in
   "Version tested", not claims about the parsers in general. RobotFileParser
   is the one that moves: CPython taught urllib.robotparser the RFC 9309
   wildcards and longest-match precedence during the 3.14 series, after
   3.14.3. Generated on 3.14.3 or older, its wildcard and length-based
   precedence cells come out empty; generated on a later 3.14 they carry a
   checkmark. Both are what the probes measured on that interpreter, so do not
   flip those two cells by hand in either direction.

.. comparison-table-start

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - Protego
     - RobotFileParser
     - robotspy
     - Robotexclusionrulesparser
   * - Version tested
     -
     - Python 3.14.7
     - 0.13.0
     - 1.7.1
   * - Reference specification
     - `RFC 9309`_
     - `Martijn Koster's 1996 draft`_
     - `RFC 9309`_
     - `Martijn Koster's 1996 draft`_
   * - `Wildcard support`_
     - ✓
     - ✓
     - ✓
     - ✓
   * - `Length-based precedence`_
     - ✓
     - ✓
     - ✓
     -
   * - Crawl-delay
     - ✓
     - ✓
     -
     -
   * - Request-rate
     - ✓
     -
     -
     -
   * - Visit-time
     - ✓
     -
     -
     -
   * - Sitemaps
     - ✓
     - ✓
     - ✓
     - ✓
   * - Host
     - ✓
     -
     -
     -
   * - Matching performance
     -
     - -75%
     - -83%
     - -98%
   * - Parsing performance
     -
     - -71%
     - +32%
     - +54%

.. comparison-table-end

.. _Length-based precedence: https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.2
.. _Martijn Koster's 1996 draft: https://www.robotstxt.org/norobots-rfc.txt
.. _Wildcard support: https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.3


API Reference
=============

Class ``protego.Protego``:

Properties
----------

*   ``sitemaps`` {``list_iterator``} A list of sitemaps specified in
    ``robots.txt``.

*   ``preferred_host`` {string} Preferred host specified in ``robots.txt``.


Methods
-------

*   ``parse(robotstxt_body)`` Parse ``robots.txt`` and return a new instance of
    ``protego.Protego``.

*   ``can_fetch(url, user_agent)`` Return True if the user agent can fetch the
    URL, otherwise return ``False``.

    *user_agent* may be a product token, such as ``"mybot"``, or a whole
    ``User-Agent`` header value, such as ``"Mozilla/5.0 (compatible;
    mybot/1.0)"``; a group applies when its product token appears in
    *user_agent* at a token boundary.

*   ``crawl_delay(user_agent)`` Return the crawl delay specified for the user
    agent as a float. If nothing is specified, return ``None``.

*   ``request_rate(user_agent)`` Return the request rate specified for the user
    agent as a named tuple ``RequestRate(requests, seconds, start_time,
    end_time)``. If nothing is specified, return ``None``.

*   ``visit_time(user_agent)`` Return the visit time specified for the user
    agent as a named tuple ``VisitTime(start_time, end_time)``.
    If nothing is specified, return ``None``.

Class ``protego.RobotsTxtManager``:

Construction
------------

*   ``RobotsTxtManager(fetcher, *, clock=None, cache_ttl_seconds=86400,
    unavailable_ttl_seconds=3600, default_retry_after_seconds=3600,
    max_redirects=5)`` ``fetcher`` is a callable taking a
    :class:`RobotsFetchRequest` and returning a :class:`RobotsFetchResult`;
    ``clock`` is an optional zero-argument callable returning the current time
    in seconds (defaults to a monotonic clock).

Methods
-------

*   ``refresh(url)`` Fetch or revalidate the ``robots.txt`` of the origin of
    ``url``, honoring the cached state and clock, and return the resulting
    :class:`RobotsStatus`. A fetch is skipped while the state is fresh.

*   ``evaluate(url, user_agent)`` Return a :class:`RobotsEvaluation` with the
    current :class:`RobotsDecision`, :class:`RobotsStatus`,
    :class:`RobotsVersion` and a ``stale`` flag, without fetching. An origin
    with no established policy reports ``RobotsDecision.UNKNOWN``.

*   ``can_fetch(url, user_agent)`` Return ``True`` only when a known policy
    explicitly allows ``url``; ``UNKNOWN`` decisions are not allowed.

*   ``get_state(url)`` Return a frozen :class:`RobotsOriginStateView` snapshot
    of the origin's cached state.

*   ``origin_key(url)`` Return the ``scheme://host[:port]`` identity used to
    isolate state, with default scheme ports normalized away.

Supporting types
----------------

*   ``RobotsFetchRequest`` The URL to fetch plus optional
    ``if_none_match``/``if_modified_since`` validators.

*   ``RobotsFetchResult`` The callback's answer: ``status`` (``None`` for a
    network failure), ``final_url``, optional ``body``, ``etag``,
    ``last_modified``, redirect ``location`` and ``retry_after``.

*   ``RobotsStatus`` One of ``unknown``, ``fetched``, ``revalidated``,
    ``unavailable``, ``temporarily_unreachable`` or ``error``.

*   ``RobotsDecision`` One of ``allowed``, ``disallowed`` or ``unknown``.

*   ``RobotsVersion`` One of ``fresh``, ``stale`` or ``none``.
