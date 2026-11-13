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

Fetching ``robots.txt`` is up to you, and so are the parts of `RFC 9309`_ that
govern it, such as the handling of HTTP status codes and redirects, caching, and
imposing a parsing limit.

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


Managed fetching and caching
============================

``RobotsManager`` adds the fetching and caching side of `RFC 9309`_ without
adding an HTTP client dependency to Protego.  The caller injects both the HTTP
callback and the clock, so the manager is easy to integrate with any client
and can be tested without waiting for wall-clock time:

.. code-block:: pycon

   >>> from protego import RobotsManager, RobotsResponse
   >>> def fetch(request):
   ...     # request is a RobotsRequest: use request.headers for
   ...     # If-None-Match / If-Modified-Since when they are present.
   ...     return RobotsResponse(
   ...         200,
   ...         "User-agent: *\nDisallow: /private\n",
   ...         {"ETag": '"v1"'},
   ...         "https://example.com/robots.txt",
   ...     )
   >>> manager = RobotsManager(fetch, clock=lambda: 0.0)
   >>> decision = manager.decision("https://example.com/private", "mybot")
   >>> decision.decision
   <Decision.DISALLOW: 'disallow'>
   >>> decision.version
   '"v1"'
   >>> decision.stale
   False

The fetch callback may take either a :class:`RobotsRequest` or a URL; the
manager inspects its signature and passes conditional validators when the
callback accepts them.  A result may be a :class:`RobotsResponse`, a
requests-style object, a mapping, or a tuple.  The optional final URL in a
result describes the address reached after redirects, but the cache is always
keyed by the original ``(scheme, host, effective port)``.  A redirect to
another origin therefore cannot replace the identity of the origin whose
policy is being stored.

The state rules are explicit:

*   ``2xx``: parse the body and store it with its ``ETag`` /
    ``Last-Modified`` validators (or a content hash when neither is present).
*   ``304``: reuse the stored policy and refresh its validation time; the
    stored version is reported unchanged.
*   ``4xx``: ``robots.txt`` is unavailable, so everything is allowed.  This
    availability state is cached like a successful result.
*   ``5xx`` or a network error: ``robots.txt`` is temporarily unreachable.
    A stored policy is reused (and marked ``stale``); without a stored policy
    the decision is ``UNKNOWN``, never an unconditional allow.
*   A successful fetch or ``304`` resets the failure count.  Repeated failures
    keep using the same stored policy and increment ``consecutive_failures``.

The default cache lifetime is 24 hours after the last successful fetch or
revalidation.  A stale policy is revalidated conditionally; if revalidation
fails, the previous policy continues to apply.  ``RobotsDecision.stale`` says
whether that policy was reused after a failed refresh (or is older than the
cache lifetime), ``fallback`` says whether it was used because the refresh
failed, and ``version`` reports the policy version actually used.

Redirects are followed for at least five consecutive hops; more than five
hops, a missing ``Location`` header, or a redirect loop is treated as
unreachable.  Cross-origin redirects are followed, but their content applies
to the original origin only.  A callback that follows redirects internally
can report the final address and the number of redirects in its result.

State is isolated by scheme, host, and effective port.  ``http`` defaults to
port 80 and ``https`` to port 443, so ``http://example.com`` and
``http://example.com:80`` share an entry, while a different scheme or an
explicit non-default port (for example ``:8080``) has its own entry.


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

Class ``protego.RobotsManager``:

*   ``RobotsManager(fetch, clock, ...)`` Create a manager.  ``fetch`` is the
    injectable HTTP callback and ``clock`` is a callable returning seconds or
    a ``datetime``.  ``cache_ttl`` defaults to 86400 seconds and
    ``max_redirects`` to 5.

*   ``decision(url, user_agent)`` Return a ``RobotsDecision`` with the current
    ``decision`` (``ALLOW``, ``DISALLOW``, or ``UNKNOWN``), the adopted
    ``version``, and the ``stale`` flag.  A fresh cache is used without a
    fetch.

*   ``fetch(url)`` / ``refresh(url)`` Force a conditional fetch or
    revalidation.  ``update(url)`` fetches only when the entry is absent or
    stale.

*   ``predicate`` helpers: ``allowed`` is ``True``, ``False``, or ``None``;
    ``can_fetch()`` returns the same result object (truthy only for an allow).
    The result also exposes ``policy``, ``state``, ``status``, ``final_url``,
    ``fetched_at``, ``consecutive_failures``, and ``revision``.
