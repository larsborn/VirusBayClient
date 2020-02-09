# VirusBay API Client
Python-based Client for the [virusbay.io] site.

## Installation

Requires at least Python 3.7 and the package `requests` to be installed. Fully compatible with being run in a virtual
environment. It is recommended to set the environment variable `VIRUSBAY_USER_NAME` and `VIRUSBAY_PASSWORD` accordingly.

## Example Usage
After aliasing the script `virusbay.py` to `virusbay` and setting the above-mentioned environment variable a session
to scrape a few pages from your personal feed may look like the following:

```Batch
> virusbay feed -store dump.json -quiet -page 0 -c 10
[INFO] <VirusBayUserDetails role=user is_manager=False first_login=False qa_credits=0 credits=1337>
[INFO] 4 new entries on page 0.
[INFO] 4 new entries on page 1.
[INFO] 4 new entries on page 2.
[INFO] 4 new entries on page 3.
[INFO] 4 new entries on page 4.
[INFO] 0 new entries on page 5.
```



[virusbay.io]: https://beta.virusbay.io/
