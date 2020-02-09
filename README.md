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

Similarly, this client can also be used to download samples from VirusBay
```Batch
> virusbay download 890a58f200dfff23165df9e1b088e58f
[INFO] Querying for 890a58f200dfff23165df9e1b088e58f...
[INFO] <VirusBayUserDetails role=user is_manager=False first_login=False qa_credits=0 credits=8>
[INFO] Sample exists on VirusBay: storing to "5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93"
[INFO] Downloaded a total of 167936 bytes
```



[virusbay.io]: https://beta.virusbay.io/
