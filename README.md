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

Similarly, this client can also be used to download single samples from VirusBay

```Batch
> virusbay download 890a58f200dfff23165df9e1b088e58f
[INFO] Querying for 890a58f200dfff23165df9e1b088e58f...
[INFO] <VirusBayUserDetails role=user is_manager=False first_login=False qa_credits=0 credits=8>
[INFO] Sample exists on VirusBay: storing to "5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93"
[INFO] Downloaded a total of 167936 bytes
```

or to list / download the most recent list of samples:

```Batch
> virusbay list -s list.json -d
[INFO] <VirusBayUserDetails role=user is_manager=False first_login=False qa_credits=0 credits=1234>
[INFO] Downloading sample with hash 5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93...
[INFO] Downloading sample with hash 0bc2c1ac8a746819cef49df2747fd7fe5d890d2146be14a4d657df807e8dfd0d...
[INFO] Downloading sample with hash bc7e55048478507b6734c8314857f33309f663ff4f3c3cb65e653a5b308f0bd5...
[INFO] Downloading sample with hash e90b970c5e5ddf821d6f9f4d7d710d6dc01d59b517e8fb39da726803dc52b5ad...
[INFO] File with name 83b42646d4983820855cd93cbcccf9afd7a235692b82bf3ec4b3365873c8767a already exists, not downloading
...
```



[virusbay.io]: https://beta.virusbay.io/
