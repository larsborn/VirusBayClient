#!/usr/bin/env python3
import argparse
import logging
import os
import datetime
import json
import hashlib
import typing

import requests
import requests.adapters

__version__ = '1.0.0'


class FixedTimeoutAdapter(requests.adapters.HTTPAdapter):
    def send(self, *pargs, **kwargs):
        if kwargs['timeout'] is None:
            kwargs['timeout'] = 5
        return super(FixedTimeoutAdapter, self).send(*pargs, **kwargs)


class Md5:
    def __init__(self, md5):
        if len(md5) != 32:
            raise Exception(F'Invalid MD5 hash: "{repr(md5)}"')
        self.hash = md5

    @staticmethod
    def from_data(data):
        return Md5(hashlib.sha256(data).hexdigest())

    def __repr__(self):
        return F'<Md5 {self.hash}>'

    def __eq__(self, other):
        return self.hash == other.hash


class FeedComment:
    def __init__(self, owner_name, body, publish_date):
        self.owner_name = owner_name
        self.body = body
        self.publish_date = publish_date

    @staticmethod
    def from_api(comment):
        return FeedComment(
            comment['owner']['name'],
            comment['body'],
            comment['publishDate']
        )

    def __repr__(self):
        return F'<FeedComment ' \
               F'{self.owner_name} @{self.publish_date.strftime("%Y-%m-%d %H:%M:%S")} ' \
               F'len={len(self.body)}>'


class FeedEntry:
    def __init__(self):
        self.sample_md5 = None
        self.owner_name = None
        self.link = None
        self.malicious_link = None
        self.c2 = None
        self.like_count = None
        self.publish_date = None
        self.edit_date = None
        self.body = None
        self.comments = []  # type: typing.List[FeedComment]

    def __repr__(self):
        return F'<FeedEntry ' \
               F'{self.publish_date.strftime("%Y-%m-%d %H:%M:%S") if self.publish_date else ""} ' \
               F'{self.edit_date.strftime("%Y-%m-%d %H:%M:%S") if self.edit_date else ""} ' \
               F'{self.owner_name} {self.sample_md5.hash if self.sample_md5 else ""} comments={len(self.comments)}>'

    PROCESSED_KEYS = {
        'owner', 'sample', 'body', 'link', 'editDate', 'publishDate', 'likes', 'likedBy', 'comments', 'cAndC',
        'maliciousLink', 'image',
    }

    @staticmethod
    def from_api(row):
        for unprocessed_key in sorted(list(set(row.keys()) - FeedEntry.PROCESSED_KEYS)):
            if unprocessed_key.startswith('_'):
                continue
            logger.error(F'Unprocessed Key "{unprocessed_key}" {json.dumps(row[unprocessed_key])}')

        feed_entry = FeedEntry()
        if 'sample' in row.keys():
            feed_entry.sample_md5 = Md5(row['sample'])
        if 'owner' in row.keys() and 'name' in row['owner']:
            feed_entry.owner_name = row['owner']['name']
        if 'body' in row.keys():
            body = json.loads(row['body'])
            if 'blocks' in body.keys():
                feed_entry.body = '\n'.join([block['text'] for block in body['blocks']])
        if 'link' in row.keys() and row['link']:
            feed_entry.link = row['link']
        if 'maliciousLink' in row.keys():
            feed_entry.malicious_link = row['maliciousLink']
        if 'cAndC' in row.keys():
            feed_entry.c2 = row['cAndC']
        if 'comments' in row.keys() and row['comments']:
            feed_entry.comments += [FeedComment.from_api(comment) for comment in row['comments']]
        if 'likedBy' in row.keys() and row['likedBy']:
            print(json.dumps(row['likedBy']))
            raise NotImplementedError('"likedBy" not implemented')  # TODO find example
        if 'likes' in row.keys():
            feed_entry.like_count = row['likes']
        if 'publishDate' in row.keys():
            feed_entry.publish_date = datetime.datetime.strptime(row['publishDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if 'editDate' in row.keys():
            feed_entry.edit_date = datetime.datetime.strptime(row['editDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        return feed_entry


class VirusBayApiException(Exception):
    def __init__(self, error, description):
        self.error = error
        self.description = description


class VirusBayUserDetails:
    def __init__(self, email, name, company, first_login, qa_credit, is_manager, credit, role):
        self.email = email
        self.name = name
        self.company = company
        self.first_login = first_login
        self.qa_credit = qa_credit
        self.is_manager = is_manager
        self.credit = credit
        self.role = role

    @staticmethod
    def from_api(j):
        return VirusBayUserDetails(
            j['email'],
            j['name'],
            j['company'],
            j['firstLogin'],
            j['QAcredits'],
            j['isManager'],
            j['credit'],
            j['role'],
        )

    def __repr__(self):
        return F'<VirusBayUserDetails ' \
               F'role={self.role} is_manager={self.is_manager} first_login={self.first_login} ' \
               F'qa_credits={self.qa_credit} credits={self.credit}' \
               F'>'


class UploadDetails:
    def __init__(self, id, uploaded_by_name, md5, sha1, sha256, publish_date, tags, pending):
        self.id = id
        self.uploaded_by_name = uploaded_by_name
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.publish_date = publish_date
        self.tags = tags
        self.pending = pending

    @staticmethod
    def from_api(row):
        return UploadDetails(
            row['_id'],
            row['uploadedBy']['name'],
            row['md5'],
            row['sha1'],
            row['sha256'],
            datetime.datetime.strptime(row['publishDate'], '%Y-%m-%dT%H:%M:%S.%fZ'),
            [tag['lowerCaseName'] for tag in row['tags']],
            row['pending'],
        )

    def __repr__(self):
        return F'<UploadDetails id={self.id}>'


class VirusBayApi:
    BASE_URL = 'https://beta.virusbay.io'

    def __init__(self, user_name, password, user_agent):
        self.session = requests.session()
        self.session.mount('https://', FixedTimeoutAdapter())
        self.session.mount('http://', FixedTimeoutAdapter())
        self.session.headers = {'User-Agent': user_agent}
        self.user_name = user_name
        self.password = password

        self._token = None
        self.user_details = None

    def _get_token(self):
        if self._token is None:
            self._login()
        return self._token

    def _login(self):
        response = self.session.post(self.BASE_URL + '/login', json={
            'email': self.user_name,
            'password': self.password
        })
        logger.debug(F'Logging in with {self.user_name} and password of length {len(self.password)}')
        if response.status_code != 200:
            raise VirusBayApiException(F'Cannot login', response.content)
        j = response.json()
        if 'token' in j.keys():
            self._token = j['token']
            logger.debug(F'Got new token: {self._token}')
        else:
            raise VirusBayApiException(F'Cannot find token', json.dumps(j))
        if 'user' in j.keys():
            self.user_details = VirusBayUserDetails.from_api(j['user'])
            logger.info(self.user_details)

    def feed(self, p=0) -> typing.Iterator[FeedEntry]:
        response = self.session.get(self.BASE_URL + '/api/feed/posts/recent', headers={
            'authorization': F'JWT {self._get_token()}',
        }, params=(('p', p),))
        if response.status_code != 200:
            raise VirusBayApiException(F'Cannot request feed', response.content)
        for row in response.json():
            yield FeedEntry.from_api(row)

    def get_details(self, hash) -> UploadDetails:
        response = self.session.get(F'https://beta.virusbay.io/sample/data/{hash}', headers={
            'authority': 'beta.virusbay.io',
            'authorization': F'JWT {self._get_token()}',
        })
        if response.status_code != 200:
            raise VirusBayApiException(F'Cannot get object id for hash {hash}', response.content)

        return UploadDetails.from_api(response.json())

    def download(self, upload: UploadDetails) -> bytes:
        response = self.session.get(F'{self.BASE_URL}/api/sample/{upload.id}/download/link', headers={
            'authority': 'beta.virusbay.io',
            'authorization': F'JWT {self._get_token()}',
        })
        if response.status_code != 200:
            raise VirusBayApiException(F'Cannot download hash {hash}', response.content)

        download_link = response.content
        response = self.session.get(download_link)
        if response.status_code != 200:
            raise VirusBayApiException(F'Cannot download sample for hash {hash}', response.content)

        return response.content


class ConsoleHandler(logging.Handler):
    def emit(self, record):
        print('[%s] %s' % (record.levelname, record.msg))


class Storage:
    def __init__(self, file_name):
        if os.path.exists(file_name):
            with open(file_name, 'r') as fp:
                self.storage = json.load(fp)
        else:
            self.storage = []

    def save(self, file_name):
        with open(file_name, 'w') as fp:
            json.dump(sorted(self.storage, key=lambda x: x['publish_date']), fp, indent=4)

    def is_in(self, feed_entry: FeedEntry):
        for existing_entry in self.storage:
            if existing_entry['owner_name'] == feed_entry.owner_name \
                    and existing_entry['publish_date'] == self._for_json(feed_entry.publish_date) \
                    and existing_entry['edit_date'] == self._for_json(feed_entry.edit_date):
                return True
        return False

    def add(self, feed_entry: FeedEntry):
        self.storage.append({
            'owner_name': feed_entry.owner_name,
            'publish_date': self._for_json(feed_entry.publish_date),
            'edit_date': self._for_json(feed_entry.edit_date),
            'body': feed_entry.body,
            'malicious_link': feed_entry.malicious_link,
            'link': feed_entry.link,
            'c2': feed_entry.c2,
            'like_count': feed_entry.like_count,
            'sample_md5_hash': feed_entry.sample_md5.hash if feed_entry.sample_md5 else None,
            'comments': [{
                'owner_name': comment.owner_name,
                'body': comment.body,
                'publish_date': self._for_json(comment.publish_date),
            } for comment in feed_entry.comments]
        })

    @staticmethod
    def _for_json(data):
        if data is None:
            return None
        if isinstance(data, datetime.datetime):
            return data.strftime("%Y-%m-%d %H:%M:%S")
        return data

    def add_if_not_exists(self, feed_entry: FeedEntry):
        if not self.is_in(feed_entry):
            self.add(feed_entry)
            return True
        return False


if __name__ == '__main__':
    import platform

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    feed_parser = subparsers.add_parser('feed', help='Retrieve your personal feed from the page.')
    feed_parser.add_argument('-q', '--quiet', action='store_true', help='Do not print anything.')
    feed_parser.add_argument('-p', '--page', default=0, type=int, help='Page of seconds between polls.')
    feed_parser.add_argument('-c', '--page-count', default=1, type=int, help='Number of pages to pull.')
    feed_parser.add_argument('-s', '--store', help='Specify JSON file to store information in.')

    download_parser = subparsers.add_parser(
        'download',
        help='Specify hashes (as SHA256, MD5 or SHA1 to download sample).'
    )
    download_parser.add_argument('hashes', nargs='+')

    parser.add_argument('--user-name', default=os.getenv('VIRUSBAY_USER_NAME', None))
    parser.add_argument('--password', default=os.getenv('VIRUSBAY_PASSWORD', None))
    parser.add_argument('--debug', action='store_true')
    parser.add_argument(
        '--user-agent',
        default=F'VirusBayClient/{__version__} (python-requests {requests.__version__}) '
                F'{platform.system()} ({platform.release()})'
    )
    args = parser.parse_args()

    logger = logging.getLogger('VirusBayClient')
    logger.handlers.append(ConsoleHandler())
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    logger.debug(F'Using User-Agent string: {args.user_agent}')
    api = VirusBayApi(args.user_name, args.password, args.user_agent)
    try:
        if args.command == 'feed':
            storage = Storage(args.store) if args.store else None
            for page in range(args.page, args.page + args.page_count):
                new_entry_count = 0
                for entry in api.feed(page):
                    if storage:
                        if storage.add_if_not_exists(entry):
                            new_entry_count += 1
                    if not args.quiet:
                        print('')
                        if entry.publish_date:
                            print(F'=== {entry.publish_date.strftime("%Y-%m-%d %H:%M:%S")} by {entry.owner_name} ===')
                        else:
                            print('=========')
                        print(entry.body)
                        if entry.link:
                            print(F'Link: {entry.link}')
                        if entry.c2:
                            print(F'C2: {entry.c2}')
                        if entry.malicious_link:
                            print(F'Malicious Link: {entry.malicious_link}')
                logger.info(F'{new_entry_count} new entries on page {page}.')
                if not new_entry_count:
                    break
            if storage:
                storage.save(args.store)

        elif args.command == 'download':
            total_size = 0
            for sample_hash in args.hashes:
                if os.path.exists(sample_hash):
                    logger.warning(F'File with name "{sample_hash}" already exists, skipping download.')
                    continue
                logger.info(F'Querying for {sample_hash}...')
                upload = api.get_details(sample_hash)
                if os.path.exists(upload.sha256):
                    logger.warning(F'File with name "{upload.sha256}" already exists, not saving.')
                    continue
                logger.info(F'Sample exists on VirusBay: storing to "{upload.sha256}"')
                payload = api.download(upload)
                total_size += len(payload)
                with open(upload.sha256, 'wb') as fp:
                    fp.write(payload)
            logger.info(F'Downloaded a total of {total_size} bytes')

    except VirusBayApiException as e:
        logger.exception(e)
