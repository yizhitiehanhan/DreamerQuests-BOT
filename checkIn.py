import asyncio
import sys
from curl_cffi.requests import AsyncSession
from loguru import logger
from web3 import AsyncWeb3
from urllib.parse import urlparse, parse_qs
import requests.utils


logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "twitter.com",
            "origin": "https://twitter.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120)
        self.authenticity_token, self.oauth_verifier = None, None

    async def get_twitter_token(self, oauth_token):
        try:
            response = await self.Twitter.get(f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}')
            if 'authenticity_token' in response.text:
                self.authenticity_token = response.text.split('authenticity_token" value="')[1].split('"')[0]
                return True
            logger.error(f'获取authenticity_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self, oauth_token):
        try:
            if not await self.get_twitter_token(oauth_token):
                return False
            data = {
                'authenticity_token': self.authenticity_token,
                'oauth_token': oauth_token
            }
            response = await self.Twitter.post('https://api.twitter.com/oauth/authorize', data=data)
            if 'oauth_verifier' in response.text:
                self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
                return True
            return False
        except Exception as e:
            logger.error(e)
            return False


class Dreamer:
    def __init__(self, auth_token,proxy):
        self.client = AsyncSession(timeout=120, impersonate="chrome120", proxy=proxy)
        self.twitter = Twitter(auth_token)
        self.auth_token=auth_token
        self.proxy=proxy

    async def getOauth(self):
        try:
            res = await self.client.get('https://server.partofdream.io/user/auth/twitter')
            if res.status_code == 200:
                parsed_url = urlparse(res.url)
                query_params = parse_qs(parsed_url.query)
                oauth_token = query_params.get("oauth_token", [""])[0]
                return await self.login(oauth_token)
            logger.error(f'{[self.auth_token]} 获取oauth_token失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.auth_token]} 获取oauth_token失败: {e}')
            return False
        
    async def login(self, oauth_token):
        try:
            if not await self.twitter.twitter_authorize(oauth_token):
                return False
            params = {
                'oauth_token': oauth_token,
                'oauth_verifier': self.twitter.oauth_verifier
            }
            res = await self.client.get(f'https://server.partofdream.io/user/auth/twitter/callback', params=params, allow_redirects=False)
            if res.status_code == 302 :
                set_cookie = res.headers.get("set-cookie", "")
                cookies = requests.utils.dict_from_cookiejar(requests.cookies.RequestsCookieJar())
                cookies.update(dict(cookie.split("=", 1) for cookie in set_cookie.split("; ") if "=" in cookie))
                connect_sid = cookies.get("connect.sid", "")
                self.client.headers.update({"Cookie": f"{connect_sid}"})
                return await self.getUserInfo()
            logger.error(f'{[self.auth_token]} 登录失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.auth_token]} 登录失败: {e}')
            return False 

    async def getUserInfo(self):
        try:
            res = await self.client.post('https://server.partofdream.io/user/session')
            if res.status_code == 200:
                userName = res.json()['user']['username']
                userId = res.json()['user']['_id']
                logger.success(f'{[userName]} 登录成功，用户id {userId},代理：{self.proxy}')
                return await self.checkIn(userId)
            logger.error(f'{[self.auth_token]} 获取用户失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.auth_token]} 获取用户失败: {e}')
            return False  

    async def checkIn(self,userId):
        try:
            json_data={
                        "timezoneOffset": -480,
                        "userId":userId
            } 
            res = await self.client.post('https://server.partofdream.io/spin/spin',json=json_data)
            if res.status_code == 200:
                logger.success(f"{[res.json()['message']]} 分数 {res.json()['user']['prize']}")
            else:
                logger.error(f'{[res.text]}')    
            res = await self.client.post('https://server.partofdream.io/checkin/checkin',json=json_data)
            if res.status_code == 200:
                logger.success(f"{[res.json()['message']]}")
            else:
                logger.error(f'{[res.text]}')
            logger.success(f"=======================================================================")          
            return True
        except Exception as e:
            logger.error(f'{[self.auth_token]} 签到失败: {e}')
            return False      


async def do(semaphore, account_line):
    async with semaphore:
        accounts = account_line.strip().split('----')
        for _ in range(3):
            if await Dreamer(accounts[0], accounts[1]).getOauth():
                break


async def main(file_path, semaphore):
    semaphore = asyncio.Semaphore(semaphore)
    with open(file_path, 'r') as f:
        task = [do(semaphore, account_line) for account_line in f]
    await asyncio.gather(*task)


if __name__ == '__main__':
    asyncio.run(main("config.txt", 1))