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
                return await self.doTask(userId)
            logger.error(f'{[self.auth_token]} 获取用户失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.auth_token]} 获取用户失败: {e}')
            return False  

    async def doTask(self,userId):
        try:
            tesk_list = ["67d2b938744953ad1f63da54", "67b8cbaffe807a78f8b80035", "67b96d39fe807a78f8b80088","67b96d88fe807a78f8b8008c","67c1b6a41851937f36175c15","67c5c78e47bc4a6b701a9840"]
            for item in tesk_list:
                    json_data={
                        "fromPage":"/",
                        "taskId":item,
                        "userId":userId
                    } 
                    res = await self.client.post('https://server.partofdream.io/task/completeTask/Delay',json=json_data)
                    if res.status_code == 200:
                        logger.success(f"{[res.json()['message']]}")
                    else:    
                        logger.error(f"{[res.json()['message']]} 执行失败: {res.text}")
            logger.success(f"=======================================================================") 
            return True
        except Exception as e:
            logger.error(f'{[self.auth_token]} 任务执行失败: {e}')
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