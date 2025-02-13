import asyncio
import aiohttp
import logging
import sys
import os
import json
from pathlib import Path
from typing import Optional, List, Tuple
from yarl import URL
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
import re
import getpass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class SimpCityDownloader:
    def __init__(self):
        self.base_url = URL("https://www.simpcity.su")
        self.session = None
        self.logged_in = False
        self.login_attempts = 0
        self.request_limiter = AsyncLimiter(10, 1)  # 10 requests per second
        self.download_path = Path("downloads/simpcity")
        self.download_path.mkdir(parents=True, exist_ok=True)
        # Path to store cookies
        self.cookie_file = Path("cookies.json")
        
        # Selectors according to the original crawler
        self.title_selector = "h1[class=p-title-value]"
        self.posts_selector = "div[class*=message-main]"
        self.post_content_selector = "div[class*=message-userContent]"
        self.images_selector = "img[class*=bbImage]"
        self.videos_selector = "video source"
        self.iframe_selector = "iframe[class=saint-iframe]"
        self.attachments_block_selector = "section[class=message-attachments]"
        self.attachments_selector = "a"
        self.next_page_selector = "a[class*=pageNav-jump--next]"

    async def init_session(self):
        """Initialize the aiohttp session and load persistent cookies (if available)"""
        if not self.session:
            self.session = aiohttp.ClientSession()
            self.load_cookies()

    async def close(self):
        """Save cookies and close the session"""
        if self.session:
            self.save_cookies()
            await self.session.close()
            self.session = None

    def save_cookies(self):
        """Save the current cookies to a JSON file"""
        if self.session and self.session.cookie_jar:
            # Obtain cookies for the base domain
            simple_cookie = self.session.cookie_jar.filter_cookies(str(self.base_url))
            cookies = {key: morsel.value for key, morsel in simple_cookie.items()}
            try:
                with open(self.cookie_file, 'w') as f:
                    json.dump(cookies, f)
                logger.info("Cookies saved in %s", self.cookie_file)
            except Exception as e:
                logger.error("Error saving cookies: %s", str(e))

    def load_cookies(self):
        """Load cookies from the file (if it exists) and add them to the session"""
        if self.cookie_file.exists():
            try:
                with open(self.cookie_file, 'r') as f:
                    cookies = json.load(f)
                self.session.cookie_jar.update_cookies(cookies)
                logger.info("Cookies loaded from %s", self.cookie_file)
            except Exception as e:
                logger.error("Error loading cookies: %s", str(e))

    async def check_login_required(self, url: str) -> bool:
        """Check if login is required to access the given URL"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # Look for login indicators in the response
                    return 'You must be logged-in to do that.' in text or 'Login or register' in text
                return True  # Assume login is required if the page cannot be accessed
        except Exception:
            return True

    async def prompt_and_login(self) -> bool:
        """Prompt for credentials and perform login"""
        print("\nLogin required for SimpCity")
        print("1. Login with username/password")
        print("2. Login with xf_user cookie")
        print("3. Continue without login")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()
            return await self.login(username, password)
            
        elif choice == "2":
            print("\nTo obtain your xf_user cookie:")
            print("1. Visit SimpCity in your browser")
            print("2. Open the developer tools (F12)")
            print("3. Go to Application/Storage -> Cookies")
            print("4. Copy the value of the 'xf_user' cookie")
            xf_user = input("\nEnter the value of the xf_user cookie: ").strip()
            return await self.login(None, None, xf_user)
            
        else:
            logger.warning("Continuing without authentication")
            return False

    async def verify_login(self) -> bool:
        """Verify if we are logged in by checking the account details page"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': str(self.base_url)
        }
        
        try:
            async with self.session.get(self.base_url / "account/account-details", headers=headers) as response:
                if response.status != 200:
                    return False
                text = await response.text()
                return 'You must be logged in to view this page.' not in text
        except Exception:
            return False

    async def login(self, username: str = None, password: str = None, xf_user_cookie: str = None) -> bool:
        """Log in to SimpCity through https://www.simpcity.su/login/ and save the cookies"""
        await self.init_session()
        
        # Common headers for all requests
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'DNT': '1'
        }
        
        if xf_user_cookie:
            self.session.cookie_jar.update_cookies({'xf_user': xf_user_cookie})
            if await self.verify_login():
                self.logged_in = True
                logger.info("Successful login using xf_user cookie")
                return True
            else:
                logger.error("Login failed: invalid or expired xf_user cookie")
                return False
            
        if not username or not password:
            return False
            
        try:
            # First, get the login page to extract the CSRF token and any hidden fields
            login_page_url = self.base_url / "login"
            headers['Referer'] = str(self.base_url)
            
            async with self.session.get(login_page_url, headers=headers) as response:
                if response.status == 403:
                    logger.error("Access forbidden. The site may be blocking automated access.")
                    logger.info("Try using the xf_user cookie method.")
                    return False
                elif response.status != 200:
                    logger.error(f"Error getting the login page: {response.status}")
                    return False
                    
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Extract CSRF token
                csrf_token_elem = soup.select_one('input[name=_xfToken]')
                if not csrf_token_elem:
                    logger.error("CSRF token not found. The login page structure may have changed.")
                    return False
                csrf_token = csrf_token_elem['value']
                
                # Extract hidden fields (if any)
                hidden_fields = {}
                for hidden in soup.find_all('input', type='hidden'):
                    if hidden.get('name') and hidden.get('value'):
                        hidden_fields[hidden['name']] = hidden['value']
            
            # Prepare data for login
            login_url = self.base_url / "login/login"
            data = {
                'login': username,
                'password': password,
                '_xfToken': csrf_token,
                '_xfRedirect': str(self.base_url),  # Will redirect to the homepage (then the user enters the desired URL)
                'remember': '1'
            }
            data.update(hidden_fields)
            
            # Update headers for the login request
            headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': str(self.base_url),
                'Referer': str(login_page_url)
            })
            
            # Attempt login
            async with self.session.post(login_url, data=data, headers=headers, allow_redirects=True) as response:
                if response.status == 403:
                    logger.error("Access forbidden during login. The site may be blocking automated access.")
                    logger.info("Try using the xf_user cookie method.")
                    return False
                elif response.status not in [200, 303]:
                    logger.error(f"Login failed: unexpected status code {response.status}")
                    return False
                
                # Verify that login was successful
                if await self.verify_login():
                    self.logged_in = True
                    logger.info("Successful login")
                    return True
                
                # If verification fails, look for error messages in the response
                text = await response.text()
                if any(error in text.lower() for error in ['invalid password', 'invalid username', 'incorrect password']):
                    logger.error("Invalid username or password")
                else:
                    logger.error("Login failed: could not verify authentication status")
                return False
                    
        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
            return False

    async def get_page(self, url: URL) -> Optional[BeautifulSoup]:
        """Get the content of a page while applying rate limiting"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
            'Referer': str(self.base_url)
        }
        
        async with self.request_limiter:
            try:
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 403:
                        logger.error(f"Access forbidden for {url}. The site may be blocking automated access.")
                        return None
                    elif response.status != 200:
                        logger.error(f"Error getting page {url}: {response.status}")
                        return None
                    text = await response.text()
                    return BeautifulSoup(text, 'html.parser')
            except Exception as e:
                logger.error(f"Error getting page {url}: {str(e)}")
                return None

    async def download_file(self, url: str, filename: str, subfolder: str = ""):
        """Download a file showing progress"""
        save_path = self.download_path / subfolder
        save_path.mkdir(exist_ok=True)
        filepath = save_path / filename
        
        if filepath.exists():
            logger.info(f"File already exists: {filename}")
            return True
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            async with self.request_limiter:
                async with self.session.get(url, headers=headers) as response:
                    if response.status != 200:
                        logger.error(f"Error downloading {filename}: {response.status}")
                        return False
                    
                    file_size = int(response.headers.get('content-length', 0))
                    if file_size == 0:
                        logger.error(f"Empty file: {filename}")
                        return False
                    
                    logger.info(f"Downloading {filename} ({file_size/1024/1024:.1f} MB)")
                    
                    temp_filepath = filepath.with_suffix('.temp')
                    try:
                        with open(temp_filepath, 'wb') as f:
                            downloaded = 0
                            async for chunk in response.content.iter_chunked(8192):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    if file_size:
                                        progress = (downloaded / file_size) * 100
                                        if downloaded % (8192 * 100) == 0:
                                            print(f"\rProgress: {progress:.1f}%", end='', flush=True)
                            
                            print()  # New line after progress
                            
                        temp_filepath.replace(filepath)
                        logger.info(f"File downloaded successfully: {filename}")
                        return True
                    except Exception as e:
                        if temp_filepath.exists():
                            temp_filepath.unlink()
                        raise e
        except Exception as e:
            logger.error(f"Error downloading {filename}: {str(e)}")
            if filepath.exists():
                filepath.unlink()
            return False

    async def process_post(self, post_content: BeautifulSoup, subfolder: str) -> List[Tuple[str, str]]:
        """Process a forum post and extract multimedia files"""
        files = []
        try:
            # Process images
            images = post_content.select(self.images_selector)
            logger.debug(f"Found {len(images)} images in the post")
            for img in images:
                src = img.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = str(self.base_url / src[1:])
                    filename = src.split('/')[-1]
                    files.append((src, filename))
            
            # Process videos
            videos = post_content.select(self.videos_selector)
            logger.debug(f"Found {len(videos)} videos in the post")
            for video in videos:
                src = video.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = str(self.base_url / src[1:])
                    filename = src.split('/')[-1]
                    files.append((src, filename))
            
            # Process attachments
            attachments_block = post_content.select_one(self.attachments_block_selector)
            if attachments_block:
                attachments = attachments_block.select(self.attachments_selector)
                logger.debug(f"Found {len(attachments)} attachments in the post")
                for attachment in attachments:
                    href = attachment.get('href')
                    if href:
                        if href.startswith('//'):
                            href = 'https:' + href
                        elif href.startswith('/'):
                            href = str(self.base_url / href[1:])
                        filename = href.split('/')[-1]
                        files.append((href, filename))
            
            if files:
                logger.debug(f"Total files found in the post: {len(files)}")
            return files
        except Exception as e:
            logger.error(f"Error processing post: {str(e)}")
            return []

    async def process_thread(self, url: str) -> None:
        """Process a forum thread and download all multimedia files"""
        logger.info(f"Starting processing thread: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = f"https://www.simpcity.su/{url.lstrip('/')}"
            logger.info(f"Converted URL to: {url}")
        
        thread_url = URL(url)
        current_url = thread_url
        
        # Check if login is required
        logger.info("Verifying if login is required...")
        if await self.check_login_required(str(current_url)):
            if not await self.prompt_and_login():
                logger.error("Login is required but authentication failed")
                return
        
        # Once logged in, redirect to the requested thread
        logger.info("Getting thread page...")
        soup = await self.get_page(current_url)
        if not soup:
            logger.error("Error getting thread page")
            return
            
        title_elem = soup.select_one(self.title_selector)
        if not title_elem:
            logger.error("Thread title not found")
            return
            
        thread_title = re.sub(r'[<>:"/\\|?*]', '_', title_elem.text.strip())
        logger.info(f"Processing thread: {thread_title}")
        
        page_num = 1
        total_files = 0
        
        while True:
            logger.info(f"Processing page {page_num}")
            soup = await self.get_page(current_url)
            if not soup:
                logger.error(f"Error getting page {page_num}")
                break
            
            # Process each post
            posts = soup.select(self.posts_selector)
            if not posts:
                logger.warning(f"No posts found on page {page_num}")
                break
                
            logger.info(f"Found {len(posts)} posts on page {page_num}")
            
            for post_index, post in enumerate(posts, 1):
                logger.info(f"Processing post {post_index}/{len(posts)} on page {page_num}")
                post_content = post.select_one(self.post_content_selector)
                if post_content:
                    files = await self.process_post(post_content, thread_title)
                    if files:
                        logger.info(f"Found {len(files)} files in post {post_index}")
                        for file_url, filename in files:
                            if await self.download_file(file_url, filename, thread_title):
                                total_files += 1
                else:
                    logger.warning(f"No content found in post {post_index}")
            
            # Check if there is a next page
            next_page = soup.select_one(self.next_page_selector)
            if next_page and (href := next_page.get('href')):
                if href.startswith('/'):
                    current_url = self.base_url / href[1:]
                else:
                    current_url = URL(href)
                logger.info(f"Moving to page {page_num + 1}: {current_url}")
                page_num += 1
            else:
                logger.info("No more pages found")
                break
        
        if total_files > 0:
            logger.info(f"Thread processing complete. Downloaded {total_files} files.")
        else:
            logger.warning("No files were downloaded from this thread.")

async def main():
    if len(sys.argv) != 2:
        print("Usage: python simpcity.py <thread_url>")
        print("Example: python simpcity.py https://www.simpcity.su/threads/thread-title.12345")
        return
    
    url = sys.argv[1]
    downloader = SimpCityDownloader()
    
    try:
        # Timeout for the entire process (1 hour)
        timeout = 3600  # 1 hour timeout
        async with asyncio.timeout(timeout):
            await downloader.init_session()
            await downloader.process_thread(url)
            
    except asyncio.TimeoutError:
        logger.error(f"The operation exceeded the timeout limit of {timeout} seconds")
    except KeyboardInterrupt:
        logger.info("Operation cancelled by the user")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
    finally:
        logger.info("Cleaning up resources...")
        await downloader.close()
        logger.info("Done!")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by the user")
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
