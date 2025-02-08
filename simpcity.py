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

# Configurar logging
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
        self.request_limiter = AsyncLimiter(10, 1)  # 10 requests por segundo
        self.download_path = Path("downloads/simpcity")
        self.download_path.mkdir(parents=True, exist_ok=True)
        # Ruta para guardar las cookies
        self.cookie_file = Path("cookies.json")
        
        # Selectores según el crawler original
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
        """Inicializar la sesión aiohttp y cargar cookies persistentes (si existen)"""
        if not self.session:
            self.session = aiohttp.ClientSession()
            self.load_cookies()

    async def close(self):
        """Guardar cookies y cerrar la sesión"""
        if self.session:
            self.save_cookies()
            await self.session.close()
            self.session = None

    def save_cookies(self):
        """Guarda las cookies actuales en un archivo JSON"""
        if self.session and self.session.cookie_jar:
            # Se obtienen las cookies para el dominio base
            simple_cookie = self.session.cookie_jar.filter_cookies(str(self.base_url))
            cookies = {key: morsel.value for key, morsel in simple_cookie.items()}
            try:
                with open(self.cookie_file, 'w') as f:
                    json.dump(cookies, f)
                logger.info("Cookies guardadas en %s", self.cookie_file)
            except Exception as e:
                logger.error("Error guardando cookies: %s", str(e))

    def load_cookies(self):
        """Carga las cookies desde el archivo (si existe) y las añade a la sesión"""
        if self.cookie_file.exists():
            try:
                with open(self.cookie_file, 'r') as f:
                    cookies = json.load(f)
                self.session.cookie_jar.update_cookies(cookies)
                logger.info("Cookies cargadas desde %s", self.cookie_file)
            except Exception as e:
                logger.error("Error cargando cookies: %s", str(e))

    async def check_login_required(self, url: str) -> bool:
        """Verifica si es necesario iniciar sesión para acceder a la URL dada"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # Se buscan indicadores de login en la respuesta
                    return 'You must be logged-in to do that.' in text or 'Login or register' in text
                return True  # Asumir que es necesario login si no se puede acceder a la página
        except Exception:
            return True

    async def prompt_and_login(self) -> bool:
        """Solicita las credenciales y realiza el login"""
        print("\nLogin requerido para SimpCity")
        print("1. Login con username/password")
        print("2. Login con cookie xf_user")
        print("3. Continuar sin login")
        
        choice = input("\nIngrese su elección (1-3): ").strip()
        
        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()
            return await self.login(username, password)
            
        elif choice == "2":
            print("\nPara obtener tu cookie xf_user:")
            print("1. Ingresa a SimpCity en tu navegador")
            print("2. Abre las herramientas de desarrollador (F12)")
            print("3. Ve a Application/Storage -> Cookies")
            print("4. Copia el valor de la cookie 'xf_user'")
            xf_user = input("\nIngresa el valor de la cookie xf_user: ").strip()
            return await self.login(None, None, xf_user)
            
        else:
            logger.warning("Continuando sin autenticación")
            return False

    async def verify_login(self) -> bool:
        """Verifica si estamos logueados comprobando la página de detalles de cuenta"""
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
        """Inicia sesión en SimpCity a través de https://www.simpcity.su/login/ y guarda las cookies"""
        await self.init_session()
        
        # Encabezados comunes para todas las solicitudes
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
                logger.info("Login exitoso usando la cookie xf_user")
                return True
            else:
                logger.error("Login fallido: cookie xf_user inválida o expirada")
                return False
            
        if not username or not password:
            return False
            
        try:
            # Primero, obtener la página de login para extraer el token CSRF y otros campos ocultos
            login_page_url = self.base_url / "login"
            headers['Referer'] = str(self.base_url)
            
            async with self.session.get(login_page_url, headers=headers) as response:
                if response.status == 403:
                    logger.error("Acceso prohibido. El sitio puede estar bloqueando accesos automatizados.")
                    logger.info("Intenta usar el método de cookie xf_user.")
                    return False
                elif response.status != 200:
                    logger.error(f"Error al obtener la página de login: {response.status}")
                    return False
                    
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Extraer token CSRF
                csrf_token_elem = soup.select_one('input[name=_xfToken]')
                if not csrf_token_elem:
                    logger.error("No se encontró el token CSRF. La estructura de la página de login pudo haber cambiado.")
                    return False
                csrf_token = csrf_token_elem['value']
                
                # Extraer campos ocultos (si los hay)
                hidden_fields = {}
                for hidden in soup.find_all('input', type='hidden'):
                    if hidden.get('name') and hidden.get('value'):
                        hidden_fields[hidden['name']] = hidden['value']
            
            # Preparar datos para el login
            login_url = self.base_url / "login/login"
            data = {
                'login': username,
                'password': password,
                '_xfToken': csrf_token,
                '_xfRedirect': str(self.base_url),  # Se redirigirá al inicio (luego el usuario ingresa la URL deseada)
                'remember': '1'
            }
            data.update(hidden_fields)
            
            # Actualizar headers para la solicitud de login
            headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': str(self.base_url),
                'Referer': str(login_page_url)
            })
            
            # Intentar el login
            async with self.session.post(login_url, data=data, headers=headers, allow_redirects=True) as response:
                if response.status == 403:
                    logger.error("Acceso prohibido durante el login. El sitio puede estar bloqueando accesos automatizados.")
                    logger.info("Intenta usar el método de cookie xf_user.")
                    return False
                elif response.status not in [200, 303]:
                    logger.error(f"Login fallido: código de estado inesperado {response.status}")
                    return False
                
                # Verificar que se haya iniciado sesión
                if await self.verify_login():
                    self.logged_in = True
                    logger.info("Login exitoso")
                    return True
                
                # Si la verificación falla, buscar mensajes de error en la respuesta
                text = await response.text()
                if any(error in text.lower() for error in ['invalid password', 'invalid username', 'incorrect password']):
                    logger.error("Usuario o contraseña inválidos")
                else:
                    logger.error("Login fallido: no se pudo verificar el estado de autenticación")
                return False
                    
        except Exception as e:
            logger.error(f"Error durante el login: {str(e)}")
            return False

    async def get_page(self, url: URL) -> Optional[BeautifulSoup]:
        """Obtiene el contenido de una página aplicando rate limiting"""
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
                        logger.error(f"Acceso prohibido para {url}. El sitio puede estar bloqueando accesos automatizados.")
                        return None
                    elif response.status != 200:
                        logger.error(f"Error al obtener la página {url}: {response.status}")
                        return None
                    text = await response.text()
                    return BeautifulSoup(text, 'html.parser')
            except Exception as e:
                logger.error(f"Error al obtener la página {url}: {str(e)}")
                return None

    async def download_file(self, url: str, filename: str, subfolder: str = ""):
        """Descarga un archivo mostrando el progreso"""
        save_path = self.download_path / subfolder
        save_path.mkdir(exist_ok=True)
        filepath = save_path / filename
        
        if filepath.exists():
            logger.info(f"El archivo ya existe: {filename}")
            return True
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            async with self.request_limiter:
                async with self.session.get(url, headers=headers) as response:
                    if response.status != 200:
                        logger.error(f"Error al descargar {filename}: {response.status}")
                        return False
                    
                    file_size = int(response.headers.get('content-length', 0))
                    if file_size == 0:
                        logger.error(f"Archivo vacío: {filename}")
                        return False
                    
                    logger.info(f"Descargando {filename} ({file_size/1024/1024:.1f} MB)")
                    
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
                                            print(f"\rProgreso: {progress:.1f}%", end='', flush=True)
                            
                            print()  # Nueva línea después del progreso
                            
                        temp_filepath.replace(filepath)
                        logger.info(f"Archivo descargado exitosamente: {filename}")
                        return True
                    except Exception as e:
                        if temp_filepath.exists():
                            temp_filepath.unlink()
                        raise e
        except Exception as e:
            logger.error(f"Error descargando {filename}: {str(e)}")
            if filepath.exists():
                filepath.unlink()
            return False

    async def process_post(self, post_content: BeautifulSoup, subfolder: str) -> List[Tuple[str, str]]:
        """Procesa un post del foro y extrae archivos multimedia"""
        files = []
        try:
            # Procesar imágenes
            images = post_content.select(self.images_selector)
            logger.debug(f"Se encontraron {len(images)} imágenes en el post")
            for img in images:
                src = img.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = str(self.base_url / src[1:])
                    filename = src.split('/')[-1]
                    files.append((src, filename))
            
            # Procesar videos
            videos = post_content.select(self.videos_selector)
            logger.debug(f"Se encontraron {len(videos)} videos en el post")
            for video in videos:
                src = video.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = str(self.base_url / src[1:])
                    filename = src.split('/')[-1]
                    files.append((src, filename))
            
            # Procesar attachments
            attachments_block = post_content.select_one(self.attachments_block_selector)
            if attachments_block:
                attachments = attachments_block.select(self.attachments_selector)
                logger.debug(f"Se encontraron {len(attachments)} attachments en el post")
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
                logger.debug(f"Total de archivos encontrados en el post: {len(files)}")
            return files
        except Exception as e:
            logger.error(f"Error procesando post: {str(e)}")
            return []

    async def process_thread(self, url: str) -> None:
        """Procesa un hilo del foro y descarga todos los archivos multimedia"""
        logger.info(f"Iniciando el procesamiento del hilo: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = f"https://www.simpcity.su/{url.lstrip('/')}"
            logger.info(f"URL convertida a: {url}")
        
        thread_url = URL(url)
        current_url = thread_url
        
        # Verificar si es necesario login
        logger.info("Verificando si es necesario iniciar sesión...")
        if await self.check_login_required(str(current_url)):
            if not await self.prompt_and_login():
                logger.error("Se requiere login pero la autenticación falló")
                return
        
        # Una vez logueados, redirigimos al hilo solicitado
        logger.info("Obteniendo la página del hilo...")
        soup = await self.get_page(current_url)
        if not soup:
            logger.error("Error al obtener la página del hilo")
            return
            
        title_elem = soup.select_one(self.title_selector)
        if not title_elem:
            logger.error("No se encontró el título del hilo")
            return
            
        thread_title = re.sub(r'[<>:"/\\|?*]', '_', title_elem.text.strip())
        logger.info(f"Procesando hilo: {thread_title}")
        
        page_num = 1
        total_files = 0
        
        while True:
            logger.info(f"Procesando página {page_num}")
            soup = await self.get_page(current_url)
            if not soup:
                logger.error(f"Error al obtener la página {page_num}")
                break
            
            # Procesar cada post
            posts = soup.select(self.posts_selector)
            if not posts:
                logger.warning(f"No se encontraron posts en la página {page_num}")
                break
                
            logger.info(f"Se encontraron {len(posts)} posts en la página {page_num}")
            
            for post_index, post in enumerate(posts, 1):
                logger.info(f"Procesando post {post_index}/{len(posts)} en la página {page_num}")
                post_content = post.select_one(self.post_content_selector)
                if post_content:
                    files = await self.process_post(post_content, thread_title)
                    if files:
                        logger.info(f"Se encontraron {len(files)} archivos en el post {post_index}")
                        for file_url, filename in files:
                            if await self.download_file(file_url, filename, thread_title):
                                total_files += 1
                else:
                    logger.warning(f"No se encontró contenido en el post {post_index}")
            
            # Verificar si hay siguiente página
            next_page = soup.select_one(self.next_page_selector)
            if next_page and (href := next_page.get('href')):
                if href.startswith('/'):
                    current_url = self.base_url / href[1:]
                else:
                    current_url = URL(href)
                logger.info(f"Pasando a la página {page_num + 1}: {current_url}")
                page_num += 1
            else:
                logger.info("No se encontraron más páginas")
                break
        
        if total_files > 0:
            logger.info(f"Procesamiento del hilo completado. Se descargaron {total_files} archivos.")
        else:
            logger.warning("No se descargó ningún archivo de este hilo.")

async def main():
    if len(sys.argv) != 2:
        print("Uso: python simpcity.py <thread_url>")
        print("Ejemplo: python simpcity.py https://www.simpcity.su/threads/thread-title.12345")
        return
    
    url = sys.argv[1]
    downloader = SimpCityDownloader()
    
    try:
        # Timeout para el proceso completo (1 hora)
        timeout = 3600  # 1 hour timeout
        async with asyncio.timeout(timeout):
            await downloader.init_session()
            await downloader.process_thread(url)
            
    except asyncio.TimeoutError:
        logger.error(f"La operación excedió el tiempo límite de {timeout} segundos")
    except KeyboardInterrupt:
        logger.info("Operación cancelada por el usuario")
    except Exception as e:
        logger.error(f"Ocurrió un error: {str(e)}")
    finally:
        logger.info("Limpiando recursos...")
        await downloader.close()
        logger.info("¡Listo!")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperación cancelada por el usuario")
    except Exception as e:
        print(f"\nError fatal: {str(e)}")
