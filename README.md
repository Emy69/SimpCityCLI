# SimpCity Downloader

This Python script downloads media files (images, videos, attachments) from a specific thread on the SimpCity forum.

**Features:**

*   **Media Download:** Downloads images, videos, and attachments from forum posts.
*   **Thread Navigation:** Automatically navigates through multiple pages of a thread.
*   **Login Support:** Supports login using a username/password or an `xf_user` cookie.
*   **Rate Limiting:** Implements rate limiting to prevent server overload.
*   **Progress Tracking:** Displays download progress for each file.
*   **Error Handling:** Includes basic error handling and logging.

**Installation:**

1.  **Clone the repository:**

    To get started, clone the repository to your local machine:

    ```bash
    git clone https://github.com/Emy69/SimpCityCLI.git
    ```

2.  **Install the required libraries:**

    Navigate to the project directory and install the dependencies:

    ```bash
    cd SimpCityCLI
    pip install -r requirements.txt
    ```

**Usage:**

1.  **Run the script from the command line:**

    After installation, you can run the script by using the following command:

    ```bash
    python simpcity.py <thread_url>
    ```

    Replace `<thread_url>` with the URL of the SimpCity thread you want to download.

**Example:**

```bash
python simpcity.py https://simpcity.su/threads/user/

