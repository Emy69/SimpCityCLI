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

1.  **Install the required libraries:**

    ```bash
    pip install -r requirements.txt
    ```

**Usage:**

1.  **Run the script from the command line:**

    ```bash
    python simpcity.py <thread_url>
    ```

    Replace `<thread_url>` with the URL of the SimpCity thread you want to download.

**Example:**

```bash
python simpcity.py [URL removed for privacy]

