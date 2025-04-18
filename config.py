import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'mp4'}
    MAX_CONTENT_LENGTH = 1000 * 1024 * 1024  # 1000MB limit
import os

class Config:
    """
    Configuration class for Flask application.
    Handles secret key, file upload settings, and other configurations.
    """
    
    # Secret key for securing sessions and other security-related operations
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'

    # Folder where uploaded files will be saved
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')

    # Set of allowed file extensions for upload
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'mp4', 'zip', 'csv'}

    # Max content length for uploads (200MB)
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB limit
    
    # Additional configurations for file storage
    STORAGE_PATH = os.path.join(os.getcwd(), 'storage')  # Path for general storage (separate from static uploads)

    # Option to allow users to create directories within their upload folder
    ALLOW_CREATE_DIRECTORIES = True  # Allows creation of subdirectories in UPLOAD_FOLDER

    @staticmethod
    def is_allowed_file(filename):
        """
        Check if a file has an allowed extension.
        :param filename: The file's name (string).
        :return: True if the file extension is allowed, False otherwise.
        """
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

    @staticmethod
    def create_directory(path):
        """
        Create a directory if it does not already exist.
        :param path: Path to the directory.
        """
        if not os.path.exists(path):
            os.makedirs(path)

    @staticmethod
    def setup_storage():
        """
        Set up the necessary directories for file uploads and storage.
        This will ensure that both the upload folder and storage directory exist.
        """
        Config.create_directory(Config.UPLOAD_FOLDER)
        Config.create_directory(Config.STORAGE_PATH)
        if Config.ALLOW_CREATE_DIRECTORIES:
            # Example: You can enable users to create subfolders here
            # by checking and creating their custom directories.
            user_upload_dir = os.path.join(Config.UPLOAD_FOLDER, 'user_uploads')
            Config.create_directory(user_upload_dir)
