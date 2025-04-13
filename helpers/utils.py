import os

# Utility function to check allowed file types
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'mp4'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Utility function to generate file icon based on file type
def get_file_icon(filename):
    file_ext = filename.rsplit('.', 1)[1].lower()
    if file_ext == 'pdf':
        return 'fa-file-pdf'
    elif file_ext == 'docx':
        return 'fa-file-word'
    elif file_ext == 'png' or file_ext == 'jpg' or file_ext == 'jpeg' or file_ext == 'gif':
        return 'fa-file-image'
    elif file_ext == 'mp4':
        return 'fa-file-video'
    else:
        return 'fa-file'
