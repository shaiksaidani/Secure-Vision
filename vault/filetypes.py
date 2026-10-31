"""Allowed file types. A file is accepted only if its extension is on the
allow-list AND its actual content matches that type (magic-byte check), so a
renamed .exe can't slip through as a .pdf."""
from django.core.exceptions import ValidationError

IMAGE, VIDEO, AUDIO, PDF, TEXT, DOCUMENT = 'IMAGE', 'VIDEO', 'AUDIO', 'PDF', 'TEXT', 'DOCUMENT'

# extension: (category, mime type)
ALLOWED = {
    'jpg': (IMAGE, 'image/jpeg'),
    'jpeg': (IMAGE, 'image/jpeg'),
    'png': (IMAGE, 'image/png'),
    'gif': (IMAGE, 'image/gif'),
    'webp': (IMAGE, 'image/webp'),
    'mp4': (VIDEO, 'video/mp4'),
    'webm': (VIDEO, 'video/webm'),
    'mp3': (AUDIO, 'audio/mpeg'),
    'wav': (AUDIO, 'audio/wav'),
    'ogg': (AUDIO, 'audio/ogg'),
    'pdf': (PDF, 'application/pdf'),
    'txt': (TEXT, 'text/plain; charset=utf-8'),
    'csv': (TEXT, 'text/csv; charset=utf-8'),
    'md': (TEXT, 'text/markdown; charset=utf-8'),
    'docx': (DOCUMENT, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    'xlsx': (DOCUMENT, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
    'pptx': (DOCUMENT, 'application/vnd.openxmlformats-officedocument.presentationml.presentation'),
}

ACCEPT_ATTR = ','.join('.' + ext for ext in sorted(ALLOWED))


def _content_matches(ext, data):
    head = data[:16]
    if ext in ('jpg', 'jpeg'):
        return head.startswith(b'\xff\xd8\xff')
    if ext == 'png':
        return head.startswith(b'\x89PNG\r\n\x1a\n')
    if ext == 'gif':
        return head.startswith(b'GIF87a') or head.startswith(b'GIF89a')
    if ext == 'webp':
        return head[:4] == b'RIFF' and head[8:12] == b'WEBP'
    if ext == 'mp4':
        return head[4:8] == b'ftyp'
    if ext == 'webm':
        return head.startswith(b'\x1a\x45\xdf\xa3')
    if ext == 'mp3':
        return head.startswith(b'ID3') or (len(head) > 1 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0)
    if ext == 'wav':
        return head[:4] == b'RIFF' and head[8:12] == b'WAVE'
    if ext == 'ogg':
        return head.startswith(b'OggS')
    if ext == 'pdf':
        return head.startswith(b'%PDF-')
    if ext in ('docx', 'xlsx', 'pptx'):
        return head.startswith(b'PK\x03\x04')
    if ext in ('txt', 'csv', 'md'):
        if b'\x00' in data:
            return False
        try:
            data.decode('utf-8-sig')
        except UnicodeDecodeError:
            return False
        return True
    return False


def identify(filename, data):
    """Return (extension, category, mime) or raise ValidationError."""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED:
        raise ValidationError('This file type is not allowed. Allowed: {}.'.format(
            ', '.join(sorted(ALLOWED))))
    if not data:
        raise ValidationError('The file is empty.')
    if not _content_matches(ext, data):
        raise ValidationError("The file's content doesn't match its .{} extension.".format(ext))
    category, mime = ALLOWED[ext]
    return ext, category, mime