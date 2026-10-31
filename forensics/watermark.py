"""Invisible forensic watermark for images.

Each authorized recipient gets a copy whose pixels carry a hidden 48-bit
watermark code linked (in the database) to that person, file and time.

How it works: the least significant bit of the blue channel of every pixel
carries one bit of an 80-bit message:
    16-bit sync pattern | 48-bit code | 16-bit CRC
Pixel (x, y) carries bit number (x + 3y) mod 80, so the message repeats
thousands of times across the image. Reading uses a majority vote for each
bit and tries every rotation of the message, which means the watermark still
reads after the image is CROPPED or saved again as PNG/BMP/TIFF.

Honest limits: changing the pixels' low bits - JPEG re-compression,
resizing, screenshots of a scaled view, heavy filters - destroys it. The
analyzer then reports "Not detected", never a guess.

Pure Pillow (no numpy), Python 3.6 compatible.
"""
import binascii
import io

from PIL import Image, ImageChops, ImageOps

MESSAGE_BITS = 80
SYNC = 0xB38F
ROW_STEP = 3
MIN_PIXELS = 4096          # e.g. 64 x 64: enough repetitions for a reliable vote
MAX_PIXELS = 40000000      # refuse absurd images (decompression bombs)
MIN_CONFIDENCE = 0.6       # average vote strength needed to report "Detected"
WATERMARKABLE_EXTENSIONS = ('jpg', 'jpeg', 'png', 'webp')

_CLEAR_LSB = [value & 0xFE for value in range(256)]
_ONLY_LSB = [value & 1 for value in range(256)]


class NotWatermarkable(Exception):
    """The image can't carry a watermark (animated, tiny, huge or unreadable)."""


def _message_bits(code):
    payload = code.to_bytes(6, 'big')
    crc = binascii.crc_hqx(payload, 0xFFFF)
    value = (SYNC << 64) | (code << 16) | crc
    return [(value >> (MESSAGE_BITS - 1 - i)) & 1 for i in range(MESSAGE_BITS)]


def _decode_bits(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    sync = value >> 64
    code = (value >> 16) & ((1 << 48) - 1)
    crc = value & 0xFFFF
    if sync != SYNC or binascii.crc_hqx(code.to_bytes(6, 'big'), 0xFFFF) != crc:
        return None
    return code


def _open(data):
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
    except Exception:
        raise NotWatermarkable('Not a readable image.')
    width, height = image.size
    if width * height < MIN_PIXELS or width * height > MAX_PIXELS:
        raise NotWatermarkable('Image size not supported for watermarking.')
    return image


def embed(data, code):
    """Return PNG bytes of the image with `code` hidden in it."""
    image = _open(data)
    if getattr(image, 'is_animated', False):
        raise NotWatermarkable('Animated images are not watermarked.')
    image = ImageOps.exif_transpose(image)       # keep the photo the right way up
    has_alpha = image.mode in ('RGBA', 'LA') or (image.mode == 'P' and 'transparency' in image.info)
    image = image.convert('RGBA' if has_alpha else 'RGB')
    width, height = image.size

    bits = _message_bits(code)
    base = bytes(bits[x % MESSAGE_BITS] for x in range(width + MESSAGE_BITS))
    rows = []
    for y in range(height):
        start = (ROW_STEP * y) % MESSAGE_BITS
        rows.append(base[start:start + width])
    mask = Image.frombytes('L', (width, height), b''.join(rows))

    bands = list(image.split())
    bands[2] = ImageChops.add(bands[2].point(_CLEAR_LSB), mask)
    marked = Image.merge(image.mode, bands)
    output = io.BytesIO()
    marked.save(output, 'PNG')
    return output.getvalue()


def extract(data):
    """Return (code, confidence) if a watermark is present, else None."""
    try:
        image = _open(data)
    except NotWatermarkable:
        return None
    image = image.convert('RGB')
    width, height = image.size
    lsb = image.split()[2].point(_ONLY_LSB).tobytes()

    ones = [0] * MESSAGE_BITS
    totals = [0] * MESSAGE_BITS
    for y in range(height):
        row = lsb[y * width:(y + 1) * width]
        shift = (ROW_STEP * y) % MESSAGE_BITS
        for bit_index in range(MESSAGE_BITS):
            samples = row[(bit_index - shift) % MESSAGE_BITS::MESSAGE_BITS]
            ones[bit_index] += samples.count(1)
            totals[bit_index] += len(samples)

    votes, strength = [], []
    for count, total in zip(ones, totals):
        share = float(count) / total if total else 0.5
        votes.append(1 if share > 0.5 else 0)
        strength.append(abs(share - 0.5) * 2)
    confidence = sum(strength) / len(strength)
    if confidence < MIN_CONFIDENCE:
        return None

    for rotation in range(MESSAGE_BITS):           # survives cropping
        code = _decode_bits(votes[rotation:] + votes[:rotation])
        if code is not None:
            return code, round(confidence, 3)
    return None


def perceptual_hash(data):
    """64-bit difference hash (hex). Similar-looking images have hashes
    that differ in only a few bits, even after re-compression or resizing."""
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
        image = ImageOps.exif_transpose(image)
    except Exception:
        return ''
    small = image.convert('L').resize((9, 8), Image.BILINEAR)
    pixels = list(small.getdata())
    value = 0
    for row in range(8):
        for col in range(8):
            left = pixels[row * 9 + col]
            right = pixels[row * 9 + col + 1]
            value = (value << 1) | (1 if left > right else 0)
    return '{:016x}'.format(value)


def hash_distance(first, second):
    return bin(int(first, 16) ^ int(second, 16)).count('1')