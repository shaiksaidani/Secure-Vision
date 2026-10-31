"""Security headers for every response (defence in depth).

* Content-Security-Policy on HTML pages: scripts and styles only from
  SecureVision itself (plus Google Fonts), no plugins, no framing by other
  sites, forms may only post back to SecureVision. Even if an attacker managed
  to inject markup, the browser would refuse to run it.
* Permissions-Policy: pages can't use the camera, microphone, location, etc.
* Cross-Origin-Opener-Policy: other sites can't keep a handle on our windows.
* Cache-Control: no-store on signed-in pages, so the Back button or a shared
  computer's cache can't show confidential pages after sign-out.
"""
from django.conf import settings

CONTENT_SECURITY_POLICY = '; '.join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "frame-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
])
PERMISSIONS_POLICY = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'


class SecurityHeadersMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault('Permissions-Policy', PERMISSIONS_POLICY)
        response.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
        if not response.get('Content-Type', '').startswith('text/html'):
            return response          # protected-file content keeps its own headers

        # Django's own debug pages and our self-contained 500 page use inline CSS.
        technical = response.status_code >= 500 or (settings.DEBUG and response.status_code == 404)
        if not technical and not request.path.startswith('/sv-admin/'):
            same_origin = response.get('X-Frame-Options', '').upper() == 'SAMEORIGIN'
            response.setdefault('Content-Security-Policy', '{}; frame-ancestors {}'.format(
                CONTENT_SECURITY_POLICY, "'self'" if same_origin else "'none'"))

        user = getattr(request, 'user', None)
        if user is not None and user.is_authenticated and not response.has_header('Cache-Control'):
            response['Cache-Control'] = 'no-store, private'
        return response