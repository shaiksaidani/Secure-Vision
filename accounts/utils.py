def describe_user_agent(user_agent):
    """Readable label such as 'Chrome on Windows' from a User-Agent string."""
    if not user_agent:
        return 'Unknown device'
    ua = user_agent.lower()

    if 'edg/' in ua:
        browser = 'Edge'
    elif 'opr/' in ua or 'opera' in ua:
        browser = 'Opera'
    elif 'firefox/' in ua:
        browser = 'Firefox'
    elif 'chrome/' in ua or 'crios/' in ua:
        browser = 'Chrome'
    elif 'safari/' in ua:
        browser = 'Safari'
    else:
        browser = 'Browser'

    if 'windows' in ua:
        system = 'Windows'
    elif 'android' in ua:
        system = 'Android'
    elif 'iphone' in ua or 'ipad' in ua:
        system = 'iOS'
    elif 'mac os x' in ua or 'macintosh' in ua:
        system = 'macOS'
    elif 'linux' in ua:
        system = 'Linux'
    else:
        system = 'unknown system'

    return '{} on {}'.format(browser, system)


def safe_next_url(request, default=None):
    """Return ?next= / POST next only if it points back into this site
    (prevents open-redirect attacks)."""
    from django.utils.http import url_has_allowed_host_and_scheme
    candidate = request.POST.get('next') or request.GET.get('next') or ''
    if candidate and url_has_allowed_host_and_scheme(
            candidate, allowed_hosts={request.get_host()},
            require_https=request.is_secure()):
        return candidate
    return default