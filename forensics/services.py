"""Personalised watermarked copies (used by the vault) and forensic analysis."""
import io
import json
import secrets
import uuid

from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from accounts.models import Device
from accounts.utils import describe_user_agent
from audit.models import AuditLog
from audit.services import get_client_ip, get_user_agent, log_event, session_fingerprint
from vault.models import ProtectedFile
from vault.protection import IntegrityError as StoredCopyError
from vault.protection import read_blob, sha256_hex, write_blob

from . import watermark as wm
from .models import ForensicAnalysis, Watermark

SIMILARITY_THRESHOLD = 6    # of 64 bits. Same image after edits: <=2; different images: >=10


def _when(moment):
    return timezone.localtime(moment).strftime('%d %b %Y, %I:%M %p') if moment else ''


def _new_code():
    while True:
        code = '{:012x}'.format(secrets.randbits(48))
        if not Watermark.objects.filter(code=code).exists():
            return code


# --------------------------------------------------------------------------
# Personalised copies
# --------------------------------------------------------------------------
def can_watermark(protected_file):
    return (protected_file.forensic_watermark
            and protected_file.category == ProtectedFile.Category.IMAGE
            and protected_file.extension in wm.WATERMARKABLE_EXTENSIONS)


def issue_copy(request, protected_file, original, purpose):
    """Return (bytes, mime_type, filename, watermark-or-None) for this recipient.
    Images get an invisible watermark naming the recipient; other files are
    returned unchanged."""
    unchanged = (original, protected_file.mime_type, protected_file.original_filename, None)
    if not can_watermark(protected_file):
        return unchanged
    defaults = {
        'code': _new_code(),
        'ip_address': get_client_ip(request),
        'device_name': describe_user_agent(get_user_agent(request)),
        'session_ref': session_fingerprint(request.session.session_key),
    }
    lookup = {'file': protected_file, 'recipient': request.user, 'purpose': purpose,
              'issued_on': timezone.localdate()}
    try:
        with transaction.atomic():
            mark, _created = Watermark.objects.get_or_create(defaults=defaults, **lookup)
    except IntegrityError:          # two requests at the same moment
        mark = Watermark.objects.get(**lookup)
    try:
        data = wm.embed(original, int(mark.code, 16))
    except wm.NotWatermarkable:
        return unchanged
    Watermark.objects.filter(pk=mark.pk).update(
        served_sha256=sha256_hex(data), last_served_at=timezone.now(),
        times_served=F('times_served') + 1)
    stem = protected_file.original_filename.rsplit('.', 1)[0]
    return data, 'image/png', stem + '.png', mark


def ensure_perceptual_hash(protected_file):
    """Fill in the visual fingerprint of a protected image if it's missing."""
    if protected_file.category != ProtectedFile.Category.IMAGE or protected_file.perceptual_hash:
        return protected_file.perceptual_hash
    try:
        data = read_blob(protected_file.storage_name, protected_file.sha256)
    except StoredCopyError:
        return ''
    value = wm.perceptual_hash(data)
    if value:
        ProtectedFile.objects.filter(pk=protected_file.pk).update(perceptual_hash=value)
    return value


# --------------------------------------------------------------------------
# Forensic analysis
# --------------------------------------------------------------------------
def _is_image(data):
    try:
        from PIL import Image
        Image.open(io.BytesIO(data)).verify()
        return True
    except Exception:
        return False


def _closest_image(sample_hash):
    best, best_distance = None, None
    for candidate in ProtectedFile.objects.filter(category=ProtectedFile.Category.IMAGE):
        reference = ensure_perceptual_hash(candidate)
        if not reference:
            continue
        distance = wm.hash_distance(sample_hash, reference)
        if best_distance is None or distance < best_distance:
            best, best_distance = candidate, distance
    return best, best_distance


def run_analysis(request, sample_name, data):
    sha = sha256_hex(data)
    findings = []        # (kind, text) - kind: detected | clear | info
    matched, mark, confidence = None, None, None
    tampered = ForensicAnalysis.Tampered.INCONCLUSIVE
    watermark_status = ForensicAnalysis.WatermarkStatus.NOT_APPLICABLE

    # 1. Byte-for-byte identical to a protected original?
    original = ProtectedFile.objects.filter(sha256=sha).first()
    if original:
        matched, tampered = original, ForensicAnalysis.Tampered.NOT_DETECTED
        findings.append(('clear', 'Byte-for-byte identical to the protected original "{}".'.format(original.title)))

    # 2. Byte-for-byte identical to a watermarked copy we issued?
    issued = Watermark.objects.select_related('file', 'recipient').filter(served_sha256=sha).first()
    if issued:
        mark, matched, confidence = issued, issued.file, 1.0
        tampered = ForensicAnalysis.Tampered.NOT_DETECTED
        watermark_status = ForensicAnalysis.WatermarkStatus.FOUND
        findings.append(('detected', 'Byte-for-byte identical to the copy of "{}" issued to {} on {}.'.format(
            issued.file.title, issued.recipient.full_name if issued.recipient else 'a deleted account',
            _when(issued.created_at))))

    # 3. Images: read the invisible watermark, then compare visually.
    if mark is None and _is_image(data):
        watermark_status = ForensicAnalysis.WatermarkStatus.NOT_FOUND
        found = wm.extract(data)
        if found:
            code, confidence = found
            candidate = (Watermark.objects.select_related('file', 'recipient')
                         .filter(code='{:012x}'.format(code)).first())
            if candidate:
                mark, matched = candidate, candidate.file
                watermark_status = ForensicAnalysis.WatermarkStatus.FOUND
                tampered = ForensicAnalysis.Tampered.DETECTED
                findings.append(('detected', 'Invisible watermark found ({:.0f}% vote strength). It identifies the copy '
                                 'of "{}" issued to {}. The file is not identical to that copy, so it was changed '
                                 'after it was issued (for example cropped or re-saved).'.format(
                                     confidence * 100, candidate.file.title,
                                     candidate.recipient.full_name if candidate.recipient else 'a deleted account')))
            else:
                findings.append(('info', 'A SecureVision watermark pattern was read, but its code is not in '
                                         "this system's records."))
        else:
            findings.append(('info', 'No invisible watermark detected. The file may never have carried one, or it '
                                     'was removed by re-compression, resizing or a screenshot.'))
        if matched is None:
            sample_hash = wm.perceptual_hash(data)
            similar, distance = _closest_image(sample_hash) if sample_hash else (None, None)
            if similar is not None and distance <= SIMILARITY_THRESHOLD:
                matched, tampered = similar, ForensicAnalysis.Tampered.DETECTED
                findings.append(('detected', 'Visually similar to the protected image "{}" (difference {} of 64) but '
                                             'not identical: the content was modified.'.format(similar.title, distance)))
    elif mark is None:
        findings.append(('info', 'Invisible watermarks are applied to images. For other file types SecureVision '
                                 'relies on exact hash matches and access records.'))

    # 4. Last resort: same file name as a protected file (weak).
    if matched is None:
        same_name = ProtectedFile.objects.filter(original_filename__iexact=sample_name).first()
        if same_name:
            matched = same_name
            findings.append(('info', 'Same name as the protected file "{}", but different content. It may be a '
                                     'modified version or an unrelated file.'.format(same_name.title)))
        else:
            findings.append(('info', 'No link to any protected file was found.'))

    associated = mark.recipient if mark else None
    strong_link = mark is not None or tampered != ForensicAnalysis.Tampered.INCONCLUSIVE
    if mark is not None:
        risk = ForensicAnalysis.Risk.HIGH
    elif matched is not None and strong_link:
        risk = ForensicAnalysis.Risk.MEDIUM
    else:
        risk = ForensicAnalysis.Risk.LOW
    evidence = ForensicAnalysis.Evidence.AVAILABLE if strong_link and matched else \
        ForensicAnalysis.Evidence.INSUFFICIENT

    details = {'findings': findings, 'confidence': confidence}
    if mark is not None:
        details['watermark'] = {
            'code': mark.code, 'purpose': mark.get_purpose_display(), 'issued': _when(mark.created_at),
            'last_served': _when(mark.last_served_at), 'times_served': mark.times_served,
            'device': mark.device_name, 'ip': mark.ip_address or '',
        }
    if matched is not None:
        events = (AuditLog.objects.filter(target='file:{}'.format(matched.public_id))
                  .select_related('user').order_by('timestamp')[:200])
        details['timeline'] = [{
            'when': _when(e.timestamp), 'who': e.user.full_name if e.user else e.actor_label,
            'email': e.actor_label, 'action': e.get_action_display(), 'result': e.get_result_display(),
            'ip': e.ip_address or '', 'device': describe_user_agent(e.user_agent) if e.user_agent else '',
        } for e in events]
        accesses = [e for e in events if e.action in (AuditLog.Action.FILE_VIEW, AuditLog.Action.FILE_DOWNLOAD)]
        details['first_access'] = _when(accesses[0].timestamp) if accesses else ''
        details['accessed_by'] = sorted({e.actor_label for e in accesses})
    if associated is not None:
        details['devices'] = [{
            'name': d.name, 'kind': d.get_kind_display(), 'status': d.get_status_display(),
            'first': _when(d.first_registered), 'last': _when(d.last_active), 'ip': d.last_ip or '',
        } for d in Device.objects.filter(user=associated)]
        details['suspicious'] = [{
            'when': _when(e.timestamp), 'action': e.get_action_display(), 'target': e.target,
            'ip': e.ip_address or '',
        } for e in AuditLog.objects.filter(user=associated, result__in=[
            AuditLog.Result.DENIED, AuditLog.Result.FAILURE]).order_by('-timestamp')[:15]]

    if mark is not None and associated is not None:
        summary = 'This file is traceable to the copy of "{}" issued to {} ({}) on {}.{}'.format(
            mark.file.title, associated.full_name, associated.email, _when(mark.created_at),
            ' It was altered after it was issued.' if tampered == ForensicAnalysis.Tampered.DETECTED else '')
    elif matched is not None and strong_link:
        summary = 'This file is linked to the protected file "{}", but no individual recipient can be identified ' \
                  'from the file itself. Review the access history below.'.format(matched.title)
    elif matched is not None:
        summary = 'Possible link to "{}" by name only. There is not enough evidence to connect this file to ' \
                  'protected content.'.format(matched.title)
    else:
        summary = 'No link to SecureVision-protected content was found. Insufficient evidence.'

    storage_name = 'fx-' + uuid.uuid4().hex
    write_blob(storage_name, data)          # keep the sample, encrypted, as evidence
    analysis = ForensicAnalysis.objects.create(
        analyst=request.user, sample_name=sample_name[:255], sample_size=len(data), sample_sha256=sha,
        sample_storage=storage_name, matched_file=matched, watermark=mark, associated_user=associated,
        tampered=tampered, watermark_status=watermark_status, risk=risk, evidence=evidence,
        summary=summary, details=json.dumps(details, default=str))
    log_event(AuditLog.Action.FORENSIC_ANALYSIS, request=request,
              target='analysis:{}'.format(analysis.public_id),
              details={'sample': sample_name, 'sha256': sha, 'risk': risk,
                       'matched_file': str(matched.public_id) if matched else None,
                       'watermark': mark.code if mark else None,
                       'associated_user': associated.email if associated else None})
    return analysis