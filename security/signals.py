from django.db.models.signals import post_save
from django.dispatch import receiver

from audit.models import AuditLog

from .rules import safe_evaluate


@receiver(post_save, sender=AuditLog)
def on_audit_event(sender, instance, created, **kwargs):
    if created:
        safe_evaluate(instance)