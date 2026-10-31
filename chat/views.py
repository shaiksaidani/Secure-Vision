"""Confidential Chat and team Community Chat.

Pages are rendered on the server; a small script sends messages and polls
for new ones without reloading. Every request re-checks access on the server.
"""
from datetime import datetime

from django.contrib import messages as flash
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from accounts.decorators import privilege_required
from accounts.permissions import Privilege
from audit.models import AuditLog
from audit.services import log_event
from notifications.models import Notification
from notifications.services import notify_many
from teams.models import Team

from . import access
from .models import Conversation, ConversationMember, Message

User = get_user_model()
Action = AuditLog.Action
HISTORY_LIMIT = 100
EPOCH = timezone.make_aware(datetime(2000, 1, 1))


def _is_ajax(request):
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def _visible_conversation_or_404(request, public_id):
    conversation = get_object_or_404(Conversation.objects.select_related('team'), public_id=public_id)
    if not access.can_view(request.user, conversation):
        log_event(Action.ACCESS_DENIED, request=request,
                  target='conversation:{}'.format(conversation.public_id),
                  result=AuditLog.Result.DENIED, details={'reason': 'not_a_participant'})
        raise Http404('Conversation not found')
    return conversation


def _mark_read(user, conversation):
    member, _created = ConversationMember.objects.get_or_create(conversation=conversation, user=user)
    ConversationMember.objects.filter(pk=member.pk).update(last_read_at=timezone.now())


def _unread_count(user, conversation):
    member = ConversationMember.objects.filter(conversation=conversation, user=user).first()
    since = member.last_read_at if member and member.last_read_at else EPOCH
    return (conversation.messages.filter(is_deleted=False, created_at__gt=since)
            .exclude(sender=user).count())


def _preview(conversation):
    last = conversation.messages.select_related('sender').order_by('-created_at', '-id').first()
    if last is None:
        return 'No messages yet'
    if last.is_deleted:
        return 'Message deleted'
    text = ' '.join(last.body.split())
    return text[:60] + ('...' if len(text) > 60 else '')


def _sidebar(user):
    direct = []
    memberships = (ConversationMember.objects
                   .filter(user=user, conversation__kind=Conversation.Kind.DIRECT)
                   .select_related('conversation'))
    for membership in memberships:
        conversation = membership.conversation
        other = access.other_participant(user, conversation)
        if other is None:
            continue
        direct.append({
            'conversation': conversation, 'other': other,
            'preview': _preview(conversation), 'unread': _unread_count(user, conversation),
            'sort': conversation.last_message_at or conversation.created_at,
        })
    direct.sort(key=lambda row: row['sort'], reverse=True)

    communities = []
    for team in access.teams_with_community(user):
        conversation = Conversation.objects.filter(team=team).first()
        communities.append({
            'team': team, 'conversation': conversation,
            'preview': _preview(conversation) if conversation else 'No messages yet',
            'unread': _unread_count(user, conversation) if conversation else 0,
        })
        # People you already talk to appear once, under Direct messages.
    talking_to = {row['other'].pk for row in direct}
    contacts = [person for person in access.contacts_for(user) if person.pk not in talking_to]
    return {'direct': direct, 'communities': communities, 'contacts': contacts,
            'sees_all_teams': user.has_privilege(Privilege.MANAGE_TEAMS)}


def _serialize(message, user):
    mine = message.sender_id == user.pk
    return {
        'id': message.pk,
        'mine': mine,
        'sender': message.sender.full_name if message.sender else 'Former user',
        'body': '' if message.is_deleted else message.body,
        'deleted': message.is_deleted,
        'announcement': message.is_announcement,
        'time': timezone.localtime(message.created_at).strftime('%d %b, %I:%M %p'),
        'delete_url': reverse('chat:delete', args=[message.pk]) if mine and not message.is_deleted else '',
    }


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@privilege_required(Privilege.USE_CHAT)
def chat_home_view(request):
    return render(request, 'chat/chat.html', {'sidebar': _sidebar(request.user), 'conversation': None})


@privilege_required(Privilege.USE_CHAT)
def conversation_view(request, public_id):
    conversation = _visible_conversation_or_404(request, public_id)
    _mark_read(request.user, conversation)
    recent = list(conversation.messages.select_related('sender')
                  .order_by('-created_at', '-id')[:HISTORY_LIMIT])
    recent.reverse()
    other = access.other_participant(request.user, conversation)
    return render(request, 'chat/chat.html', {
        'sidebar': _sidebar(request.user),
        'conversation': conversation,
        'chat_messages': recent,
        'last_id': recent[-1].pk if recent else 0,
        'other': other,
        'can_post': access.can_post(request.user, conversation),
        'can_announce': access.can_announce(request.user, conversation),
        'max_length': Message.MAX_LENGTH,
    })


@privilege_required(Privilege.USE_CHAT)
@require_POST
def start_direct_view(request, user_pk):
    other = get_object_or_404(User, pk=user_pk)
    if not access.can_message(request.user, other):
        log_event(Action.ACCESS_DENIED, request=request, target='user:{}'.format(other.pk),
                  result=AuditLog.Result.DENIED, details={'reason': 'chat_not_permitted'})
        flash.error(request, "You can't start a conversation with this person.")
        return redirect('chat:home')
    with transaction.atomic():
        conversation, created = Conversation.objects.get_or_create(
            direct_key=Conversation.key_for(request.user, other),
            defaults={'kind': Conversation.Kind.DIRECT})
        for person in (request.user, other):
            ConversationMember.objects.get_or_create(conversation=conversation, user=person)
    return redirect('chat:conversation', public_id=conversation.public_id)


@privilege_required(Privilege.USE_CHAT)
def team_chat_view(request, team_pk):
    team = get_object_or_404(Team, pk=team_pk)
    if not access.teams_with_community(request.user).filter(pk=team.pk).exists():
        log_event(Action.ACCESS_DENIED, request=request, target='team:{}'.format(team.pk),
                  result=AuditLog.Result.DENIED, details={'reason': 'not_a_team_member'})
        raise Http404('Team not found')
    conversation, _created = Conversation.objects.get_or_create(
        team=team, defaults={'kind': Conversation.Kind.TEAM})
    return redirect('chat:conversation', public_id=conversation.public_id)


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------
@privilege_required(Privilege.USE_CHAT)
@require_POST
def send_message_view(request, public_id):
    conversation = _visible_conversation_or_404(request, public_id)
    back = reverse('chat:conversation', args=[conversation.public_id])
    error = None
    body = (request.POST.get('body') or '').strip()
    if not access.can_post(request.user, conversation):
        error = "You can't send messages in this conversation."
    elif not body:
        error = 'Type a message first.'
    elif len(body) > Message.MAX_LENGTH:
        error = 'Messages can be at most {} characters.'.format(Message.MAX_LENGTH)
    if error:
        if _is_ajax(request):
            return JsonResponse({'error': error}, status=400)
        flash.error(request, error)
        return redirect(back)

    announce = bool(request.POST.get('announcement')) and access.can_announce(request.user, conversation)
    with transaction.atomic():
        message = Message.objects.create(conversation=conversation, sender=request.user,
                                         body=body, is_announcement=announce)
        Conversation.objects.filter(pk=conversation.pk).update(last_message_at=message.created_at)
    _mark_read(request.user, conversation)
    # The audit trail records that a message was sent, never its content.
    log_event(Action.CHAT_MESSAGE, request=request,
              target='conversation:{}'.format(conversation.public_id),
              details={'message_id': message.pk, 'kind': conversation.kind,
                       'length': len(body), 'announcement': announce})
    if announce:
        members = [m.user for m in conversation.team.memberships.select_related('user')]
        notify_many(members, Notification.Kind.ANNOUNCEMENT,
                    'New announcement in {}'.format(conversation.team.name),
                    '{}: {}'.format(request.user.full_name, body[:160]),
                    url=reverse('chat:conversation', args=[conversation.public_id]), exclude=request.user)
    if _is_ajax(request):
        return JsonResponse({'message': _serialize(message, request.user)})
    return redirect(back + '#latest')


@privilege_required(Privilege.USE_CHAT)
@require_POST
def delete_message_view(request, message_pk):
    """Deletion only ever happens here: an explicit POST, confirmed by the
    user from the message menu. Nothing on hover or mouse movement can
    reach this view."""
    message = get_object_or_404(Message.objects.select_related('conversation'), pk=message_pk)
    conversation = _visible_conversation_or_404(request, message.conversation.public_id)
    back = reverse('chat:conversation', args=[conversation.public_id])
    if message.sender_id != request.user.pk:
        log_event(Action.ACCESS_DENIED, request=request, target='message:{}'.format(message.pk),
                  result=AuditLog.Result.DENIED, details={'reason': 'not_message_sender'})
        if _is_ajax(request):
            return JsonResponse({'error': 'You can only delete your own messages.'}, status=403)
        flash.error(request, 'You can only delete your own messages.')
        return redirect(back)
    if not message.is_deleted:
        Message.objects.filter(pk=message.pk).update(
            is_deleted=True, deleted_at=timezone.now(), deleted_by=request.user)
        log_event(Action.MESSAGE_DELETE, request=request, target='message:{}'.format(message.pk),
                  details={'conversation': str(conversation.public_id)})
    if _is_ajax(request):
        return JsonResponse({'deleted': message.pk})
    flash.success(request, 'Message deleted.')
    return redirect(back)


@privilege_required(Privilege.USE_CHAT)
@require_GET
def updates_view(request, public_id):
    """New messages after ?after=<id>, plus ids of deleted recent messages."""
    conversation = _visible_conversation_or_404(request, public_id)
    try:
        after = int(request.GET.get('after', '0'))
    except ValueError:
        after = 0
    new = conversation.messages.select_related('sender').filter(pk__gt=after).order_by('created_at', 'id')[:50]
    recent_ids = list(conversation.messages.order_by('-id').values_list('id', flat=True)[:HISTORY_LIMIT])
    deleted = list(conversation.messages.filter(pk__in=recent_ids, is_deleted=True)
                   .values_list('id', flat=True))
    _mark_read(request.user, conversation)
    return JsonResponse({
        'messages': [_serialize(m, request.user) for m in new],
        'deleted': deleted,
        'can_post': access.can_post(request.user, conversation),
    })