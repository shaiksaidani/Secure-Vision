"""Forensic Analyzer: upload a suspicious file and get an evidence report."""
from django.conf import settings
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from accounts.decorators import privilege_required
from accounts.permissions import Privilege

from .forms import SampleForm
from .models import ForensicAnalysis
from .services import run_analysis


@privilege_required(Privilege.RUN_FORENSICS)
def analyzer_view(request):
    form = SampleForm(request.POST or None, request.FILES or None)
    if request.method == 'POST' and form.is_valid():
        analysis = run_analysis(request, form.sample_name, form.sample_bytes)
        messages.success(request, 'Analysis of "{}" complete.'.format(analysis.sample_name))
        return redirect('forensics:report', public_id=analysis.public_id)
    recent = ForensicAnalysis.objects.select_related('analyst', 'matched_file', 'associated_user')[:25]
    return render(request, 'forensics/analyzer.html', {
        'form': form, 'recent': recent, 'max_mb': settings.SV_MAX_UPLOAD_MB,
    })


@privilege_required(Privilege.RUN_FORENSICS)
def report_view(request, public_id):
    analysis = get_object_or_404(
        ForensicAnalysis.objects.select_related('analyst', 'matched_file', 'watermark', 'associated_user'),
        public_id=public_id)
    return render(request, 'forensics/report.html', {
        'analysis': analysis, 'details': analysis.details_dict,
    })