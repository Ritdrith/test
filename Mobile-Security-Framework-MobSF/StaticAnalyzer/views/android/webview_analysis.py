# -*- coding: utf_8 -*-
"""Module holding the functions for webview analysis."""

import logging
from pathlib import Path
from django.conf import settings
from MobSF.utils import filename_from_path
from StaticAnalyzer.views.sast_engine import (
    scan,
)

logger = logging.getLogger(__name__)

def webview_analysis(app_dir, typ, manifest_file):
    """Perform the webview analysis."""
    try:
        logger.info('Webview Analysis Started')
        root = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views'
        webview_rules = root / 'android' / 'rules' / 'android_webview_rules.yaml'
        webview_findings = {}
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
        elif typ == 'studio':
            src = app_dir / 'app' / 'src' / 'main' / 'java'
            kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'eclipse':
            src = app_dir / 'src'
        src = src.as_posix() + '/'
        skp = settings.SKIP_CLASS_PATH
        logger.info('Webview Analysis Started on - %s',
                    filename_from_path(src))
        # Webview Analysis
        webview_findings = scan(
            webview_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        logger.info('Finished Webview Analysis')
        webview_an_dic = {
            'findings': webview_findings,
        }
        return webview_an_dic
    except Exception:
        logger.exception('Performing Webview Analysis')
