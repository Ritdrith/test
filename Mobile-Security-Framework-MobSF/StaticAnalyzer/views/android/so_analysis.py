# -*- coding: utf_8 -*-
"""analysis smali files."""

import logging
import os
import re
import struct
from pathlib import Path
from MobSF.utils import filename_from_path

logger = logging.getLogger(__name__)

def so_analysis(app_dir):
    try:
        logger.info('so_analysis...')
        so_assets_dict = {
            'libjiagu.so': '360加固',
            'libjiagu_a64.so': '360加固',
            'libjiagu_x64.so': '360加固',
            'libjiagu_x86.so': '360加固',
            'libjiagu_art.so': '360加固',
            'libprotectClass.so': '360加固',
            'libSecShell.so': '邦邦-免费版',
            'libSecShell-x86.so': '邦邦-免费版',
            'libDexHelper.so': '邦邦-免费版',
            'libDexHelper-x86.so': '邦邦-免费版',
            'libdexjni.so': '邦邦-免费版',
            'libdexjni%s.so': '邦邦-免费版',
            'libexecmain.so': '爱加密',
            'libexec.so': '爱加密',
            'libbaiduprotect.so': '百度应用加固',
            'libsgsecuritybody.so': '阿里加固',
            'libpreverify1.so': '阿里加固',
            'libmobisec.so': '阿里加固',
            'libchaosvmp.so': '娜迦',
            'libddog.so': '娜迦',
            'kdpdata.so': '几维安全',
            'libkwscmm.so': '几维安全',
            'libegis.so': '通付盾',
            'libNSaferOnly.so': '通付盾',
            'libnqshield.so': '网秦',
            'libAPKProtect.so': 'APKProtect',
            'libmisc-ld.so': '顶象科技',
            'libcsn_x86.so': '顶象科技',
            'libitsec.so': '海云安加固',
            'libapktoolplus_jiagu.so': '海云安加固',
            'libuusafe.jar.so': 'UU安全',
            'libuusafe.so': 'UU安全',
            'dp.arm-v7.so.dat': 'DexProtect加固',
            'dp.arm.so.dat': 'DexProtect加固',
            'libmogosec_sodecrypt.so': '中国移动加固',
            'libcmvmp.so': '中国移动加固',
            'libreincp.so': '珊瑚灵御',
            'libBugly.so': '乐固',
            'libshellx-3.0.0.0.so': '乐固',
            'libapktoolplus_jiagu.so': 'apktoolplus',
            'librsprotect.so': '瑞星加固',
            'libapssec.so': '盛大加固'
            }
        res = []
        res_dict = {}
        app_dir = Path(app_dir)
        src_lib = app_dir / 'lib'
        src_assets = app_dir / 'assets'
        for dirpath,dirnames,filenames in os.walk(src_lib):
            for filename in filenames:
                temp = filename_from_path(os.path.join(dirpath,filename))
                lib_dirpath = re.search( r'\\lib\\',dirpath).start() + 1
                lib_filename = dirpath[lib_dirpath:] + '\\' + filename
                flag=so_assets_dict.get(temp)
                if flag:
                    # print(so_assets_dict[temp])
                    res.append({'filename': lib_filename,
                            })
                    res_dict[lib_filename] = 'packer'
                else:
                    flag_a = re.match( r'libshella-',filename)
                    flag_b = re.match( r'libshell-super',filename)
                    flag_c = re.match( r'libshellx',filename)
                    if flag_a or flag_b or flag_c:
                        res.append({'filename': lib_filename,
                            })
                        res_dict[lib_filename] = 'packer'
                    # print(flag)
        for dirpath,dirnames,filenames in os.walk(src_assets):
            for filename in filenames:
                temp = filename_from_path(os.path.join(dirpath,filename))
                assets_dirpath = re.search( r'\\assets',dirpath).start() + 1
                assets_filename = dirpath[assets_dirpath:] + '\\' + filename
                flag=so_assets_dict.get(temp)
                if flag:
                    # print(so_assets_dict[temp])
                    res.append({'filename': assets_filename,
                            })
                    res_dict[assets_filename] = 'packer'
                else:
                    flag_a = re.match( r'libshella-',filename)
                    flag_b = re.match( r'libshell-super',filename)
                    flag_c = re.match( r'libshellx',filename)
                    if flag_a or flag_b or flag_c:
                        res.append({'filename': assets_filename,
                            })
                        res_dict[assets_filename] = 'packer'
                    # print(flag)
        return res_dict
    except Exception:
        logger.exception('Performing So Analysis')