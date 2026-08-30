#!/usr/bin/env python3

import atexit
import sys
import os
from pathlib import Path
from termcolor import colored

# import common python file for PPH utils
PPH_HELPER_FOLDER = '{}/scripts'.format(os.path.abspath(os.environ['HABANALABS_ROOT']))
sys.path.append(PPH_HELPER_FOLDER)
import prepush_helper as pph

FILES_CLEANUP = []

print(colored('****  Running Checkpatch  ****', 'green'))

cmdargs = pph.parse_args()

cwd = pph.pph_init(cmdargs.gitroot)

atexit.register(pph.cleanup_resources, FILES_CLEANUP, cwd)

# run check patch
checkpatch_ignore_list = 'FILE_PATH_CHANGES,GERRIT_CHANGE_ID,NAKED_SSCANF,SSCANF_TO_KSTRTO,PREFER_PACKED,SPLIT_STRING,CONSTANT_COMPARISON,MACRO_WITH_FLOW_CONTROL,MULTISTATEMENT_MACRO_USE_DO_WHILE,SINGLE_STATEMENT_DO_WHILE_MACRO,COMPLEX_MACRO,UNKNOWN_COMMIT_ID,DO_WHILE_MACRO_WITH_TRAILING_SEMICOLON,VOLATILE'
folders_to_ignore = ['.ci', 'scripts']
pph.check_patch(cmdargs.commit, folders_to_ignore, checkpatch_ignore_list, FILES_CLEANUP)

commit_hdr_re = '^\[[F]?SW-[0-9]+\] '
pph.check_commit_header(cmdargs.commit, commit_hdr_re)

if (cmdargs.spellcheck):
    pph.check_commit_message_spell(cmdargs.commit)

sys.exit(0)
