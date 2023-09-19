import base64
from typing import Callable, Tuple, Union
from pathlib import Path

import pytest

from pytest_xray.exceptions import XrayError

evidence_nb: int = 1


@pytest.fixture
def xray_evidence(request) -> Callable:
    """ Fixture to add an evidence to the Test Run details of a Test.
    See https://docs.getxray.app/display/XRAY/Import+Execution+Results

    Copyright © 2023 Orange - All rights reserved
    """
    media_types = {
        'bin': 'application/octet-stream',
        'csv': 'text/csv',
        'gz': 'application/gzip',
        'html': 'text/html',
        'json': 'application/json',
        'jpeg': 'image/jpeg',
        'jpg': 'image/jpeg',
        'js': 'text/javascript',
        'md': 'text/markdown',
        'pcap': 'application/vnd.tcdump.pcap',
        'png': 'image/png',
        'spdx': 'text/spdx',
        'txt': 'text/plain',
        'xml': 'text/xml',
        'yml': 'application/yaml',
        'yaml': 'application/yaml',
        'zip': 'application/zip'
    }

    def wrapper_evidence(path: Union[str, Path] = '',
                         *, data: Union[str, bytes] = '',
                         ctype: str = ''
                         ) -> None:
        """
        Behaviour of the fixture from the value of 'path', 'data' and 'ctype'
        arguments:
+------+------+-------+--------------------------------------------------------+
| path | data | ctype | Comment                                                |
+======+======+=======+========================================================+
| No   | No   | No    | Error, "No data to upload"                             |
+------+------+-------+--------------------------------------------------------+
| No   | No   | Yes   | Error, "No data to upload"                             |
+------+------+-------+--------------------------------------------------------+
| No   | Yes  | No    | If data is binary, content-type is "application/octet- |
|      |      |       | stream" otherwise "text/plain". For filename see below.|
+------+------+-------+--------------------------------------------------------+
| No   | Yes  | Yes   | Filename is set to "attachmentX.Y" where X is a number |
|      |      |       | and extension Y is deduced from content-type value.    |
+------+------+-------+--------------------------------------------------------+
| Yes  | Yes  | Yes   | Takes all the values given.                            |
+------+------+-------+--------------------------------------------------------+
| Yes  | Yes  | No    | Content-type is set from the filename extension.       |
+------+------+-------+--------------------------------------------------------+
| Yes  | No   | Yes   | Data is the content of the file.                       |
+------+------+-------+--------------------------------------------------------+
| Yes  | No   | No    | Extension of filename is used to determine content-type|
|      |      |       | and content of file is the data.                       |
+------+------+-------+--------------------------------------------------------+
        """
        global evidence_nb
        # data_base64: str = ''
        # evidence_name: str = ''
        # contentType: str = ''

        if path == '':
            if data == '':
                raise XrayError('No data to upload')
            elif isinstance(data, bytes):
                db64 = base64.b64encode(data)
            else:
                db64 = base64.b64encode(bytes(data, 'utf-8'))
            data_base64 = db64.decode('utf-8')

            if ctype == '':
                if isinstance(data, bytes):
                    contentType = 'application/octet-stream'
                else:
                    contentType = 'text/plain'
            else:
                contentType = ctype

            evidence_name = 'attachment' + str(evidence_nb)
            extension: str = ''
            for e, t in media_types.items():
                if t == contentType:
                    extension = e
                    break
            if extension != '':
                evidence_name += '.' + extension
                # else: no extension
            evidence_nb += 1

        else:
            if not isinstance(path, (str, Path)):
                raise XrayError('Path must be a string')
            evidence_path: Path = Path(path)
            # Jira wants a filename for the attachment
            evidence_name = evidence_path.name

            if data == '':
                if not evidence_path.is_absolute():
                    # Following code is for debugging purpose
                    # with open("/tmp/pytest-jira-xray_debug.txt", 'a') as f:
                    #    import os
                    #    f.write("evidence_path=" + str(evidence_path) + "\n")
                    #    f.write("cwd=" + os.getcwd() + "\n")
                    #    f.write("request.path=" + str(request.path) + "\n---\n")
                    evidence_path = request.path.parent.joinpath(evidence_path)
                try:
                    with open(evidence_path, 'rb') as f:
                        data_base64 = base64.b64encode(f.read()).decode('utf-8')
                except OSError:
                    raise XrayError(f'Cannot open or read file {evidence_path}')
            elif isinstance(data, bytes):
                data_base64 = base64.b64encode(data).decode('utf-8')
            else:
                data_base64 = base64.b64encode(bytes(data, encoding='utf-8')).decode('utf-8')

            if ctype == '':
                extension = evidence_path.suffix.replace('.', '')
                if media_types.get(extension) is None:
                    raise XrayError(f'Media type not found for extension {extension}')
                else:
                    contentType = str(media_types.get(extension))
            else:
                contentType = ctype

        new_evidence = {
            'data': data_base64,
            'filename': evidence_name,
            'contentType': contentType
        }
        # Add the new evidence to the stash of the node to get it from the hook function
        if not hasattr(request.node, 'evidences'):
            request.node.evidences = []
        request.node.evidences.append(new_evidence)

    return wrapper_evidence
