#!/usr/bin/env python3
"""Install pinned upstream Linux releases into the workflow scratch directory."""
import gzip
import argparse
import hashlib
import io
from pathlib import Path
import tarfile
import requests

TOOLS = [
    ('clash-speedtest', 'https://github.com/faceair/clash-speedtest/releases/download/v1.8.8/clash-speedtest_Linux_x86_64.tar.gz',
     '8672b2b814a887b0319040284278361606b8d8c87488c4164fce599b1caeaa1c', 'tar'),
    ('mihomo', 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-v1.19.32.gz',
     '8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10', 'gz'),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo-only', action='store_true')
    args = parser.parse_args()
    root = Path('.node-work/bin')
    root.mkdir(parents=True, exist_ok=True)
    for name, url, checksum, kind in TOOLS:
        if args.mihomo_only and name != 'mihomo':
            continue
        response = requests.get(url, timeout=(10, 90))
        response.raise_for_status()
        if hashlib.sha256(response.content).hexdigest() != checksum:
            raise RuntimeError(f'{name} SHA-256 校验失败')
        if kind == 'gz':
            executable = gzip.decompress(response.content)
        else:
            with tarfile.open(fileobj=io.BytesIO(response.content)) as archive:
                member = next(item for item in archive.getmembers() if Path(item.name).name == name and item.isfile())
                executable = archive.extractfile(member).read()
        target = root / name
        target.write_bytes(executable)
        target.chmod(0o755)
        print(f'{name} 已安装，SHA-256 校验通过')


if __name__ == '__main__':
    main()
