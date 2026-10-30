"""刷新 jsDelivr 各节点的缓存。

`@main` 版本的缓存是 12 小时（响应头 s-maxage=43200），发布后不主动清理，
国内用户拉到的是上一版。这里对每个发布文件调一次 purge 接口；失败不阻塞发布，
只打印警告，下一次定时任务还会再清一次。
"""
import sys
import time
import urllib.parse
import urllib.request

ROOT = 'https://purge.jsdelivr.net/gh/{repo}@main/{path}'
FILES = ('优选配置.yaml', '前置配置.yaml', '后置配置.yaml', '链式配置.yaml',
         'v2rayN.txt', '最新检测.json', '连通性报告.json')


def purge(path, repo, attempts=3, timeout=30):
    url = ROOT.format(repo=repo, path=urllib.parse.quote(path))
    for index in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.status == 200
        except Exception as error:  # 网络抖动或接口限流都不该让发布失败
            if index == attempts - 1:
                print(f'清除缓存失败 {path}：{type(error).__name__}', flush=True)
                return False
            time.sleep(3)
    return False


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    repo = argv[0] if argv else 'hoooou/my_yml'
    failed = [path for path in FILES if not purge(path, repo)]
    print(f'CDN 缓存已刷新 {len(FILES) - len(failed)}/{len(FILES)}' + (f'，失败：{"、".join(failed)}' if failed else ''), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
