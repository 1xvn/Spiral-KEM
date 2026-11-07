#!/usr/bin/env python3
"""Record compiler arguments without changing them or adding feedback coverage."""
import json
import os
import sys


def main():
    trace = os.environ['SPIRAL_LIFECYCLE_RUSTC_TRACE']
    if len(sys.argv) < 2:
        raise ValueError('expected rustc path')
    rustc, args = sys.argv[1], sys.argv[2:]
    row = (json.dumps({'rustc':rustc,'args':args,'pid':os.getpid(),'cwd':os.getcwd()},separators=(',',':'))+'\n').encode()
    fd = os.open(trace,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:
        if os.write(fd,row) != len(row):
            raise OSError('partial compiler audit write')
    finally:
        os.close(fd)
    os.execv(rustc,[rustc,*args])


if __name__ == '__main__':
    main()
