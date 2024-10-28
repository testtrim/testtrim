# SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from multiprocessing import Pool

import os
import os.path
# subprocess.run(["ls", "-l"], cwd="/home/mfenniak")


def f(x):
    (parent, file) = os.path.split(x)
    os.chdir(parent)
    open(file, "rb").read()
    return 1

def bare_open(x):
    print(os.getcwd())
    open("test.txt", "rb").read()

if __name__ == '__main__':
    open("flake.nix", "rb").read()
    print("main cwd:", os.getcwd())
    os.chdir("/home/mfenniak/Dev")
    print("main cwd:", os.getcwd())
    with Pool(2) as p:
        p.map(bare_open, [1]) # this should "inherit" the cwd of the parent process, I think
        print(p.map(f, [
            "/home/mfenniak/Dev/testtrim/README.md",
            "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz",
            "/home/mfenniak/.zsh_history",
            "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf",
        ]))
