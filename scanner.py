from threading import Thread, Lock, Event, active_count
from datetime import datetime
from iptools import IpRangeList
from re import compile
from socket import socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, SOL_SOCKET, SO_REUSEADDR
from pystyle import Colors, Colorate, Center, Write
from os.path import exists as file_exists
from contextlib import suppress
from typing import (Set, Tuple, Dict, List, Iterator, TextIO, Any, Callable)
from multiprocessing import RawValue
from time import sleep

RANGEIP = compile("((?:\d{1,3}\.){3}\d{1,3})-((?:\d{1,3}\.){3}\d{1,3})")

class Logger:
    @staticmethod
    def succses(*msg):
        return Logger.log(Colors.green, "+", *msg)

    @staticmethod
    def info(*msg):
        return Logger.log(Colors.cyan, "~", *msg)

    @staticmethod
    def warning(*msg):
        return Logger.log(Colors.yellow, "!", *msg)

    @staticmethod
    def fail(*msg):
        return Logger.log(Colors.red, "-", *msg)

    @staticmethod
    def log(color, icon, *msg):
        print("%s[%s%s%s] %s%s%s%s" % (
                                    Colors.gray,
                                    color,
                                    icon,
                                    Colors.gray,
                                    color,
                                    Tools.arrayToString(msg),
                                    Colors.reset,
                                    " " * 50))


class SyncIPRange(IpRangeList, Iterator[str]):
    def __init__(self, *args):
        super().__init__(*args)
        self._read_lock = Lock()
        self._iter = self.__iter__()
    
    def __next__(self) -> str:
        with self._read_lock:
            return next(self._iter)

class Tools:
    @staticmethod
    def arrayToString(array):
        return " ".join([str(ar) or repr(ar) for ar in array])

    @staticmethod
    def cleanArray(array):
        return [arr.strip() for arr in array]

class Inputs:
    @staticmethod
    def file(*msg):
        def check(data):
            return file_exists(data)
        return Inputs.require(*msg, check=check, checkError="The File dosn't exists")
    
    @staticmethod
    def string(*msg):
        def check(data):
            return len(data) > 3
        return Inputs.require(*msg, check=check)
    
    @staticmethod
    def integer(*msg):
        def check(data):
            return data.isdigit()
        return Inputs.require(*msg, check=check, clazz=int, checkError="Invalid Numeric format")

    @staticmethod
    def require(*msg, check=None, clazz=str, checkError="Invalid String format"):
        while True:
            data = input(Tools.arrayToString(msg)) or ""
            if not data or check(data):
                return clazz(data)
            else:
                Logger.fail(checkError)
class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self
    def __repr__(self):
        return f"{int(self):,}"


class Scanner(Thread):
    def __init__(self, sync_range, io, port=22):
        super().__init__(daemon=True)
        self._ip_range = sync_range
        self._io = io
        self._scan_port = port
    
    def run(self):
        global CPS, Goods, Fails
        with suppress(StopIteration):
            while True:
                target = next(self._ip_range), self._scan_port
                CPS += 1
                with suppress(Exception), socket(AF_INET, SOCK_STREAM) as sock:
                    sock.settimeout(.3)
                    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                    sock.connect(target)
                    Logger.succses(target[0])
                    Goods += 1
                    self._io.write(target[0])
                    sock.close()
                    continue
                Fails += 1

        
class writeIO:
    def __init__(self, file):
        self._lock = Lock()
        self.file = file
    
    def write(self, data):
        with self._lock, open(self.file, "a+") as f:
            f.write(data + "\n")
        
Goods = Counter()
Fails = Counter()
CPS = Counter()


if __name__ == "__main__":
    print(Colorate.Horizontal(Colors.red_to_blue,Center.XCenter( """
.-.   .-.  .---.   .---. .-. .-. 
 ) \_/ /  ( .-._) ( .-._)| | | | 
(_)   /  (_) \   (_) \   | `-' | 
  / _ \  _  \ \  _  \ \  | .-. | 
 / / ) \( `-'  )( `-'  ) | | |)| 
`-' (_)-'`----'  `----'  /(  (_) 
                        (__)     
 Hello, Welcome to xSSH Scanner.
""")))
    with suppress(KeyboardInterrupt):
        file = Inputs.file("Ip Range File: ")
        with open(file, "r+") as f:
            Logger.info("Loading IP ranges from " + file)
            raaa = RANGEIP.findall(f.read())
            ranged = SyncIPRange(*raaa)
            Logger.info("Loaded %d ip ranges" % len(raaa))
            port = Inputs.integer("Port to scan: ")
            threads = Inputs.integer("Threads: ")
            op = writeIO(input("Output: "))
            Logger.info("Loaded ips", f"{len(ranged):,}")

            for _ in range(threads):
                Scanner(ranged, op, port) .start()

        while True:
            CPS.set(0)
            sleep(1)
            print("CPS: %s | Fails: %s | Goods: %s | Threads: %s | Done: %s%%%s" % (
                    repr(CPS), repr(Fails), repr(Goods),
                    f"{active_count():,}", round((((int(Fails) + int(Goods)) / len(ranged)) * 100), 2),
                    " " * 50), end="\r") 
        