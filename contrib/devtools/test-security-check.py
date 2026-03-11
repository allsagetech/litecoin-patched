#!/usr/bin/env python3
# Copyright (c) 2015-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Test script for security-check.py
'''
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT_PATH = pathlib.Path(__file__).with_name('security-check.py')
SPEC = importlib.util.spec_from_file_location('security_check', SCRIPT_PATH)
SECURITY_CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY_CHECK)


def write_testcode(filename):
    with open(filename, 'w', encoding="utf8") as f:
        f.write('''
    #include <stdio.h>
    int main()
    {
        printf("the quick brown fox jumps over the lazy god\\n");
        return 0;
    }
    ''')


def call_security_check(cc, source, executable, options):
    subprocess.run([cc, source, '-o', executable] + options, check=True)
    p = subprocess.run([sys.executable, str(SCRIPT_PATH), executable], stdout=subprocess.PIPE, universal_newlines=True)
    return (p.returncode, p.stdout.rstrip())


def command_exists(command):
    try:
        if pathlib.Path(command).exists():
            return True
    except OSError:
        pass
    return shutil.which(command) is not None


class TestSecurityChecks(unittest.TestCase):
    def require_tools(self, *commands):
        missing = [command for command in commands if not command_exists(command)]
        if missing:
            self.skipTest('Missing required tools: ' + ', '.join(missing))

    def test_identify_executable_magic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = (
                (b'MZ\x00\x00', 'PE'),
                (b'\x7fELF', 'ELF'),
                (b'\xcf\xfa\xed\xfe', 'MACHO'),
                (b'\x00\x00\x00\x00', None),
            )
            for index, (magic, expected) in enumerate(cases):
                with self.subTest(expected=expected):
                    path = pathlib.Path(tmpdir) / f'magic-{index}.bin'
                    path.write_bytes(magic)
                    self.assertEqual(SECURITY_CHECK.identify_executable(str(path)), expected)

    def test_ELF(self):
        source = 'test1.c'
        executable = 'test1'
        cc = 'gcc'
        self.require_tools(cc, SECURITY_CHECK.READELF_CMD)
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-zexecstack','-fno-stack-protector','-Wl,-znorelro','-no-pie','-fno-PIE', '-Wl,-z,separate-code']),
                (1, executable+': failed PIE NX RELRO Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fno-stack-protector','-Wl,-znorelro','-no-pie','-fno-PIE', '-Wl,-z,separate-code']),
                (1, executable+': failed PIE RELRO Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-znorelro','-no-pie','-fno-PIE', '-Wl,-z,separate-code']),
                (1, executable+': failed PIE RELRO'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-znorelro','-pie','-fPIE', '-Wl,-z,separate-code']),
                (1, executable+': failed RELRO'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-zrelro','-Wl,-z,now','-pie','-fPIE', '-Wl,-z,noseparate-code']),
                (1, executable+': failed separate_code'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-zrelro','-Wl,-z,now','-pie','-fPIE', '-Wl,-z,separate-code']),
                (0, ''))

    def test_PE(self):
        source = 'test1.c'
        executable = 'test1.exe'
        cc = 'x86_64-w64-mingw32-gcc'
        self.require_tools(cc, SECURITY_CHECK.OBJDUMP_CMD)
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--no-nxcompat','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed DYNAMIC_BASE HIGH_ENTROPY_VA NX RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed DYNAMIC_BASE HIGH_ENTROPY_VA RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed HIGH_ENTROPY_VA RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase','-Wl,--high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase','-Wl,--high-entropy-va','-pie','-fPIE']),
            (0, ''))

    def test_MACHO(self):
        source = 'test1.c'
        executable = 'test1'
        cc = 'clang'
        self.require_tools(cc, SECURITY_CHECK.OTOOL_CMD)
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-flat_namespace','-Wl,-allow_stack_execute','-fno-stack-protector']),
            (1, executable+': failed PIE NOUNDEFS NX LAZY_BINDINGS Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-flat_namespace','-Wl,-allow_stack_execute','-fstack-protector-all']),
            (1, executable+': failed PIE NOUNDEFS NX LAZY_BINDINGS'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-flat_namespace','-fstack-protector-all']),
            (1, executable+': failed PIE NOUNDEFS LAZY_BINDINGS'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-fstack-protector-all']),
            (1, executable+': failed PIE LAZY_BINDINGS'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-bind_at_load','-fstack-protector-all']),
            (1, executable+': failed PIE'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-pie','-Wl,-bind_at_load','-fstack-protector-all']),
            (0, ''))

if __name__ == '__main__':
    unittest.main()
