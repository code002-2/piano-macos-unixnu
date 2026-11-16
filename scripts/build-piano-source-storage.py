#!/usr/bin/env python3
"""Build the arm64e source UFS runtime for piano (SM8750) and its authenticated policy handoff."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def weak_defaults(source):
    import re
    lines = []
    for line in source.read_text().splitlines():
        line = line.strip()
        if not (line.startswith('extern ') and line.endswith('__attribute__((weak_import));')):
            continue
        decl = line[len('extern '):-len('__attribute__((weak_import));')].replace('__attribute__((weak_import))', '').strip()
        call = re.match(r'^(.*?[\s*])([A-Za-z_]\w*)\s*\((.*)\)$', decl)
        if call and '(*' not in decl.split(call.group(2))[0]:
            ret = call.group(1).strip()
            body = ('' if ret == 'void' else ' return -1;' if ret == 'int' else
                    ' return "";' if ret.replace(' ', '') in ('constchar*', 'char*') else ' return 0;')
            lines.append(f'__attribute__((weak, visibility("hidden"))) {decl} {{{body} }}')
        else:
            lines.append(f'__attribute__((weak, visibility("hidden"))) {decl};')
    includes = [l.replace('#include "', f'#include "{source.parent}/') for l in source.read_text().splitlines()
                if l.startswith('#include')]
    named = set(re.findall(r'struct (\w+)', '\n'.join(lines)))
    includes += [m.group(0) for m in re.finditer(r'^struct (\w+) \{[^;{}]*(?:;[^;{}]*)*\};', source.read_text(), re.M)
                 if m.group(1) in named]
    pragma = ['#pragma clang diagnostic ignored "-Wc23-extensions"']
    return '\n'.join(includes + pragma + lines) + '\n'


def prepare_native_ufs(source_path, out_path):
    text = source_path.read_text()
    old_weak = 'void boot_progress_poll (void) __attribute__((weak));'
    if old_weak not in text:
        raise SystemExit(f'{source_path}: expected weak boot_progress_poll declaration')
    text = text.replace(old_weak, 'void boot_progress_poll (void);', 1)
    text = text.replace('if (boot_progress_poll) boot_progress_poll ();', 'boot_progress_poll ();')
    meta_marker = 'OSDefineMetaClassAndStructors (NativeUfsBlock, IOBlockStorageDevice)'
    if meta_marker not in text:
        raise SystemExit(f'{source_path}: expected NativeUfsBlock metaclass macro')
    text = text.replace(meta_marker, meta_marker + '\n\nextern "C" IOService *native_ufs_source_create(void)\n{\n  return new NativeUfs;\n}\n', 1)
    out_path.write_text(text)
    return out_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, default=ROOT)
    parser.add_argument('--device', type=Path)
    parser.add_argument('--storage-source', type=Path)
    parser.add_argument('--policy-dir', type=Path)
    args = parser.parse_args()
    tree = args.tree.resolve()
    device = Path(os.environ.get('UNIXNU_DEVICE') or args.device or tree).resolve()
    storage = (args.storage_source or tree / 'refer/IOStorageFamily').resolve()
    build_id = os.environ.get('UNIXNU_IPSW_BUILD')
    if not build_id:
        parser.error('UNIXNU_IPSW_BUILD is not set; run through unixnu build kernel')

    policies = args.policy_dir or (tree / f'build/verified-root-{build_id}')
    if not args.policy_dir and not policies.is_dir():
        shipped = sorted(tree.glob(f'scripts/policies/*{build_id}'))
        if len(shipped) != 1:
            parser.error(f'no policy directory for {build_id}: pass --policy-dir or ship scripts/policies/*{build_id}')
        policies = shipped[0]
    policies = policies.resolve()

    package_dirs = [device / 'package']
    if device != tree:
        package_dirs += [device / 'kits/piano', tree / 'kits/piano']
    else:
        package_dirs += [tree / 'kits/piano']

    def device_source(relative):
        for directory in package_dirs + [device, tree]:
            candidate = directory / relative
            if candidate.is_file():
                return candidate
        parser.error(f'{relative} not found under the device or build tree')

    if os.environ.get('UNIXNU_XNU_ARCH', 'arm64e') != 'arm64e':
        parser.error('This adapter requires an arm64e profile')
    os.environ['UNIXNU_XNU_ARCH'] = 'arm64e'
    if int(os.environ.get('UNIXNU_IOS_VERSION', '0').split('.')[0]) < 26:
        parser.error('This adapter requires iOS/iPadOS/macOS 26 or later')

    build = helper('source_compile', ROOT / 'scripts/build-sheng-source-drivers.py')
    headers = helper('source_headers', ROOT / 'scripts/prepare-storage-headers.py')
    target = helper('source_target', ROOT / 'scripts/kernel_target.py')
    out = tree / 'build/piano-source-storage'
    out.mkdir(parents=True, exist_ok=True)
    header_report = headers.prepare(storage, '7edb88fbae296fb7c8ce2f64e115e116e566d51c', out / 'headers')

    tables_in_userdata = os.environ.get('XNU_SOURCE_STORAGE_TABLES', '') == 'userdata'
    default_policies = 'OS,SystemOS,App' if (policies / 'App').is_dir() else 'OS,SystemOS'
    selected = [name.strip() for name in (os.environ.get('UNIXNU_SOURCE_STORAGE_POLICIES') or os.environ.get('XNU_SOURCE_STORAGE_POLICIES', default_policies)).split(',')
                if name.strip() in ('OS', 'SystemOS', 'App')]
    if not selected:
        parser.error('UNIXNU_SOURCE_STORAGE_POLICIES names no policy')
    manifest_paths = [policies / name / 'manifest.bin' for name in selected]
    key = (policies / f'{selected[0]}/trusted-key.bin').read_bytes()
    if len(key) != 395 or any(key != (policies / f'{name}/trusted-key.bin').read_bytes() for name in selected):
        parser.error('All selected policies must share the same complete explicit owner anchor')

    manifests = []
    expected = {}
    for name, prefix in (('OS', 'UNIXNU_ROOT_OS'), ('SystemOS', 'UNIXNU_ROOT_SYSTEMOS'), ('App', 'UNIXNU_ROOT_APP')):
        digest, identity = os.environ.get(prefix + '_SHA256'), os.environ.get(prefix + '_UUID')
        if name in selected and not (digest and identity):
            parser.error(f'the OS profile has no [root] {name.lower()}_image_sha256 and {name.lower()}_volume_uuid')
        expected[name] = (digest, identity and identity.upper())
    for path in manifest_paths:
        verification = json.loads(path.with_name('verification.json').read_text())
        digest, identity = expected[path.parent.name]
        if (not verification['real_c_signature_and_block_verification'] or
                verification['image_sha256'] != digest or verification['volume_uuid'] != identity or
                verification['trusted_key_sha256'] != hashlib.sha256(key).hexdigest()):
            parser.error(f'{path.parent.name}: require complete verification of the actual {build_id} image')
        header = path.with_name('manifest.header.bin')
        if tables_in_userdata and header.is_file():
            data = header.read_bytes()
            if len(data) != 544 or data[56:88].hex() != digest:
                parser.error(f'{header}: policy header does not describe the selected image')
            manifests.append(data)
        else:
            data = path.read_bytes()
            if len(data) < 544 or data[56:88].hex() != digest:
                parser.error(f'{path}: manifest does not describe the selected image')
            manifests.append(data[:544] if tables_in_userdata else data)

    cursor = 32 + 16 * len(manifests)
    table = bytearray()
    for data in manifests:
        table += struct.pack('<QQ', cursor, len(data))
        cursor += len(data)
    bundle = struct.pack('<8sQQQ', b'VROOTB01', 1, len(manifests), cursor) + table + b''.join(manifests)
    (out / 'root-policies.bin').write_bytes(bundle)

    boot_log_defaults = out / 'BootLogDefaults.c'
    boot_log_defaults.write_text(weak_defaults(device_source('BootLog.c')))
    anchor = out / 'RootAnchor.c'
    anchor.write_text('#include <stdint.h>\nconst uint8_t verified_root_key[395] = {' +
                      ','.join(str(b) for b in key) + '};\n')
    base = out / 'IOBlockStorageDevice.cpp'
    original = (storage / 'IOBlockStorageDevice.cpp').read_text()
    macro = 'OSDefineMetaClassAndAbstractStructors(IOBlockStorageDevice,IOService)'
    if original.count(macro) != 1:
        parser.error('Pinned IOBlockStorageDevice registration macro changed')
    base.write_text(original.replace(macro, '''
extern "C" const OSMetaClass *native_source_storage_parent(void);
OSDefineMetaClassWithInit(IOBlockStorageDevice, IOService, )
IOBlockStorageDevice::MetaClass::MetaClass()
    : OSMetaClass("UniXNUBlockStorageDevice", native_source_storage_parent(), sizeof(IOBlockStorageDevice)) {}
OSDefineAbstractStructors(IOBlockStorageDevice, IOService)
OSDefineOperatorMethods(IOBlockStorageDevice)
'''))

    ufs_dir = tree / 'drivers/NativeUfs'
    if not (ufs_dir / 'NativeUfs.cpp').is_file():
        ufs_dir = device / 'modules/Piano/drivers/NativeUfs'
    native_ufs = prepare_native_ufs(ufs_dir / 'NativeUfs.cpp', out / 'NativeUfs.cpp')

    obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    cpp = json.loads((obj / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
    c = json.loads((obj / 'osfmk/DEVELOPMENT/startup.o.json').read_text().strip().rstrip(','))
    bsd = json.loads((obj / 'bsd/DEVELOPMENT/kern_exec.o.json').read_text().strip().rstrip(','))
    bsd_sources = {'BootWatchdogPolicy.c', 'BootDiagExport.c'}
    pkg_dir = device_source('SourceStorage.cpp').parent
    includes = ['-I', str(out / 'headers/include'),
                '-I', str(ROOT / 'kits/VerifiedRoot/include'),
                '-I', str(ROOT / 'drivers/VirtioMmioBlock'),
                '-I', str(ufs_dir),
                '-I', str(pkg_dir),
                '-I', str(tree / '.cache/xnu-work/osfmk')]
    flags = ['-DNATIVE_UFS_SOURCE_API=1', '-DNATIVE_UFS_SM8750=1', '-DNATIVE_VERIFIED_BLOCK=1',
             '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1', '-DNATIVE_VERIFIED_POLICY_HANDOFF=1']
    if os.environ.get('UNIXNU_XNU_TARGET') == 'macosx':
        osx = out / 'macos-target.h'
        osx.write_text('/* Generated: the macOS IOStorageFamily ABI on the iOS-triple kernel. */\n'
                       '#include <TargetConditionals.h>\n#undef TARGET_OS_OSX\n#define TARGET_OS_OSX 1\n')
        flags += ['-include', str(osx)]

    sources = [base, native_ufs, ROOT / 'drivers/RamBlock/NativeRamBlock.cpp',
               device_source('SourceStorage.cpp'), device_source('SourceRootPolicies.cpp'),
               device_source('SourceRootBinding.cpp'), device_source('BootLog.c'), boot_log_defaults,
               device_source('BootReset.c'), device_source('BootProcessProbe.c'),
               device_source('BootUiTraceProbe.c'), device_source('BootProcessWorker.c'),
               device_source('BootWatchdogPolicy.c'), device_source('BootDiagExport.c'),
               ROOT / 'kits/VerifiedRoot/src/verified_root.c',
               ROOT / 'kits/VerifiedRoot/adapters/xnu_crypto.c', anchor]
    flags.append('-DNATIVE_BOOT_PROCESS_CAPTURE=1')

    objects, inputs = [], {}
    objcopy = shutil.which('llvm-objcopy') or '/opt/homebrew/opt/llvm/bin/llvm-objcopy'
    for source in sources:
        record = (bsd if source.name in bsd_sources else c) if source.suffix == '.c' else cpp
        output = out / (source.stem + '.o')
        command = build.compile_command(record, source, output, includes, flags)
        if source in (base, native_ufs):
            command.append('-Wno-error')
        result = subprocess.run(command, cwd=record['directory'], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / (source.stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        (out / (source.stem + '.log')).write_text(result.stdout)
        if result.returncode:
            raise SystemExit(f'{source.name}: compile failed\n{result.stdout[-6000:]}')
        target.check_object(output.read_bytes(), source.name)
        if source.name in ('IOBlockStorageDevice.cpp', 'NativeUfs.cpp', 'NativeRamBlock.cpp'):
            late = output.with_suffix('.late.o')
            subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func',
                            f'--globalize-symbol=__GLOBAL__sub_I_{source.name}', output, late], check=True)
            output = late
        objects.append(output)
        inputs[str(source)] = build.sha(source)

    archive = out / 'libPianoSourceStorage.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['xcrun', 'ar', 'rcs', archive, *objects], check=True)
    report = dict(archive=str(archive), archive_sha256=build.sha(archive), sources=inputs,
                  headers=header_report, target=target.TRIPLE,
                  policy_bundle_sha256=build.sha(out / 'root-policies.bin'),
                  trusted_key_sha256=hashlib.sha256(key).hexdigest(), runtime_qualified=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(archive)


if __name__ == '__main__':
    main()
