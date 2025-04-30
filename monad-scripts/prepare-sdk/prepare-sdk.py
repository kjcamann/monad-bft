#!/usr/bin/env python3

import argparse
import pathlib
import shutil
import sys

parser = argparse.ArgumentParser(description = 'copy source files to free-standing SDK library')

parser.add_argument('-v', '--verbose', action='count', default=0,
    help='be more verbose, may be repeated')

parser.add_argument('-e', '--execution', action='store', type=pathlib.Path,
    metavar='<exec-repo>', help='path to execution repo')

parser.add_argument('-s', '--source', action='store', type=pathlib.Path,
    default=pathlib.Path(__file__).parent.parent.parent,
    help='path to the monad-bft source repository')

parser.add_argument('dest', action='store', type=pathlib.Path,
    metavar='<dest-repo-root>', help='destination SDK repo dir')

def main(script_dir: pathlib.Path, args: argparse.Namespace) -> int:
  if args.verbose:
    print(args)

  src_repo_root = args.source
  dest_repo_root = args.dest
  exec_repo = args.execution or src_repo_root / 'monad-cxx' / 'monad-execution'

  EventRingPackageName = 'monad-event-ring'
  ExecEventsPackageName = 'monad-exec-events'

  shutil.rmtree(dest_repo_root / EventRingPackageName)
  shutil.copytree(src_repo_root / EventRingPackageName,
                  dest_repo_root / EventRingPackageName)
  shutil.copy2(script_dir / 'build-event-ring.rs',
               dest_repo_root / EventRingPackageName / 'build.rs')

  shutil.rmtree(dest_repo_root / ExecEventsPackageName)
  shutil.copytree(src_repo_root / ExecEventsPackageName,
                  dest_repo_root / ExecEventsPackageName)
  shutil.copy2(script_dir / 'build-exec-events.rs',
               dest_repo_root / ExecEventsPackageName / 'build.rs')

  NativeApiDirectory = 'monad-event-c'
  shutil.rmtree(dest_repo_root / NativeApiDirectory)
  shutil.copytree(exec_repo / 'category' / 'event',
                  dest_repo_root / NativeApiDirectory)
  shutil.copy2(script_dir / 'CMakeLists.txt',
               dest_repo_root / NativeApiDirectory / 'CMakeLists.txt')

  # Copy event ring sources
  event_lib_files = [
    'event_iterator.h',
    'event_iterator_inline.h',
    'event_metadata.h',
    'event_ring.c',
    'event_ring.h',
    'event_ring_util.c',
    'event_ring_util.h',
  ]
  event_dir_relative = pathlib.Path('category/core/event')
  c_event_dest_dir = dest_repo_root / NativeApiDirectory / event_dir_relative
  c_event_dest_dir.mkdir(parents=True, exist_ok=True)
  for file in event_lib_files:
    shutil.copy2(exec_repo / event_dir_relative / file, c_event_dest_dir)

  # Copy support files
  core_lib_files = ['format_err.c', 'format_err.h', 'srcloc.h']
  core_dir_relative = pathlib.Path('category/core')
  c_core_dest_dir = dest_repo_root / NativeApiDirectory / core_dir_relative
  c_core_dest_dir.mkdir(parents=True, exist_ok=True)
  for file in core_lib_files:
    shutil.copy2(exec_repo / core_dir_relative / file, c_core_dest_dir)

  # Copy core execution definition files
  exec_eth_dir_relative = pathlib.Path('category/execution/ethereum')
  c_exec_core_dest_dir = dest_repo_root / NativeApiDirectory / exec_eth_dir_relative / 'core'
  c_exec_core_dest_dir.mkdir(parents=True, exist_ok=True)
  exec_core_files = ['base_ctypes.h', 'eth_ctypes.h']
  for file in exec_core_files:
    shutil.copy2(exec_repo / exec_eth_dir_relative / 'core' / file,
                 c_exec_core_dest_dir)

  # Copy execution event ring files
  exec_event_files = [
    'exec_event_ctypes.h',
    'exec_event_ctypes_metadata.c',
    'exec_iter_help.h',
    'exec_iter_help_inline.h'
  ]
  c_exec_event_dest_dir = dest_repo_root / NativeApiDirectory / exec_eth_dir_relative / 'event'
  c_exec_event_dest_dir.mkdir(parents=True, exist_ok=True)
  for file in exec_event_files:
    shutil.copy2(exec_repo / exec_eth_dir_relative / 'event' / file,
                 c_exec_event_dest_dir)

  return 0

if __name__ == '__main__':
  script_dir = pathlib.Path(__file__).parent
  sys.exit(main(script_dir, parser.parse_args()))
