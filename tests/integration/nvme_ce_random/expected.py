#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent byte replay from frozen input images and requests, no BPF plans."""
import struct

_MASK = (1 << 64) - 1
_STEP = 0x9e3779b97f4a7c15


def _initial(length, seed):
    if type(length) is not int or not 0 <= length <= _MASK:
        raise ValueError('invalid initial image length')
    image = bytearray(length)
    for offset in range(0, length, 8):
        word = ((offset // 8) * _STEP + seed) & _MASK
        part = struct.pack('<Q', word)
        image[offset:offset+min(8, length-offset)] = part[:min(8, length-offset)]
    return bytes(image)


def gpu_initial(length):
    return _initial(length, 0x10213243c9a47f5a)


def disk_initial(length):
    return _initial(length, 0x21324354c6b5a493)


def _intervals(rows, disk_length, allocation_length, guard, window_length, disk_guard, disk_window_length, save):
    if type(guard) is not int or guard < 0 or guard > allocation_length // 2:
        raise ValueError('invalid allocation guard')
    if window_length is None:
        window_length = allocation_length - 2 * guard
    if disk_window_length is None:
        disk_window_length = disk_length - 2 * disk_guard
    if (type(window_length) is not int or not 0 <= window_length <= allocation_length - 2*guard or
            type(disk_guard) is not int or disk_guard < 0 or
            type(disk_window_length) is not int or not 0 <= disk_window_length <= disk_length - 2*disk_guard):
        raise ValueError('invalid authorized window or disk guard')
    previous_phase = -1
    phase_ranges = []
    for row in rows:
        values = [row[name] for name in ('nvme_offset', 'gpu_offset', 'bytes', 'phase')]
        if any(type(value) is not int or value < 0 or value > _MASK for value in values):
            raise ValueError('invalid request integer')
        disk, gpu, length, phase = values
        if not length or phase < previous_phase or disk > disk_window_length or length > disk_window_length-disk:
            raise ValueError('invalid disk interval or phase')
        if gpu > window_length or length > window_length-gpu:
            raise ValueError('invalid GPU interval')
        if phase != previous_phase:
            phase_ranges = []
        for old_disk, old_gpu, old_length in phase_ranges:
            if gpu < old_gpu+old_length and old_gpu < gpu+length:
                raise ValueError('same-phase GPU overlap has no ordered oracle')
            if save and disk < old_disk+old_length and old_disk < disk+length:
                raise ValueError('same-phase storage WRITE overlap has no ordered oracle')
        phase_ranges.append((disk, gpu, length))
        previous_phase = phase
        yield disk_guard+disk, guard+gpu, length


def load_image(initial_gpu, frozen_disk, rows, guard, *, window_length=None, disk_guard=0, disk_window_length=None):
    image = bytearray(initial_gpu)
    for disk, gpu, length in _intervals(rows, len(frozen_disk), len(initial_gpu), guard, window_length, disk_guard, disk_window_length, False):
        image[gpu:gpu+length] = frozen_disk[disk:disk+length]
    return bytes(image)


def save_image(initial_disk, frozen_gpu, rows, guard, *, window_length=None, disk_guard=0, disk_window_length=None):
    image = bytearray(initial_disk)
    for disk, gpu, length in _intervals(rows, len(initial_disk), len(frozen_gpu), guard, window_length, disk_guard, disk_window_length, True):
        image[disk:disk+length] = frozen_gpu[gpu:gpu+length]
    return bytes(image)


def compare(actual, want):
    if len(actual) != len(want):
        raise ValueError('whole image length differs')
    count = 0
    first = None
    for position, (got, byte) in enumerate(zip(actual, want)):
        if got != byte:
            count += 1
            if first is None:
                first = position
    return dict(equal=count == 0, mismatch_count=count, first_mismatch=first)
