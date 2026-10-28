# SPDX-License-Identifier: GPL-2.0
"""Default worker admission, with control-plane agreement before native START."""
import os

_FAILED_STARTUPS = []


def _close_failed_startup(backend):
    if backend is None:
        return
    try:
        backend.close()
    except Exception:
        # Preserve an inspectable Python owner as well as native custody.
        _FAILED_STARTUPS.append(backend)


def create_backend(communicator):
    import torch
    from xdev_tp_torch import TorchCommunicator
    from xdev_tp_torch.config import agreement_key, load_options
    path = os.environ.get('XDEV_TP_CONFIG', '')
    if not path:
        raise RuntimeError('strict TP requires rank-local XDEV_TP_CONFIG JSON')
    with torch.cuda.device(communicator.device):
        device = torch.cuda.current_device()
        options = load_options(path, rank=communicator.rank_in_group,
                               group=communicator.unique_name, device_index=device)
        local = dict(rank=communicator.rank_in_group, group=communicator.unique_name,
                     configuration=agreement_key(options))
        peers = [None, None]
        torch.distributed.all_gather_object(peers, local, group=communicator.cpu_group)
        if (any(not isinstance(peer, dict) for peer in peers) or
                {peer.get('rank') for peer in peers} != {0, 1} or
                any(peer.get('group') != local['group'] or
                    peer.get('configuration') != local['configuration'] for peer in peers)):
            raise RuntimeError('TP ranks did not agree on strict admission configuration')
        backend = None
        failure = None
        try:
            backend = TorchCommunicator.from_options(options)
        except Exception as error:
            failure = error
        ready = dict(rank=communicator.rank_in_group, ready=backend is not None,
                     error=None if failure is None else str(failure))
        admitted = [None, None]
        try:
            torch.distributed.all_gather_object(admitted, ready, group=communicator.cpu_group)
        except Exception:
            _close_failed_startup(backend)
            raise
        if (any(not isinstance(peer, dict) or not peer.get('ready') for peer in admitted) or
                {peer.get('rank') for peer in admitted} != {0, 1}):
            _close_failed_startup(backend)
            raise RuntimeError('both TP ranks must finish native admission before first payload') from failure
        return backend
