# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
# Exact GroupCoordinator methods from vLLM v0.10.2, commit
# 01efc7ef781391e744ed08c3292817a773d654e6, parallel_state.py.
# Dependencies are boundary stand-ins in tests; these are upstream method bodies.
from __future__ import annotations
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from typing import Optional
import torch

@dataclass
class GraphCaptureContext:
    stream: object

class GroupCoordinator:
    @contextmanager
    def graph_capture(
            self, graph_capture_context: Optional[GraphCaptureContext] = None):
        if graph_capture_context is None:
            stream = torch.cuda.Stream()
            graph_capture_context = GraphCaptureContext(stream)
        else:
            stream = graph_capture_context.stream

        # only cuda uses this function,
        # so we don't abstract it into the base class
        maybe_ca_context = nullcontext()
        from vllm.distributed.device_communicators.cuda_communicator import (
            CudaCommunicator)
        if self.device_communicator is not None:
            assert isinstance(self.device_communicator, CudaCommunicator)
            ca_comm = self.device_communicator.ca_comm
            if ca_comm is not None:
                maybe_ca_context = ca_comm.capture()  # type: ignore

        # ensure all initialization operations complete before attempting to
        # capture the graph on another stream
        curr_stream = torch.cuda.current_stream()
        if curr_stream != stream:
            stream.wait_stream(curr_stream)

        with torch.cuda.stream(stream), maybe_ca_context:
            yield graph_capture_context

    def destroy(self):
        if hasattr(self, "device_group"):
            torch.distributed.destroy_process_group(self.device_group)
            del self.device_group
        if hasattr(self, "cpu_group"):
            torch.distributed.destroy_process_group(self.cpu_group)
            del self.cpu_group
        if self.device_communicator is not None:
            self.device_communicator.destroy()
        if self.mq_broadcaster is not None:
            self.mq_broadcaster = None


@contextmanager
def graph_capture(device: torch.device):
    """
    `graph_capture` is a context manager which should surround the code that
    is capturing the CUDA graph. Its main purpose is to ensure that some
    operations will be run after the graph is captured, before the graph
    is replayed. It returns a `GraphCaptureContext` object which contains the
    necessary data for the graph capture. Currently, it only contains the
    stream that the graph capture is running on. This stream is set to the
    current CUDA stream when the context manager is entered and reset to the
    default stream when the context manager is exited. This is to ensure that
    the graph capture is running on a separate stream from the default stream,
    in order to explicitly distinguish the kernels to capture
    from other kernels possibly launched on background in the default stream.
    """
    context = GraphCaptureContext(torch.cuda.Stream(device=device))
    with get_tp_group().graph_capture(context), get_pp_group().graph_capture(
            context):
        yield context
