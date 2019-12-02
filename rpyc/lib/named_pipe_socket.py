"""
Impersonate a Unix domain socket using a Windows named pipe.

We just impersonate what's required for RPyC.

We need to implement the following functions for 
server.py and stream.py:
#   accept -
#   bind -
#   close -
#   connect -
#   fileno -
#   getpeername -
#   getsockname -
#   listen -
#   recv -
#   send -
#   shutdown -
#   setblocking -
#   settimeout -
That last one means we need to use overlapped IO (async IO).

We don't seem to need any others. setsockopt is present but not in the code paths we need.
"""
import ctypes
import ctypes.wintypes
import socket
import time
from rpyc.lib import Timeout

AF_UNIX = 1

FILE_FLAG_OVERLAPPED = 0x40000000

# Open mode (when creating pipe) is PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
# We need async I/O to implement timeouts.
OPENMODE = 3 | FILE_FLAG_OVERLAPPED

# Pipe mode (when creating pipe) is default
PIPEMODE = 0

# Access mode (when opening pipe as client) is read | write
ACCESSMODE = 0x80000000 | 0x40000000

# Share mode (when opening pipe as client) is read | write
SHAREMODE = 3

# When opening a pipe we OPEN_EXISTING to avoid creating anything.
OPEN_EXISTING = 3

# Max instances is PIPE_UNLIMITED_INSTANCES
INSTANCES = 255

# Error codes and etc:
ERROR_IO_PENDING = 997
INVALID_HANDLE_VALUE = -1
INFINITE = -1
WAIT_TIMEOUT = 0x102
WAIT_ABANDONED = 0x80
WAIT_OBJECT_0 = 0
ERROR_PIPE_CONNECTED = 535

# The OVERLAPPED struct is a bit odd.
class OVERLAPPED(ctypes.Structure):
    class DummyUnion(ctypes.Union):
        class DummyStruct(ctypes.Structure):
            _fields_ = (
                ("Offset", ctypes.wintypes.DWORD),
                ("OffsetHigh", ctypes.wintypes.DWORD),
            )
        _fields_ = (
            ("DUMMYSTRUCTNAME", DummyStruct),
            ("Pointer", ctypes.c_void_p),
        )

    _fields_ = (
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("DUMMYUNIONNAME", DummyUnion),
        ("hEvent", ctypes.wintypes.HANDLE),
    )

LPOVERLAPPED = ctypes.c_void_p


# Get the windows API calls we need.
runtime = ctypes.windll.kernel32

WriteFile = runtime.WriteFile
WriteFile.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p,
    LPOVERLAPPED,
)

FlushFileBuffers = runtime.FlushFileBuffers
FlushFileBuffers.argtypes = (
    ctypes.wintypes.HANDLE,
)

ReadFile = runtime.ReadFile
ReadFile.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p,
    LPOVERLAPPED,
)

CloseHandle = runtime.CloseHandle
CloseHandle.argtypes = (
    ctypes.wintypes.HANDLE,
)

CreateFileA = runtime.CreateFileA
CreateFileA.argtypes = (
    ctypes.wintypes.LPCSTR,
    ctypes.wintypes.DWORD, # access mode
    ctypes.wintypes.DWORD, # share mode
    ctypes.c_void_p, # security
    ctypes.wintypes.DWORD, # create mode
    ctypes.wintypes.DWORD, # flags
    ctypes.wintypes.HANDLE, # template
)

CallNamedPipeA = runtime.CallNamedPipeA
CallNamedPipeA.argtypes = (
    ctypes.wintypes.LPCSTR,
    ctypes.c_void_p, # write buffer
    ctypes.wintypes.DWORD, # write buffer size
    ctypes.c_void_p, # read buffer
    ctypes.wintypes.DWORD, # read buffer size
    ctypes.c_void_p, # [out] num bytes read
    ctypes.wintypes.DWORD, # timeout (ms)
)

CreateNamedPipeA = runtime.CreateNamedPipeA
CreateNamedPipeA.argtypes = (
    ctypes.wintypes.LPCSTR,
    ctypes.wintypes.DWORD, # open mode
    ctypes.wintypes.DWORD, # pipe mode
    ctypes.wintypes.DWORD, # max instances
    ctypes.wintypes.DWORD, # out buffer size
    ctypes.wintypes.DWORD, # in buffer size
    ctypes.wintypes.DWORD, # default timeout (ms)
    ctypes.c_void_p, # security attributes (null => defaults)
)

ConnectNamedPipe = runtime.ConnectNamedPipe
ConnectNamedPipe.argtypes = (
    ctypes.wintypes.HANDLE,
    LPOVERLAPPED,
)

DisconnectNamedPipe = runtime.DisconnectNamedPipe
DisconnectNamedPipe.argtypes = (
    ctypes.wintypes.HANDLE,
)

CreateEventA = runtime.CreateEventA
CreateEventA.argtypes = (
    ctypes.c_void_p,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.LPCSTR,
)

WaitForSingleObject = runtime.WaitForSingleObject
WaitForSingleObject.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.ULONG, # timeout (ms)
)

ResetEvent = runtime.ResetEvent
ResetEvent.argtypes = (
    ctypes.wintypes.HANDLE,
)

CancelIo = runtime.CancelIo
CancelIo.argtypes = (
    ctypes.wintypes.HANDLE,
)

GetLastError = runtime.GetLastError


class NamedPipeSocket(object):
    """
    Emulate AF_UNIX sockets using Windows Named Pipes.

    The protocol for connecting is:
        server creates a named "listener" pipe (CreateNamedPipeA)
        client calls the pipe to get the name of a private pipe (CallNamedPipeA)
        server accepts that (ConnectNamedPipe), creates a new pipe, writes the path to the listener pipe, and connects the new pipe
    """
    __slots__ = (
        '_bound',
        '_localpath',
        '_remotepath',
        '_handle',
        '_timeout',
        '_clientNum',
        '_overlapped',
        '_read_buffer',
        '_read_buffer_empty',
    )

    def __init__(self, *_):
        self._bound = False
        self._localpath = None
        self._remotepath = None
        self._timeout = INFINITE
        self._clientNum = 0
        self._overlapped = OVERLAPPED()
        self._overlapped.hEvent = CreateEventA(
            None,
            True,
            False,
            None,
        )
        self._handle = INVALID_HANDLE_VALUE
        self._read_buffer = ctypes.c_byte()
        self._read_buffer_empty = True

    def _call_and_wait(self, winapi_async_call, timeout=None):
        """
        Perform an "overlapped" call and wait for it to finish, raising appropriate 
        exceptions on error.

        winapy_async_call must be a lambda that takes no arguments and returns BOOL.

        Returns None, or raises an exception.
        """
        ok = winapi_async_call()
        if ok:
            return

        error = GetLastError()
        if error != ERROR_IO_PENDING:
            raise socket.error(error, "Windows error {}".format(error))

        if timeout is None:
            timeout = self._timeout

        print("waiting {} ms".format(timeout))
        ok = WaitForSingleObject(self._overlapped.hEvent, timeout)
        try:
            if ok == WAIT_OBJECT_0:
                pass
            elif ok == WAIT_TIMEOUT:
                CancelIo(self._handle)
                raise socket.timeout("timed out")
            elif ok == WAIT_ABANDONED:
                raise socket.error(-1, "Wait abandoned")
            else:
                error = GetLastError()
                raise socket.error(error, "Windows error {}".format(error))
        finally:
            ResetEvent(self._overlapped.hEvent)

    def settimeout(self, seconds):
        """
        Set the timeout for blocking operations on the socket.
        None means block forever.
        """
        if seconds is None:
            self._timeout = INFINITE
        else:
            self._timeout = int(seconds * 1000)

    def setblocking(self, flag):
        if flag:
            self.settimeout(None)
        else:
            self.settimeout(0)


    def bind(self, path):
        """
        Bind to a path.

        This actually starts to listen immediately; named pipes don't separate those concepts.
        """
        if not path.startswith('\\\\.\\pipe'):
            path = '\\\\.\\pipe' + re.sub('[\\\\:]', '-', path)
        self._localpath = path
        self._handle = CreateNamedPipeA(
                path,
                OPENMODE,
                PIPEMODE,
                INSTANCES,
                0, # out buffer size
                0, # in buffer size
                1000, # default timeout for a client trying to connect
                None, # default security attributes
        )
        self._bound = True

    def listen(self, *_):
        """
        Start to listen on the named pipe.

        Except... we already did.
        """
        pass

    def accept(self):
        """
        Block until an incoming connection arrives, or until the timeout elapses.
        """
        def do_accept(handle):
            print("connecting on handle {}".format(handle))
            try:
                self._call_and_wait(lambda: ConnectNamedPipe(handle, ctypes.byref(self._overlapped)))
            except socket.timeout:
                raise
            except socket.error as e:
                (err, msg) = e.args
                # ERROR_PIPE_CONNECTED is actually a success! Anything else is a real error.
                if err != ERROR_PIPE_CONNECTED:
                    raise

        do_accept(self._handle)
        self._clientNum += 1
        print("client # {} connected".format(self._clientNum))

        # We've connected. Now, create a *new* pipe and connect that one.
        spawned_path = "{}-{}".format(self._localpath, self._clientNum)
        print("moving connection to {}".format(spawned_path))
        s = NamedPipeSocket()
        s._timeout = self._timeout
        s.bind(spawned_path)
        print("bound")
        s.listen()
        print("listening")
        s._localpath = self._localpath
        s._remotepath = spawned_path

        # Tell the client about the new pipe.
        print("telling client to connect on {} which is {} bytes".format(spawned_path, len(spawned_path)))
        try:
            nBytes = ctypes.c_int(len(spawned_path))
            print("  writing length {}".format(nBytes.value))
            self._call_and_wait(lambda:
                WriteFile(
                    self._handle,
                    ctypes.byref(nBytes),
                    4,
                    None,
                    ctypes.byref(self._overlapped),
                )
            )
            print("  flushing")
            FlushFileBuffers(self._handle)
            print("  writing string [{}]".format(bytes(spawned_path)))
            self._call_and_wait(lambda:
                WriteFile(
                    self._handle,
                    bytes(spawned_path),
                    len(spawned_path),
                    None,
                    ctypes.byref(self._overlapped),
                )
            )
            print("  flushing")
            FlushFileBuffers(self._handle)
            print("  flushed")
        except:
            import traceback
            traceback.print_exc()
            raise
        finally:
            # Hang up on the client from the listener pipe so we can answer the next client.
            DisconnectNamedPipe(self._handle)
            print("restored listener pipe to listen status")

        # Connect to the client on the new pipe.
        do_accept(s._handle)
        print("connected to client on {}".format(spawned_path))

        return (s, spawned_path)

    def shutdown(self, _):
        """
        Send any data that still needs to be sent.

        The read/write argument is ignored; we only flush the write.

        This is blocking no matter what, no timeout.
        """
        FlushFileBuffers(self._handle)

    def close(self):
        """
        Close the socket.

        Unlike with AF_UNIX sockets this will delete the pipe when the last use closes.
        """
        DisconnectNamedPipe(self._handle)
        CloseHandle(self._handle)

    def connect(self, path):
        """
        Connect to a server whose listener pipe is the given path.

        Returns None. After this call, this socket will be connected to the server
        unless an exception was raised.
        """
        timeout = Timeout(self._timeout * 1000)

        def connect_to_pipe(path):
            """
            Connect to a pipe on the given path. Sleep 10ms if we fail, until the timeout runs out.
            """
            while True:
                handle = CreateFileA(
                    path,
                    ACCESSMODE,
                    SHAREMODE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    INVALID_HANDLE_VALUE,
                )
                if handle != INVALID_HANDLE_VALUE:
                    # This is how we break out in the expected case.
                    return handle
                if timeout.expired():
                    # This is how we break out in the timeout case.
                    raise socket.timeout("timed out")
                time.sleep(0.01)

        # Connect to the listener pipe and let the server tell us what pipe to use for our connection.
        print("connecting to {}".format(path))
        handle = connect_to_pipe(path)
        print("connected")

        try:
            print("reading to get connection pipe address length")
            bufferlen = ctypes.c_int()
            self._call_and_wait(lambda: ReadFile(handle, ctypes.byref(bufferlen), 4, None, ctypes.byref(self._overlapped)))
            print("got length = {}".format(bufferlen.value))
            buffer = ctypes.create_string_buffer(bufferlen.value)
            self._call_and_wait(lambda: ReadFile(handle, buffer, bufferlen.value, None, ctypes.byref(self._overlapped)))
            print("got localpath = {}".format(buffer.value))
        except:
            import traceback
            traceback.print_exc()
            raise
        finally:
            CloseHandle(handle)

        # Path is negotiated; now connect on that pipe.
        # There's no good API to do this without looping.
        # WaitForNamedPipe is just a busy-wait.
        self._remotepath = path
        self._localpath = str(buffer.value)
        print("communication pipe is on [{}]".format(self._localpath))
        self._handle = connect_to_pipe(self._localpath)

    def fileno(self):
        if self._handle != INVALID_HANDLE_VALUE:
            return self._handle
        else:
            raise EOFError()

    def getpeername(self):
        return self._remotepath

    def getsockname(self):
        return self._localpath

    def recv(self, n):
        """
        Async recv, can time out.
        """
        print("reading")
        if self._read_buffer_empty:
            # easy case
            buffer = ctypes.create_string_buffer(n)
            n_read = ctypes.c_int()
            self._call_and_wait(lambda: ReadFile(self._handle, buffer, n, ctypes.byref(n_read), ctypes.byref(self._overlapped)))
            return bytes(buffer.value[:n_read.value])
        else:
            # we did a poll, so there's a byte waiting to be included
            first_byte = self._read_buffer
            self._read_buffer_empty = True
            msg = self.recv(n - 1)
            return bytes(first_byte) + msg

    def send(self, msg):
        """
        Write. Does not block, though you might run out of buffer space if you write too fast without reading on the other side.
        """
        n_written = ctypes.c_int()
        WriteFile(self._handle, bytes(msg), len(bytes(msg)), ctypes.byref(n_written), ctypes.byref(self._overlapped))
        return n_written.value

    def poll(self, timeout):
        """
        Blocks up to timeout seconds (None means block indefinitely) until there is data to read.

        Return True if there is data to read, False if we timed out.
        """
        print("polling on {}".format(self._handle))
        if not self._read_buffer_empty:
            return True

        n = ctypes.c_int()
        try:
            # PeekNamedPipe returns instantly no matter what.
            # If we want to sleep until there's data, we need to do a read.
            self._call_and_wait(lambda: ReadFile(self._handle, self._read_buffer, 1, ctypes.byref(n), ctypes.byref(self._overlapped)))
        except socket.timeout:
            return False
        self._read_buffer_empty = False
        return True

