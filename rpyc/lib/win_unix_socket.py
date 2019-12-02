"""
Impersonate a Unix domain socket using a Windows Unix domain socket.

There's no python support for them on Windows: bpo-33408.

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

We don't seem to need any others. setsockopt is present but not in the code
paths we need.
"""
import ctypes
import ctypes.wintypes
import socket
import time
from rpyc.lib import Timeout

AF_UNIX = 1
POLLIN = 0x100 | 0x200
POLLOUT = 0x10
WSAEINTR = 10004
INFINITE = -1
FIONBIO = 0x8004667e
MAX_PATH_LENGTH = 260

# Get the windows API calls we need.
runtime = ctypes.windll.ws2_32

# On startup (when we import this module), initialize winsock.
def init_winsock():
    class WSAData(ctypes.Structure):
        _fields_ = (
            ('wVersion', ctypes.wintypes.WORD),
            ('wHighVersion', ctypes.wintypes.WORD),
            ('foo', ctypes.CHAR * 4000), # unclear, but a page should be plenty enough.
        )
    data = WSAData()

    # Request API 2.2 which is available since win98/win2k, 20 years before
    # AF_UNIX support was finally added.
    runtime.WSAStartup(0x0202, data)
init_winsock()


# The SOCKET type is intptr.
SOCKET = cypes.c_void_p

# sockaddr_un for storing unix addresses.
class sockaddr_un(ctypes.Structure):
    _fields_ = (
        ('sun_family', ctypes.c_ushort),
        ('sun_path', ctypes.c_char * MAX_PATH_LENGTH),
    )

# for poll
class pollfd(ctypes.Structure):
    _fields_ = (
        ('fd', SOCKET),
        ('events', ctypes.c_short),
        ('revents', ctypes.c_short),
    )

#########################
# Import the calls we need

socket = runtime.socket
socket.argtypes = (
    ctypes.c_int, # address family
    ctypes.c_int, # type
    ctypes.c_int, # protocol
)

accept = runtime.accept
accept.argtypes = (
    SOCKET,
    ctypes.POINTER(sockaddr_un),
    ctypes.POINTER(ctypes.c_int),
)

bind = runtime.bind
bind.argtypes = (
    SOCKET,
    ctypes.POINTER(sockaddr_un),
    ctypes.c_int,
)

close = runtime.closesocket
close.argtypes = (
    SOCKET,
)

connect = runtime.connect
connect.argtypes = (
    SOCKET,
    ctypes.POINTER(sockaddr_un),
    ctypes.c_int,
)

getpeername = runtime.getpeername
getpeername.argtypes = (
    SOCKET,
    ctypes.POINTER(sockaddr_un),
    ctypes.POINTER(ctypes.c_int),
)

getsockname = runtime.getsockname
getsockname.argtypes = (
    SOCKET,
    ctypes.POINTER(sockaddr_un),
    ctypes.POINTER(ctypes.c_int),
)

listen = runtime.listen
listen.argtypes = (
    SOCKET,
    ctypes.c_int, # backlog
)

recv = runtime.recv
recv.argtypes = (
    SOCKET,
    ctypes.c_char_p, # buf
    ctypes.c_int, # len
    ctypes.c_int, # flags
)

send = runtime.send
send.argtypes = (
    SOCKET,
    ctypes.c_char_p, # buf
    ctypes.c_int, # len
    ctypes.c_int, # flags
)

shutdown = runtime.shutdown
shutdown.argtypes = (
    SOCKET,
    ctypes.c_int, # how
)

errno_fn = runtime.WSAGetLastError
errno_fn.argtypes = ()

# for setblocking
ioctl = runtime.ioctlsocket
ioctl.argtypes = (
    SOCKET,
    ctypes.c_long, # cmd
    ctypes.POINTER(ctypes.c_ulong), # argp
)

poll = runtime.poll
poll.argtypes = (
    ctypes.POINTER(pollfd), # fds
    ctypes.c_ulong, # number of fds
    ctypes.c_int, # timeout (ms)
)


# copy the concept in cpython:
#   * wait until the socket is readable or writeable
#   * first, evaluate the function
#   * if interrupted by a signal, retry
#   * if timeout is set, run async and wait for completion or timeout.
def wait_for_fd(s, r_w_connect, timeout):
    """
    Wait until the socket is ready.

    Low on error handling.

    r_w_connect is 0 for read, 1 for write, 2 for connect
    """
    p = pollfd()
    p.fd = s._sock_fd
    if r_w_connect == 0:
        p.events = POLLIN
    elif r_w_connect == 1:
        p.events = POLLOUT
    else:
        p.events = POLLIN | POLLERR

    return poll(byref(p), 1, timeout)

def call_socket_fn(s, r_w_connect, sockfn):
    """
    Call a function (passed in as a lambda: () -> bool) on a socket,
    with a specified timeout in ms.

    r_w_connect is 0 for read, 1 for write, 2 for connect

    The socket must be non-blocking unless timeout is -1.
    The caller must make sure the sockfn is calling a socket function on
    the socket passed in; we can't check.

    Heavily based on cpython's sock_call_ex.
    """
    # QueryPerformanceCounter, monotonic and accurate to sub-microsecond.
    timeout = s._timeout
    if timeout >= 0:
        start_t = time.clock()
        end_t = start_t + timeout

    while True:
        if timeout > 0 or r_w_connect == 2:
            err = wait_for_fd(s, r_w_connect, end_t - time.clock())
            if err < 0:
                # get the error reason
                err = errno_fn()
                if err == WSAEINTR:
                    # interrupted by signal (and didn't raise) => retry
                    continue
                else:
                    # some other kind of error => raise
                    raise socket.error(err, "Windows error {}".format(err))
            elif err == 0:
                # timeout
                raise socket.timeout("timed out")

            # socket is ready; do the thing (loop until we aren't interrupted)
            while True:
                ok = (sockfn() == 0)
                if ok:
                    ######################
                    # The thing is done!
                    # This is the only success codepath.
                    ######################
                    return
                else:
                    # why did it fail?
                    err = errno_fn()
                    if err == WSAEINTR:
                        # interrupted by signal (and didn't raise) => retry
                        continue
                    else:
                        # not interrupted by signal => break out to outer while
                        # loop and handle it there.
                        break

            if err = WSAEWOULDBLOCK or err = WSAEAGAIN:
                # non-blocking IO fails with this until IO is done; loop
                # back to the poll().
                continue

            # if we're here, the error is scary
            raise socket.error(err, "Windows error {}")


class WindowsUnixSocket(object):
    """
    Emulate python AF_UNIX sockets using windows AF_UNIX sockets.

    Python doesn't have support for AF_UNIX on Windows, though Windows itself
    does, so we need to reimplement socketmodule.c to get compatibility.
    """
    __slots__ = (
        "_sock_fd",
        "_timeout",
    )

    def __init__(self, af=AF_UNIX, type=socket.SOCK_STREAM, proto=0, fd = None):
        self._timeout = INFINITE
        if af != AF_UNIX or type != socket.SOCK_STREAM:
            raise socket.error("Invalid family or type: AF_UNIX and SOCK_STREAM is what we implement")
        if fd is None:
            self._sock_fd = socket(AF_UNIX, socket.SOCK_STREAM, 0)
        else:
            self._sock_fd = fd

    def settimeout(self, seconds):
        """
        Set the timeout for blocking operations on the socket.
        None means block forever.
        """
        if seconds is None or seconds < 0:
            self._timeout = INFINITE
            is_async = ctypes.wintypes.ULONG(0)
        else:
            self._timeout = int(seconds * 1000)
            is_async = ctypes.wintypes.ULONG(1)
        ioctl(self._sock_fd, FIONBIO, ctypes.byref(is_async))

    def setblocking(self, flag):
        if flag:
            self.settimeout(None)
        else:
            self.settimeout(0)

    def bind(self, path):
        """
        Bind to a path.
        """
        path = bytes(path)
        nbytes = len(path) + 1
        if nbytes > MAX_PATH_LENGTH:
            raise socket.error(ERROR_BAD_PATHNAME,
                    "Socket path name too long ({} bytes, max {})".format(nbytes, MAX_PATH_LENGTH)
            )
        addr = sockaddr_un()
        addr.sun_family = AF_UNIX
        ctypes.memmove(addr.sun_path, path, nbytes - 1)
        addr.sun_path[nbytes - 1] = 0
        if bind(self._sock, ctypes.byref(addr), ctypes.sizeof(addr)) != 0:
            raise socket.error(errno_fn(), "Windows error {}".format(errno_fn()))

    def listen(self, n):
        """
        Start to listen on the named pipe.
        """
        if listen(self._sock_fd, n) != 0:
            raise socket.error(errno_fn(), "Windows error {}".format(errno_fn()))

    def accept(self):
        """
        Block until an incoming connection arrives, or until the timeout elapses.
        """
        addr = sockaddr_un()
        n = ctypes.c_int()
        nonlocal_fd = [None]
        def accept_and_return_zero():
            """
            Do the accept, return 0 and write to the_fd[0] on success.

            call_socket_fn will handle interrupts, timeouts, error handling.
            """
            s = accept(self._sock_fd, ctypes.byref(addr), ctypes.byref(n))
            if int(s) >= 0:
                nonlocal_fd[0] = s
                return 0
            return -1
        call_socket_fn(self, 0, accept_and_return_zero)
        return (WindowsUnixSocket(fd = nonlocal_fd[0]), str(addr.sun_family))

    def shutdown(self, how):
        """
        Send any data that still needs to be sent.

        This is blocking no matter what, no timeout.
        """
        shutdown(self._sock_fd, how)

    def close(self):
        """
        Close the socket.
        """
        close(self._sock_fd)
        self._sock_fd = -1

    def connect(self, path):
        """
        Connect to a server whose listener pipe is the given path.

        Returns None. After this call, this socket will be connected to the server
        unless an exception was raised.
        """
        path = bytes(path)
        nbytes = len(path) + 1
        if nbytes > MAX_PATH_LENGTH:
            raise socket.error(ERROR_BAD_PATHNAME,
                    "Socket path name too long ({} bytes, max {})".format(nbytes, MAX_PATH_LENGTH)
            )
        addr = sockaddr_un()
        addr.sun_family = AF_UNIX
        ctypes.memmove(addr.sun_path, path, nbytes - 1)
        addr.sun_path[nbytes - 1] = 0

        call_socket_fn(self, 0, lambda: connect(self._sock_fd, ctypes.byref(addr), ctypes.sizeof(addr)))

    def fileno(self):
        if int(self._sock_fd) < 0:
            raise EOFError()
        else:
            return self._sock_fd

    def getpeername(self):
        addr = sockaddr_un()
        n = ctypes.c_int()
        if getpeername(self._sock_fd, ctypes.byref(addr), ctypes.byref(n)) != 0:
            raise socket.error(errno_fn(), "Windows error {}".format(errno_fn()))
        return str(addr.sun_family)

    def getsockname(self):
        addr = sockaddr_un()
        n = ctypes.c_int()
        if getsockname(self._sock_fd, ctypes.byref(addr), ctypes.byref(n)) != 0:
            raise socket.error(errno_fn(), "Windows error {}".format(errno_fn()))
        return str(addr.sun_family)

    def recv(self, n):
        buffer = ctypes.create_string_buffer(n)
        call_socket_fn(self, 0, lambda: recv(self._sock_fd, buffer, n, 0))
        return buffer.value

    def send(self, msg):
        buffer = bytes(msg)
        nonlocal_n = [None]
        def send_and_ret0():
            n = send(self._sock_fd, buffer, len(buffer), 0)
            if n < 0:
                return -1
            else:
                nonlocal_n[0] = n
        call_socket_fn(self, 1, send_and_ret0)
        return nonlocal_n[0]
