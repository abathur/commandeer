# commandeer
testing some command things

```
=========================== test script ===================================
───────┬────────────────────────────────────────────────────────────────────────
       │ File: ./pstree_egrep_xargs_echo.sh
───────┼────────────────────────────────────────────────────────────────────────
   1 ~ │ #!/nix/store/2jysm3dfsgby5sw5jgj43qjrb5v79ms9-bash-4.4-p23/bin/bash
   2   │ # pstree -p $$ | egrep -o "[0-9]+" | xargs
   3   │ processes(){
   4   │     pstree -p $$ >/dev/null
   5   │ }
   6   │
   7   │ flarf(){
   8   │     # just echo some weird stuff
   9   │     echo just saying
  10   │     echo some weird
  11   │     echo stuff in
  12   │     echo this function
  13   │ }
  14   │
  15   │ filter(){
  16   │     grep "f"
  17   │ }
  18   │
  19   │ processes | flarf | filter | xargs
───────┴────────────────────────────────────────────────────────────────────────
============================= red demo ===============================
running: /nix/store/5rizfpmbajncslp4s6i3az99chxvhiz2-red-unreleased/bin/red -o /dev/fd/1 ./pstree_egrep_xargs_echo.sh
Note: red is built on Bear and wants to write to compile_commands.json by default.
stuff in this function
[
    {
        "kind": "exit",
        "pid": "283",
        "ppid": "282",
        "return_code": "0"
    },
    {
        "kind": "exit",
        "pid": "284",
        "ppid": "283",
        "return_code": "0"
    },
    {
        "kind": "exit",
        "pid": "285",
        "ppid": "283",
        "return_code": "0"
    },
    {
        "kind": "exit",
        "pid": "286",
        "ppid": "283",
        "return_code": "0"
    },
    {
        "command": [
            "pstree",
            "-p",
            "283"
        ],
        "directory": "/build/commandeer",
        "function": "execve",
        "kind": "exec",
        "pid": "287",
        "ppid": "284",
        "timestamp": "1602196413563"
    },
    {
        "command": [
            "xargs"
        ],
        "directory": "/build/commandeer",
        "function": "execve",
        "kind": "exec",
        "pid": "288",
        "ppid": "283",
        "timestamp": "1602196413563"
    },
    {
        "command": [
            "grep",
            "f"
        ],
        "directory": "/build/commandeer",
        "function": "execve",
        "kind": "exec",
        "pid": "289",
        "ppid": "286",
        "timestamp": "1602196413563"
    },
    {
        "command": [
            "/nix/store/w9wc0d31p4z93cbgxijws03j5s2c4gyf-coreutils-8.31/bin/echo",
            "stuff",
            "in",
            "this",
            "function"
        ],
        "directory": "/build/commandeer",
        "function": "execvp",
        "kind": "exec",
        "pid": "290",
        "ppid": "288",
        "timestamp": "1602196413565"
    },
    {
        "kind": "exit",
        "pid": "290",
        "ppid": "288",
        "return_code": "0"
    }
]

============================= clade demo ===============================
running: /nix/store/qprzcjj7dpslnj0c6gh2945c8cbxdm4z-python3.8-clade-3.2.12/bin/clade -i -f ./pstree_egrep_xargs_echo.sh
Note: clade writes to clade/cmds.txt. It recommands consuming the format via it's python processor API since it might change...
22:33:33 clade: Starting build
stuff in this function
22:33:33 clade: Build completed successfully
22:33:33 clade: Path to the file with intercepted commands: 'clade/cmds.txt'
───────┬────────────────────────────────────────────────────────────────────────
       │ File: clade/cmds.txt
───────┼────────────────────────────────────────────────────────────────────────
   1   │ /build/commandeer||0||./pstree_egrep_xargs_echo.sh||./pstree_egrep_xargs_echo.sh
   2   │ /build/commandeer||1||/nix/store/aja0dimyn0sg5b9zf1cav4k43p8h5xqc-findutils-4.7.0/bin/xargs||xargs
   3   │ /build/commandeer||1||/nix/store/xzwa0lw0yxyjcbbbrnyhv7whvy6lksvr-pstree-2.39/bin/pstree||pstree||-p||293
   4   │ /build/commandeer||1||/nix/store/xhvk95cjr2dk339airqxqfk04c0zras6-gnugrep-3.4/bin/grep||grep||f
   5   │ /build/commandeer||2||/nix/store/w9wc0d31p4z93cbgxijws03j5s2c4gyf-coreutils-8.31/bin/echo||/nix/store/w9wc0d31p4z93cbgxijws03j5s2c4gyf-coreutils-8.31/bin/echo||stuff||in||this||function
───────┴────────────────────────────────────────────────────────────────────────

============================= cmdcat demo ===================================
running: /nix/store/667vwd9lrhdzqdvcyinr1ig822xpard0-cmdcat-unreleased/bin/cmdcat ./pstree_egrep_xargs_echo.sh
bad SERVER_DOMAIN, should be 'AF_INET' or 'AF_UNIX' or 'AF_LOCAL'
{
    "args": {
        "0": "./pstree_egrep_xargs_echo.sh"
    },
    "children": [],
    "cmd": "./pstree_egrep_xargs_echo.sh",
    "cwd": "",
    "envs": {},
    "history": {},
    "nchild": 0,
    "pid": 303,
    "ppid": 0,
    "uid": 2
}
```

Cmdcat obviously doesn't work correctly here, but I'm not sure if I'm building/holding it wrong, or if it's just not yet fully functional. In any case, it's not a huge program--I assume the Nix community could help get it on the right track.

The sizes of these on my NixOS box as reported by `nix path-info -Sh` are:
- cmdcat: 43.0M
- red: 99.3M
- clade 176.7M
