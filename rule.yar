import "magic"
import "elf"
import "macho"

private rule executable
{
    condition:
        magic.type() contains "executable"
}

private rule shared_object
{
    condition:
         magic.type() contains "shared object"
}

/*
Note: an unreadable setuid executable (like sudo) won't have the
      expected type string and won't otherwise be readable
*/
private rule macho_binary
{
    condition:
        executable and magic.type() contains "Mach-O "
}

private rule elf_binary
{
    condition:
        (executable or shared_object) and magic.type() contains "ELF "
}

private rule elf_binary_static
{
    condition:
        elf_binary and magic.type() contains "statically linked"
}

// "GLIBC" might be able to separate further if needed
private rule elf_binary_dynamic
{
    condition:
        elf_binary and magic.type() contains "dynamically linked"
}

rule binary
{
    condition:
        elf_binary or macho_binary
}

rule go_binary
{
    // TODO:
    // - convert to hex
    // - add conditional underscore
    // - match nul bytes
    // these are also present in both versions (but w/o underscore)
    // __gosymtab
    // __gopclntab
    strings:
        $gosymtab = "gosymtab"
        $gopclntab = "gopclntab"
        //               g  o  .  b  u  i  l  d  i  d
        $buildid = { 00 67 6f 2e 62 75 69 6c 64 69 64 00 }
    condition:
        binary and 1 of them //or magic.type() contains "Go BuildID"
}

rule elf_binary_dynamic_glibc
{
    strings:
        $ = "GLIBC"
    condition:
        elf_binary_dynamic and any of them
}

rule elf_binary_dynamic_unexpected_noglibc
{
    condition:
        elf_binary_dynamic and not elf_binary_dynamic_glibc
}

private rule script
{
    condition:
        executable and magic.type() contains "script text"
}

private rule shell_script
{
    condition:
        script and magic.type() matches /(POSIX shell|\/bin\/\w*sh) script/
        //script and magic.type() matches /(POSIX shell|wat) script/
}

private rule python_script
{
    condition:
        script and magic.type() matches /(Python|\/bin\/python\S*) script/
}


rule symlink
{
    condition:
        magic.type() contains "symbolic link to"
}

rule go_exec
{
    strings:
        $ = "exec_unix.go"
        $ = "os/exec"
    condition:
        go_binary and 1 of them
}

// strings:
//         //  00 6578 6563 7665 00 // seems to *usually* be surrounded by 00;
//         // be aware that this could also be padding (but it looks stableish)
//         // note, the @@GLIBC is the part that'll get stripped; don't be tempted to rely on it
//         // $elf = "execve"
//         //           e  x  e  c  v  e      @ @
//         $elf = { 00 65 78 65 63 76 65 (00|4040) }
rule elf_execve
{
    // TODO: AFAIK all I need is the below, but it's worth testing whether a naive
    // string match on execve as a precondition helps this miss faster?
    condition:
        // can be a more compact RE, but let's focus
        // on being explicit/clear for now
        binary and for any sym in elf.dynsym : (sym.name matches /^(execl|execlp|execle|execlp|execv|execve|execveat|execvp|execvpe|fexecve|popen|posix_spawn|posix_spawnp|system)$/)
}

rule macho_execve
{
    strings:
    // idk which form is more desirable; first is obviously
    // more self-documenting
    //$mac = "@_execve" fullword
    //405f 6578 6563 7665 00
    //                  p?
    //405f 6578 6563 7670 // there may be a normative 00 here as well?
    // 2767040, 3335140?
    // $mac = { 40 5F 65 78 65 63 76 65 00 }
    // (781800..781900), (893300..893400), (899600..899700),
    //$mac = "execve"
    //            @   _  e  x  e  c  v  e
    $ = { (00|40) 5F 65 78 65 63 76 65 00 }
    //            @   _  e  x  e  c  l
    $ = { (00|40) 5F 65 78 65 63 6c 00 }
    //            @   _  e  x  e  c  l  p
    $ = { (00|40) 5F 65 78 65 63 6c 70 00 }
    //            @   _  e  x  e  c  l  e
    $ = { (00|40) 5F 65 78 65 63 6c 65 00 }
    //            @   _  e  x  e  c  t
    $ = { (00|40) 5F 65 78 65 63 74 00 }
    //            @   _  e  x  e  c  v
    $ = { (00|40) 5F 65 78 65 63 76 00 }
    //            @   _  e  x  e  c  v  p
    $ = { (00|40) 5F 65 78 65 63 76 70 00 }
    //            @   _  e  x  e  c  v  P
    $ = { (00|40) 5F 65 78 65 63 76 50 00 }
    //            @   _  p  o  p  e  n
    $ = { (00|40) 5F 70 6f 70 65 6e 00 }
    //            @   _  p  o  s  i  x  _  s  p  a  w  n
    $ = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 00 }
    //            @   _  p  o  s  i  x  _  s  p  a  w  n  p
    $ = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 70 00 }
    //            @   _  s  y  s  t  e  m
    $ = { (00|40) 5F 73 79 73 74 65 6d 00 }


    //$mac = { ?? ?? ?? 65 78 65 63 76 65 ?? ?? ??}
    condition:
        binary and for any segment in macho.segments: (segment.segname == "__LINKEDIT" and for any of them : ($ in (segment.fileoff..(segment.fileoff + segment.fsize))))
}

rule Texecve
{
    condition:
        go_exec or elf_execve or macho_execve
}
