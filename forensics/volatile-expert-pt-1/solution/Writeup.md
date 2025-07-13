# Volatile Expert

## Part 1

Either:

- Contruct symbols for the provided snapshot, [blog reference](https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility)
- Or use [this script](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/symbols_finders/ubuntu_symbols_finder.py) that automatically downloads the correct symbols
- Or use the ready made [symbols](https://github.com/Abyss-W4tcher/volatility3-symbols/tree/master/Ubuntu/amd64/5.15.0/139/generic) **Note the Version of the symbols!!**

In the first case you will have the actual debug `vmlinux` that you can hash, however the `sha256` exists in the resuling symbol file itself:

```json
{
  "metadata": {
    "linux": {
      "symbols": [
        {
          "kind": "dwarf",
          "name": "vmlinux-5.15.0-139-generic",
          "hash_type": "sha256",
          "hash_value": "46e56757f5aa58b6f3bbb810cf8d7aa01bebcca6cd61cc4b8f5baf7ed24602f0"
        },
```

### Part 2

The virtual offset can be found using the `pslist` plugin:

```bash
$> vol -f mem.elf -s setup linux.pslist --pid 1576
Volatility 3 Framework 2.26.2
Progress:  100.00		Stacking attempts finished
OFFSET (V)	PID	TID	PPID	COMM	UID	GID	EUID	EGID	CREATION TIME	File output

0x99495097cc80	1576	1576	1184	gsd-wwan	1000	1000	1000	1000	2025-06-04 23:33:26.696763 UTC	Disabled
```

And the physical with the `psscan`:

```bash
$> vol -f mem.elf -s setup --filter "PID,1576" linux.psscan
Volatility 3 Framework 2.26.2
Progress:  100.00		Stacking attempts finished
OFFSET (P)	PID	TID	PPID	COMM	EXIT_STATE

0x1097cc80	1576	1576	1184	gsd-wwan	TASK_RUNNING
0x109e9980	1576	1600	1184	gdbus	TASK_RUNNING
0x18a94c80	1576	1588	1184	gmain	TASK_RUNNING
0x20181980	1576	1639	1184	pool-gsd-wwan	EXIT_DEAD
0x20186600	1576	1644	1184	dconf worker	TASK_RUNNING
```

### Part 3

The `__x64_sys_execve` can be found using:

```bash
$> vol -f mem.elf -s setup --filter "SymbolName,__x64_sys_execve" linux.kallsyms --core
Volatility 3 Framework 2.26.2
Progress:  100.00		Stacking attempts finished
Addr	Type	Size	Exported	SubSystem	ModuleName	SymbolName	Description

0xffffb159c360	T	96	True	core	kernel	__x64_sys_execveat	Symbol is in the text (code) section
0xffffb159c3c0	T	80	True	core	kernel	__x64_sys_execve	Symbol is in the text (code) section
0xffffb370ca40	t	16	False	core	kernel	_eil_addr___x64_sys_execveat	Symbol is in the text (code) section
0xffffb370ca60	t	16	False	core	kernel	_eil_addr___x64_sys_execve	Symbol is in the text (code) section
```

### Part 4

The physical address can be found using Volshell by translating the virtual address found above:

```python
[layer_name]> kernel_layer = self.context.layers['layer_name']
[layer_name]> hex(kernel_layer.translate(0xffffb159c3c0)[0])
Out[5]: '0x64d9c3c0'
```

### Part 5

The stack canary in (kernel space) of a process can be found in the `task_struct.stack_canary` field:

```python
[layer_name]> proc = gp(pid=1554)

[layer_name]> hex(proc.stack_canary)
Out[8]: '0xaf1673f117bf4600'
```

But since the flag is in Big Endianness we can either reverse the byte order or:

```python
[layer_name]> dq(proc.stack_canary.vol.offset, 8, byteorder=">")
0x9949509609c8    0046bf17f17316af                     .F...s..
```

### Part 6

Similarly, we can read all the data of the `task_struct` and get the `sha1` hash of it:

```python
[layer_name]> proc = gp(pid=972)

[layer_name]> data = kernel_layer.read(proc.vol.offset, proc.vol.size)

[layer_name]> import hashlib

[layer_name]> h = hashlib.sha1(data).hexdigest()

[layer_name]> h
Out[16]: '4ba1e2c98c299bd46567653eed574a1cf69409dc'
```
