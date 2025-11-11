# security_c_examples

示例目录：演示一个简单的 C 程序 `safe_string.c`，重点展示安全字符串拷贝与敏感数据清零的技巧。

编译（Windows + MinGW 或 WSL / Linux）：

```
# 使用 MinGW 或 WSL 下的 gcc
gcc -o safe_string safe_string.c
./safe_string
```

说明要点：
- 使用固定长度目标缓冲区并将其大小传入拷贝函数，避免缓冲区溢出
- 对可能的截断行为进行检测和处理
- 在处理完敏感数据后使用显式清零（volatile 写法）以防止编译器优化掉清零操作

注意：示例代码用于教学，生产环境中可采用更完善的库函数与平台特定 API（例如 `SecureZeroMemory`、`explicit_bzero`、`memset_s` 等）。

## Windows 终端中文乱码及解决方法

如果你在 Windows 的 `cmd.exe` 或 `PowerShell` 中看到类似 `\u748b\u75af\u7f16...`（如："璇疯緭..."）的奇怪字符，这是终端编码与程序输出编码不匹配导致的显示问题（常见为 UTF-8 字节被按本地 ANSI/GBK 解码，或反之）。下面汇总了常用的排查与修复方法：

### 原因简述
- 源文件通常以 UTF-8 保存，字符串字面量为 UTF-8 字节流；Windows 控制台默认代码页可能为 CP936（GBK）或 OEM 编码，直接按不同编码显示会产生乱码。
- PowerShell、cmd、Windows Terminal、以及不同的字体/终端设置会影响最终显示。

### 临时快速修复（命令行）
在 `cmd.exe` 中临时切换到 UTF-8 代码页，然后运行程序：
```cmd
chcp 65001
cd /d d:\Defense\PyHack-Lab\security_c_examples
safe_string.exe
```
在 PowerShell（当前会话）中还需设置输出编码：
```powershell
chcp 65001
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
.\safe_string.exe
```
注意：`chcp 65001` 在某些旧终端或旧 Windows 版本上可能仍有兼容性问题，但在较新的 Windows 10/11 终端通常可用。

### 在程序中设置（更可靠）
可以在程序启动时通过 Windows API 将控制台输出代码页设为 UTF-8：

```c
#ifdef _WIN32
#include <windows.h>
#endif
#include <locale.h>

int main(void) {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8); // 将控制台输出改为 UTF-8
#endif
	setlocale(LC_ALL, "");
	...
}
```

这种做法在多数现代 Windows 环境中能有效显示 UTF-8 字符（前提是源文件以 UTF-8 保存）。如果你希望我把 `safe_string.c` 中添加这段条件编译的初始化，我可以替你修改并重新编译验证。

### 编译时使用本地编码（另一种选择）
如果你更希望字面量直接匹配当前控制台的 ANSI 编码（例如 GBK），可以在编译时指定执行时字面量的编码：
```cmd
gcc -fexec-charset=GBK -o safe_string safe_string.c
```
这会将字面量以 GBK 存入可执行文件，从而在默认 CP936 控制台中直接显示正确中文。但它会降低程序的可移植性（不同机器、不同本地编码会有不同行为）。

### 推荐实践
- 开发与演示阶段：把源文件保存为 UTF-8（无 BOM），在终端使用 `chcp 65001` 或在程序内 `SetConsoleOutputCP(CP_UTF8)`。
- 面向多机器部署：考虑在启动时检测控制台代码页并在必要时进行编码转换，或使用宽字符 API（`wprintf`）并设置合适的 `locale`。
- 生产环境更稳妥的方法：使用平台提供的 API 做转换（Windows 上的 `WideCharToMultiByte` / `MultiByteToWideChar`）并记录/测试不同环境下的表现。

### 快速示例：在 `safe_string.c` 中启用 UTF-8 控制台输出
你可以在源码中加入如下代码（仅在 Windows 下启用）：

```c
#ifdef _WIN32
#include <windows.h>
#endif
#include <locale.h>

int main(void) {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif
	setlocale(LC_ALL, "");
	/* 其余程序逻辑 */
}
```

### 小结
终端乱码通常不是程序逻辑错误，而是编码/解码层面的不匹配。常用修复：在终端设置为 UTF-8（`chcp 65001`）、或在程序中设置控制台编码、或在编译时采用与目标终端一致的执行时字面量编码。根据你的部署/使用场景选择合适方案即可。

----
（如果你愿意，我现在可以：1）修改 `safe_string.c` 在 Windows 下启用 `SetConsoleOutputCP(CP_UTF8)` 并重新编译验证；或 2）把 README 中这节内容再翻译成英文并添加示例截图。请告诉我你想要哪个。）