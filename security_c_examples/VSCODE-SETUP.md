# VS Code 使用说明（针对 security_c_examples 子项目）

本文件说明如何使用本目录下的 VS Code 本地配置（`.vscode/tasks.json` 与 `.vscode/launch.json`），以便在不影响工作区其他文件夹的情况下，方便地对任意 C 文件进行 构建 / 运行 / 调试。

> 位置：`d:\Defense\PyHack-Lab\security_c_examples\.vscode`（仅对该子文件夹生效）。

## 概要
- 新增的任务（tasks）支持：
  - `Build active C file (gcc)` — 编译当前活动的 C 文件（默认构建任务）。
  - `Run active C file` — 先编译当前活动文件，再运行生成的可执行文件。
  - `Clean active C executable` — 删除当前活动文件对应的可执行文件。
  - `Build safe_string (gcc)` — 保留的示例构建任务（向后兼容之前的示例）。
- 新增的启动配置（launch）支持：
  - `Debug current C file` — 使用 gdb（cppdbg）调试当前打开的 C 文件（会先运行 `Build active C file (gcc)`）。
  - `Run safe_string (integrated console)` — 保留的示例调试配置（调试 `safe_string.exe`）。

## 使用前提
- 已安装 GCC / MinGW，并且 `gcc` / `gdb` 可在 PATH 中被调用（系统示例中使用 MinGW64）。
- 推荐将源文件保存为 UTF-8（无 BOM）。如果遇到中文乱码问题，请参考项目根目录下 `README.md` 中的“Windows 终端中文乱码及解决方法”。

## 快速使用指南（在 VS Code 中）
1. 在 VS Code 中打开 `d:\Defense\PyHack-Lab\security_c_examples` 文件夹（或在工作区中打开该文件）。
2. 打开你要运行/调试的 C 文件（例如 `1.c`、`safe_string.c`）。
3. 构建当前文件：按 Ctrl+Shift+B（会运行 `Build active C file (gcc)`）。
4. 运行当前文件：按 Ctrl+Shift+P -> 输入 `Tasks: Run Task` -> 选择 `Run active C file`。该任务会先构建再运行。
5. 调试当前文件：打开欲调试的 C 文件，设置断点，按 F5 或在 Run 面板选择 `Debug current C file`。调试会在集成终端中启动（`externalConsole:false`），并在构建完成后启动 gdb 会话。
6. 清理生成文件：Tasks -> Run Task -> 选择 `Clean active C executable`。

## 在命令行中运行（等效）
如果你喜欢在命令行中直接操作（cmd / PowerShell）：

构建当前文件（示例：在文件所在目录）：
```cmd
gcc -g -O0 -o 1.exe 1.c
```
运行：
```cmd
1.exe
```

## 常见问题与排查
- 如果调试时看到 “Unable to perform this action because the process is running.”：
  - 确认调试器已处于暂停状态（断点命中时 VS Code 应显示黄色箭头）。如果未暂停，点击调试工具栏的 Pause（暂停）按钮。
  - 将 launch 配置改为使用集成终端（本项目默认已设置为 `externalConsole:false`）；某些组合（gdb + 外部控制台）在 Windows 上会导致交互不同步。
  - 如果仍有问题，请将 Debug Console 的日志贴给我（本目录的 launch.json 已启用 adapter 日志）。
- 如果中文提示/注释显示为乱码：
  - 在 `cmd` 中运行前执行 `chcp 65001`，或在 PowerShell 中设置 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`。另可在 `safe_string.c` 中添加 `SetConsoleOutputCP(CP_UTF8)`（仅 Windows）来强制输出为 UTF-8（示例见 README）。
- 若 `gdb` 无法正常工作或找不到 `miDebuggerPath`：
  - 将 `miDebuggerPath` 修改为你系统上 gdb 的绝对路径，例如 `C:\mingw64\bin\gdb.exe`，以提高稳定性。

## 如何自定义
- 改变编译选项：编辑 `.vscode/tasks.json` 中 `Build active C file (gcc)` 的 `args`（例如加入 `-std=c11`、`-Wall`、或 `-O2`）。
- 向运行/调试配置传递参数：编辑 `.vscode/launch.json` 的配置，将命令行参数写入 `args` 数组。
- 切换为 MSVC 调试器：如果你使用 MSVC/Visual Studio 的调试器，请告诉我我会添加 `cppvsdbg` 的模板配置并移除 gdb 特有设置。

## 备注
- 配置只放在本子文件夹的 `.vscode` 中，因此不会影响其他子项目或全局设置。若你把整个工作区（workspace）打开，这些设置仍然作为该文件夹的本地配置被 VS Code 使用。
- 若你希望我把这些说明合并到项目的主 `README.md` 中，我也可以替你追加一节。

----
如果需要，我可以：
- (A) 把 `miDebuggerPath` 改为你的 MinGW gdb 的绝对路径并重新验证；
- (B) 增加一个任务选项来提示构建类型（Debug/Release）；
- (C) 把这份说明合并进 `README.md`。


