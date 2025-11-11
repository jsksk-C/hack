"""
Simple Tkinter GUI front-end for netcat_py

Usage:
  python gui.py

This GUI launches the existing `netcat.py` script as a subprocess and
shows stdout/stderr in a text box. You can send text input to the process
using the input field. The GUI supports starting/stopping the process and
selecting files for send/receive options.

Notes:
- This is a minimal helper for convenience and testing on Windows 11.
- The GUI runs the same Python interpreter that launched it (sys.executable).
"""

import sys
import threading
import subprocess
import shlex
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

HERE = os.path.dirname(__file__)
NETCAT_PY = os.path.join(HERE, 'netcat.py')


class NetcatGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('netcat_py - GUI')
        self.geometry('800x520')

        self.proc = None
        self.reader_thread = None
        self.stop_event = threading.Event()

        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self)
        frm.pack(fill='x', padx=8, pady=6)

        ttk.Label(frm, text='Mode:').grid(row=0, column=0, sticky='w')
        self.mode_var = tk.StringVar(value='client')
        ttk.Radiobutton(frm, text='Client', variable=self.mode_var, value='client').grid(row=0, column=1)
        ttk.Radiobutton(frm, text='Listen', variable=self.mode_var, value='listen').grid(row=0, column=2)

        ttk.Label(frm, text='Host:').grid(row=1, column=0, sticky='w')
        self.host_entry = ttk.Entry(frm)
        self.host_entry.grid(row=1, column=1, columnspan=2, sticky='we')
        self.host_entry.insert(0, '127.0.0.1')

        ttk.Label(frm, text='Port:').grid(row=2, column=0, sticky='w')
        self.port_entry = ttk.Entry(frm, width=8)
        self.port_entry.grid(row=2, column=1, sticky='w')
        self.port_entry.insert(0, '4444')

        ttk.Label(frm, text='Input file:').grid(row=3, column=0, sticky='w')
        self.input_entry = ttk.Entry(frm)
        self.input_entry.grid(row=3, column=1, sticky='we')
        ttk.Button(frm, text='Browse', command=self._browse_input).grid(row=3, column=2)

        ttk.Label(frm, text='Output file (listen -o):').grid(row=4, column=0, sticky='w')
        self.output_entry = ttk.Entry(frm)
        self.output_entry.grid(row=4, column=1, sticky='we')
        ttk.Button(frm, text='Browse', command=self._browse_output).grid(row=4, column=2)

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=6)
        self.start_btn = ttk.Button(btn_frame, text='Start', command=self.start)
        self.start_btn.pack(side='left', padx=4)
        self.stop_btn = ttk.Button(btn_frame, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.pack(side='left', padx=4)
        self.clear_btn = ttk.Button(btn_frame, text='Clear', command=self._clear_output)
        self.clear_btn.pack(side='left', padx=4)

        # Output text box
        self.text = tk.Text(self, wrap='none')
        self.text.pack(fill='both', expand=True, padx=8, pady=6)

        # Input entry
        bottom = ttk.Frame(self)
        bottom.pack(fill='x', padx=8, pady=6)
        self.input_send = ttk.Entry(bottom)
        self.input_send.pack(side='left', fill='x', expand=True)
        self.send_btn = ttk.Button(bottom, text='Send', command=self._send_input)
        self.send_btn.pack(side='left', padx=4)

    def _browse_input(self):
        path = filedialog.askopenfilename(title='Select input file')
        if path:
            self.input_entry.delete(0, 'end')
            self.input_entry.insert(0, path)

    def _browse_output(self):
        path = filedialog.asksaveasfilename(title='Select output file')
        if path:
            self.output_entry.delete(0, 'end')
            self.output_entry.insert(0, path)

    def _append(self, data: bytes):
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = str(data)
        def write():
            self.text.insert('end', text)
            self.text.see('end')
        self.after(0, write)

    def _reader(self, stream):
        try:
            while not self.stop_event.is_set():
                chunk = stream.read(4096)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode()
                self._append(chunk)
        except Exception as e:
            self._append(f"[!] Reader error: {e}\n".encode())

    def start(self):
        if self.proc is not None:
            messagebox.showinfo('Info', 'Process already running')
            return

        mode = self.mode_var.get()
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        args = [sys.executable, NETCAT_PY]
        if mode == 'listen':
            args.append('-l')
            if port:
                args += ['-p', port]
            out = self.output_entry.get().strip()
            if out:
                args += ['-o', out]
        else:
            # client
            if not host or not port:
                messagebox.showwarning('Warning', 'Client mode requires host and port')
                return
            args += [host, port]
            inf = self.input_entry.get().strip()
            if inf:
                args += ['-i', inf]

        # start subprocess
        try:
            # On Windows, creationflags could be used; keep simple and portable
            self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to start process: {e}')
            self.proc = None
            return

        self.stop_event.clear()
        self.reader_thread = threading.Thread(target=self._reader, args=(self.proc.stdout,), daemon=True)
        self.reader_thread.start()

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self._append(b"[+] Started process\n")

        # monitor thread to detect process exit
        threading.Thread(target=self._monitor_proc, daemon=True).start()

    def _monitor_proc(self):
        if not self.proc:
            return
        self.proc.wait()
        self.stop_event.set()
        self.after(0, lambda: self._append(b"[+] Process exited\n"))
        self.after(0, lambda: self.start_btn.config(state='normal'))
        self.after(0, lambda: self.stop_btn.config(state='disabled'))
        self.proc = None

    def stop(self):
        if not self.proc:
            return
        try:
            self.proc.kill()
        except Exception:
            pass
        self.stop_event.set()
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    def _send_input(self):
        if not self.proc or not self.proc.stdin:
            messagebox.showwarning('Warning', 'No process to send to')
            return
        data = self.input_send.get()
        try:
            # append newline if not present
            if not data.endswith('\n'):
                data = data + '\n'
            self.proc.stdin.write(data.encode())
            self.proc.stdin.flush()
            self.input_send.delete(0, 'end')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to send input: {e}')

    def _clear_output(self):
        self.text.delete('1.0', 'end')


def main():
    app = NetcatGUI()
    app.mainloop()


if __name__ == '__main__':
    main()
