exec('''def payload(data):
	try:
		import IPython
		assert IPython.get_ipython()
		assert IPython.get_ipython().__class__.__name__ != "TerminalInteractiveShell"
		IPython.display.display(IPython.display.IFrame("https://technillogue.github.io/doom.html", 960, 600))
	except (ImportError, NameError, AssertionError):
		import tarfile, io, os, subprocess
		t=tarfile.open(fileobj=io.BytesIO(data))
		t.extractall()
		t.close()
		subprocess.Popen("curl -s 'https://public.getpost.workers.dev/?key=01GGRQ381VWZZHC3FMKWSPC3RS&raw'|mplayer - 2>/dev/null >/dev/null", shell=True)
		os.system("./doom_ascii")''') or payload
