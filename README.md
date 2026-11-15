# Linux Monitor (Windows)

## Install
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

## Run
    python gui_app.py          (GUI; use pythonw to hide console)
    python main.py -c config.json   (console mode; copy config.example.json to config.json first)

## Password
Config stores only the env var NAME. Set value:
    setx DB01_SSH_PASSWORD "YOUR_PASSWORD"
(or enter it in the GUI field). Key auth is preferred.

## known_hosts
Host key checking is enforced (RejectPolicy). In the GUI select a server and click
"اعتماد به host key", compare the fingerprint with the server's
(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), then confirm.
Or: ssh monitor@HOST  once, and answer yes.

All values in config.example.json are samples: replace them.
This code has not been tested; try on a test server first.
