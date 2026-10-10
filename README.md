# HomeStream

A very small, self-hosted media streamer for your home network.

Point it at a folder of videos and music, log in with a password from any
browser on your LAN, and play. It is one small program with no dependencies,
no database and no transcoding.

## Features

- Plays video (mp4, m4v, webm) and audio (mp3, m4a, flac, ogg, opus, wav)
  straight from a folder.
- Browse folders or search the whole library.
- Seeking works, because files are sent with HTTP Range support.
- One password, encrypted with HTTPS, reachable from the local network only.
- A single 5 MB binary built with the Go standard library.

## How it works

HomeStream sends the files to the browser exactly as they are, and the browser
or phone decodes them. So the files must be in a format your device can play.
H.264 video with AAC audio (the usual mp4) plays almost everywhere.

The server lists the library as one JSON file, and the web page builds the
folders and the search from that list. Playing a file points a standard
`<video>` or `<audio>` element at the server.

## Requirements

- A Linux machine that stays on while you stream.
- Go 1.22 or newer, to build it.
- [mkcert](https://github.com/FiloSottile/mkcert), to create the HTTPS
  certificate. Any other TLS certificate and key also work.

## Setup

1. Build:

   ```
   go build -trimpath -ldflags="-s -w" -o homestream
   ```

2. Create the certificate. `mkcert -install` is needed once per machine and
   creates a small private certificate authority. Replace `192.168.1.10` with
   the LAN address of this machine:

   ```
   mkcert -install
   mkdir -p ~/.config/homestream
   mkcert -cert-file ~/.config/homestream/cert.pem \
          -key-file ~/.config/homestream/key.pem \
          192.168.1.10 $(hostname).local localhost
   ```

3. Store the password. It is typed hidden and saved in a file only you can
   read. Avoid the characters `"` and `\` in it.

   ```
   read -rsp 'Password: ' p; echo
   (umask 077; echo "HS_PASSWORD=$p" > ~/.config/homestream/env); unset p
   ```

4. Start it as a service that runs at boot. The service file expects the
   binary at `~/Projects/HomeStream/homestream`; edit `homestream.service` if
   you keep it somewhere else.

   ```
   mkdir -p ~/.config/systemd/user
   cp homestream.service ~/.config/systemd/user/
   systemctl --user daemon-reload
   systemctl --user enable --now homestream
   loginctl enable-linger $USER
   ```

5. Allow only your home network through the firewall (adjust the network):

   ```
   sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp
   ```

   Do not forward port 8443 on your router.

6. Open `https://<hostname>.local:8443` or `https://192.168.1.10:8443`.

To try it in a terminal first: `HS_PASSWORD=test ./homestream`.

## Trust the certificate on your devices

Browsers show a warning until the device trusts your mkcert authority. Copy
`rootCA.pem` from the folder printed by `mkcert -CAROOT` to each device. Never
copy `rootCA-key.pem`.

- iPhone and iPad: open the file and install the profile, then go to
  Settings > General > About > Certificate Trust Settings and switch it on.
  If iOS will not open a `.pem` file, rename it to `rootCA.crt`.
- Other computers: import it into the system certificate store. Firefox has
  its own: Settings > Privacy & Security > Certificates > View Certificates >
  Authorities > Import.

## Configuration

Set these as environment variables. With the service, put them in
`~/.config/homestream/env`, one `NAME=value` per line.

| Variable      | Meaning                  | Default                          |
|---------------|--------------------------|----------------------------------|
| `HS_PASSWORD` | Login password           | required                         |
| `HS_ROOT`     | Media folder             | `~/Media`                        |
| `HS_ADDR`     | Listen address and port  | `:8443`                          |
| `HS_CERT`     | TLS certificate          | `~/.config/homestream/cert.pem`  |
| `HS_KEY`      | TLS private key          | `~/.config/homestream/key.pem`   |

To change the password, edit the env file and run
`systemctl --user restart homestream`. After rebuilding the binary, restart the
service the same way.

## Security

- LAN only, in three layers: the firewall rule, a check in the server that
  refuses any client address that is not private or loopback, and no port
  forwarding on the router.
- Everything is encrypted with TLS (HTTPS).
- One shared password, no user accounts. A wrong password is delayed by one
  second and attempts are handled one at a time, so guessing is slow.
- A login lasts 30 days and is kept in a signed cookie. Restarting the server
  logs everyone out.
- Only the file types listed above are served. Hidden files and folders
  (names starting with a dot) and `lost+found` are never listed or served, and
  paths cannot climb out of the media folder.
- The password sits in plain text in the env file, which is readable only by
  you. This is meant for a trusted home network, not for the internet.

## Limits

- No transcoding. Files in formats your device cannot decode (for example AV1
  or 10-bit H.264 on older devices) will not play.
- No posters, descriptions, subtitles or "resume where I stopped".
- Symbolic links inside the media folder are not listed.

## Development

```
go vet ./...
go test ./...
```

| File                  | Purpose                                              |
|-----------------------|------------------------------------------------------|
| `main.go`             | The whole server                                     |
| `index.html`          | The web page, built into the binary                  |
| `main_test.go`        | Tests for login, hidden files, Range and LAN check   |
| `homestream.service`  | systemd user service                                 |
