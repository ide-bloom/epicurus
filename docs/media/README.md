# Demo media

`demo.gif` is currently a **placeholder** (a static banner). Replace it with a real recording before the first release announcement.

## Recording the demo

The demo shows the built-in harmless simulation end to end. It never involves real malware or real credentials.

1. Use a clean Windows 11 VM (24H2 or later) with a 1280×720 desktop, dark terminal theme, and font size 16 or larger.
2. In Windows Terminal (not elevated):

   ```powershell
   .\epicurus.exe install          # accept the UAC prompt
   epicurus status
   epicurus simulate --keep
   ```

3. When the toast appears, keep it on screen for about two seconds, then click **Open** to show the incident in the dashboard: score explanation, process tree, decoys touched, timeline.
4. Click **Kill tree** in the dashboard.
5. Finish with `epicurus status`.

Record with [ScreenToGif](https://www.screentogif.com/) (or OBS plus `ffmpeg`), 12–15 fps, keeping the GIF under about 8 MB:

```powershell
ffmpeg -i demo.mp4 -vf "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer" -loop 0 demo.gif
```

Save it as `docs/media/demo.gif` and remove the placeholder note from the README.
