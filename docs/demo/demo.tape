Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 720
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

# Shadow `gisweep` with a deterministic player so the GIF is reproducible
# without contacting any real network. The Hide block keeps prompt setup
# off-camera.
Hide
Env PS1 "$ "
Type "export PS1='\$ '"
Enter
Type "alias gisweep='bash $PWD/demo_player.sh'"
Enter
Type "clear"
Enter
Show

Sleep 700ms
Type "gisweep arcgis http://localhost/arcgis/rest/ -o report.html"
Sleep 700ms
Enter
Sleep 6s
