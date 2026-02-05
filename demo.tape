# VHS Demo for S3 TUI
Output demo.gif

Set FontSize 13
Set Width 800
Set Height 500
Set Theme "Catppuccin Mocha"
Set Framerate 12
Set LoopOffset 0%

Type "./s3tui --demo"
Enter
Sleep 1s

# Navigate buckets
Down
Sleep 200ms
Down
Sleep 200ms
Down
Sleep 300ms

# Select a bucket
Enter
Sleep 800ms

# Enter a folder
Down
Sleep 200ms
Enter
Sleep 800ms

# Multi-select some files
Down
Sleep 150ms
Type " "
Sleep 200ms
Down
Sleep 150ms
Type " "
Sleep 200ms
Down
Sleep 150ms
Type " "
Sleep 400ms

# Switch tabs
Tab
Sleep 400ms
Tab
Sleep 600ms

# Show help
Type "?"
Sleep 1.5s

# Close and quit
Escape
Sleep 300ms
Type "q"
Sleep 300ms
